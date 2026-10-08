//go:build linux

package executor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// This independent Nginx instance writes only its private fixture directory.
// It proves rendered TLS business traffic, not signed panel API installation.
// The coordinator makes the host root read-only and verifies all live services.
func TestLoadBalanceTLSBackendPrivateNginxQA(t *testing.T) {
	if os.Getenv("PANEL_LB_BACKEND_PRIVATE_NGINX_QA") != "1" {
		t.Skip("explicit isolated private Nginx coordinator required")
	}
	host, e := os.Hostname()
	if e != nil || os.Geteuid() != 0 || (host != "lima-panel-compat-ubuntu24" && host != "lima-panel-store-apps-debian13") {
		t.Fatal("unknown host or non-root private QA")
	}
	nginx := "/usr/sbin/nginx"
	if _, e := os.Stat(nginx); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"valid", "wrong-name", "expired", "unknown-ca", "old-TLS"} {
		t.Run(mode, func(t *testing.T) {
			stage, e := os.MkdirTemp(os.TempDir(), "lb-backend-private-nginx-")
			if e != nil {
				t.Fatal(e)
			} // Retained, never delete the proof directory.
			backendName := "backend.example.test"
			certificateName := backendName
			if mode == "wrong-name" {
				certificateName = "wrong.example.test"
			}
			certificate, ca := lbTLSCertificate(t, certificateName, mode == "expired")
			var countA, countB atomic.Int32
			handler := func(counter *atomic.Int32) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					counter.Add(1)
					if r.Host != backendName || r.TLS == nil || r.TLS.ServerName != backendName || r.TLS.Version < 0x0303 {
						t.Error("backend Host/SNI/minimum TLS changed")
					}
					b, e := io.ReadAll(io.LimitReader(r.Body, 2049))
					if e != nil || len(b) > 2048 {
						t.Error("payload unexpectedly changed", e)
					}
					if r.Method == "POST" && string(b) != "private-QA-payload" {
						t.Error("POST body lost")
					}
					w.Header().Set("Content-Type", "text/plain")
					fmt.Fprintf(w, "TLS-BUSINESS:%s:%s", r.Method, string(b))
				}
			}
			start := func(counter *atomic.Int32) *httptest.Server {
				server := httptest.NewUnstartedServer(handler(counter))
				server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
				if mode == "old-TLS" {
					server.TLS.MinVersion = tls.VersionTLS10
					server.TLS.MaxVersion = tls.VersionTLS11
				}
				server.StartTLS()
				t.Cleanup(server.Close)
				return server
			}
			first, second := start(&countA), start(&countB)
			if mode == "unknown-ca" {
				_, ca = lbTLSCertificate(t, backendName, false)
			}
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			if port < 20000 || port > 60000 {
				t.Fatal("private fixture received out-of-contract ephemeral port", port)
			}
			entry := loadBalanceEntry{Format: 2, Revision: 1, Domain: "frontend.example.test", Port: port,
				Nodes:      []core.AppUpstream{{Address: strings.TrimPrefix(first.URL, "https://"), Weight: 1}, {Address: strings.TrimPrefix(second.URL, "https://"), Weight: 2}},
				BackendTLS: &core.LoadBalanceBackendTLS{ServerName: backendName, CAPEM: ca}}
			caPath := filepath.Join(stage, "public-ca.pem")
			if e := os.WriteFile(caPath, []byte(ca), 0600); e != nil {
				t.Fatal(e)
			}
			rendered, e := renderLoadBalanceEntryTrust(entry, caPath)
			if e != nil {
				t.Fatal(e)
			}
			config := fmt.Sprintf("user nobody nogroup;\nworker_processes 1;\npid %s;\nerror_log %s notice;\nevents { worker_connections 64; }\nhttp {\n access_log off;\n client_body_temp_path %s;\n proxy_temp_path %s;\n %s\n}\n", filepath.Join(stage, "nginx.pid"), filepath.Join(stage, "error.log"), filepath.Join(stage, "client-temp"), filepath.Join(stage, "proxy-temp"), rendered)
			// Distribution builds carry absolute default FastCGI/uWSGI/SCGI
			// paths even when this test uses only proxy_pass. Never let their
			// startup ownership checks touch the live host's cache directories.
			privateDefaults := fmt.Sprintf(" fastcgi_temp_path %s;\n uwsgi_temp_path %s;\n scgi_temp_path %s;\n", filepath.Join(stage, "fastcgi-temp"), filepath.Join(stage, "uwsgi-temp"), filepath.Join(stage, "scgi-temp"))
			config = strings.Replace(config, "http {\n", "http {\n"+privateDefaults, 1)
			path := filepath.Join(stage, "nginx.conf")
			if e := os.WriteFile(path, []byte(config), 0600); e != nil {
				t.Fatal(e)
			}
			if b, e := exec.Command(nginx, "-t", "-p", stage+"/", "-c", path).CombinedOutput(); e != nil {
				t.Fatalf("private native syntax: %v %s", e, b)
			}
			output, e := os.OpenFile(filepath.Join(stage, "process.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				t.Fatal(e)
			}
			defer output.Close()
			command := exec.Command(nginx, "-p", stage+"/", "-c", path, "-g", "daemon off;")
			command.Stdout = output
			command.Stderr = output
			if e := command.Start(); e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			defer func() {
				command.Process.Signal(syscall.SIGTERM)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					command.Process.Kill()
					<-done
					t.Error("private Nginx did not stop gracefully")
				}
			}()
			transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			request := func(method, path, body string) (int, string, error) {
				req, e := http.NewRequestWithContext(context.Background(), method, "http://127.0.0.1:"+strconv.Itoa(port)+path, strings.NewReader(body))
				if e != nil {
					return 0, "", e
				}
				req.Host = entry.Domain
				res, e := client.Do(req)
				if e != nil {
					return 0, "", e
				}
				defer res.Body.Close()
				b, e := io.ReadAll(io.LimitReader(res.Body, 4097))
				return res.StatusCode, string(b), e
			}
			ready := false
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				status, body, e := request("GET", loadBalanceProbePath(entry.Domain), "")
				if e == nil && status == 200 && body == loadBalanceFingerprint(entry) {
					ready = true
					break
				}
				select {
				case e := <-done:
					done <- e // The deferred shutdown also observes the terminal result.
					t.Fatalf("private Nginx exited: %v", e)
				default:
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !ready {
				t.Fatal("private entry fingerprint not ready")
			}
			results := []map[string]any{}
			iterations := 2
			if mode == "valid" {
				iterations = 12
			}
			for i := 0; i < iterations; i++ {
				method, body := "GET", ""
				if i%2 != 0 {
					method, body = "POST", "private-QA-payload"
				}
				status, response, e := request(method, "/business?qa=1", body)
				results = append(results, map[string]any{"method": method, "status": status, "body": response})
				if e != nil {
					t.Fatal(e)
				}
				if mode == "valid" {
					if status != 200 || response != "TLS-BUSINESS:"+method+":"+body {
						t.Fatal("real TLS business forwarding failed", status, response)
					}
				} else if status != 502 {
					t.Fatal("invalid TLS not rejected", mode, status, response)
				}
			}
			if mode == "valid" && (countA.Load() == 0 || countB.Load() == 0) {
				t.Fatal("weighted TLS did not reach both fixed nodes")
			}
			if mode != "valid" && countA.Load()+countB.Load() != 0 {
				t.Fatal("invalid TLS reached application or downgraded to HTTP")
			}
			proof := map[string]any{"passed": !t.Failed(), "mode": mode, "private_nginx": true, "not_signed_panel_API_acceptance": true, "results": results, "backend_a_requests": countA.Load(), "backend_b_requests": countB.Load(), "CA_global_trust_untouched": true}
			b, e := json.MarshalIndent(proof, "", "  ")
			if e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(stage, "proof.json"), b, 0600); e != nil {
				t.Fatal(e)
			}
			t.Log("private native TLS forwarding evidence: " + filepath.Join(stage, "proof.json"))
		})
	}
}
