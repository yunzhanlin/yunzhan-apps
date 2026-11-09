//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Genuine engine and two HTTP virtual hosts, but no published 2.4 application
// receipt or Core API enablement. An outer runner supplies private complete
// filesystem/network namespaces and observes preservation of the live panel.
func TestApacheBodyManagedBlocksNativeTwoSitesTransitions(t *testing.T) {
	if os.Getenv("PANEL_QA_APACHE_BODY_TRANSITION") != "1" {
		t.Skip("explicit private native managed-body transition fixture required")
	}
	job := os.Getenv("PANEL_QA_APACHE_BODY_ENGINE")
	if os.Geteuid() != 0 || !core.ValidID(job) {
		t.Fatal("restricted root and independently sealed engine required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := verifyApacheBodyBuildContext(ctx, job); err != nil {
		t.Fatal("no genuine native authority", err)
	}
	record, err := readApacheBodyBuildRecord(job)
	if err != nil {
		t.Fatal(err)
	}
	root := "/run/panel-apache-body-transition24agv"
	if err := apacheBodyOwnedAncestors(root); err != nil {
		t.Fatal(err)
	}
	var backendHits atomic.Int64
	longStarted, longRelease := make(chan struct{}, 1), make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits.Add(1)
		if r.URL.Path == "/long" {
			io.WriteString(w, "before-reload\n")
			w.(http.Flusher).Flush()
			longStarted <- struct{}{}
			select {
			case <-longRelease:
			case <-r.Context().Done():
			case <-ctx.Done():
			}
			io.WriteString(w, "after-reload\n")
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		sum := sha256.Sum256(body)
		w.Header().Set("X-Owned-Body-SHA", hex.EncodeToString(sum[:]))
		io.WriteString(w, "owned-native-business\n")
	}))
	defer func() { cancel(); backend.Close() }()
	var builder strings.Builder
	fmt.Fprintf(&builder, "# managed by panel\nServerRoot /opt/panel/runtimes/apache/2.4.68\nDefaultRuntimeDir %s\nPidFile %s\nListen 127.0.0.1:19080\nServerName protected-a.localhost\nUser www-data\nGroup www-data\nErrorLog %s\nLogLevel warn\nLogFormat \"%%h %%l %%u %%t \\\"%%r\\\" %%>s %%b\" combined\n", root, filepath.Join(root, "httpd.pid"), filepath.Join(root, "apache-error.log"))
	for _, name := range []string{"mpm_event", "authz_core", "authz_host", "unixd", "log_config", "env", "setenvif", "headers", "rewrite", "proxy", "proxy_http"} {
		fmt.Fprintf(&builder, "LoadModule %s_module /opt/panel/runtimes/apache/2.4.68/modules/mod_%s.so\n", name, name)
	}
	builder.WriteString("StartServers 1\nServerLimit 2\nThreadsPerChild 8\nMaxRequestWorkers 16\nMinSpareThreads 1\nMaxSpareThreads 16\n")
	builder.WriteString("<Directory />\nRequire all granted\n</Directory>\n")
	for _, host := range []struct{ id, domain string }{{apacheBodyConfigSiteA, "protected-a.localhost"}, {apacheBodyConfigSiteB, "protected-b.localhost"}} {
		fmt.Fprintf(&builder, "<VirtualHost 127.0.0.1:19080>\n  ServerName %s\n  SetEnvIfExpr \"true\" PANEL_AW_SITE=%s\n  %s  CustomLog /var/log/apache2/panel-%s.access.log combined\n  ProxyPass /long %s/long flushpackets=on\n  ProxyPass / %s/\n</VirtualHost>\n", host.domain, host.id, apacheWAFInclude, host.id, backend.URL, backend.URL)
	}
	base := builder.String()
	previous := core.DefaultApacheWAFConfig()
	s := New(Config{SystemRoot: "/", SitesDir: "/srv/panel/sites", ApacheSiteConfig: filepath.Join(root, "httpd.conf")})
	rulesPath := "/etc/panel/security-apps/modules/apache-waf/rules.conf"
	write := func(source string, cfg core.WAFConfig) {
		t.Helper()
		_, bindings, err := func() (string, map[string][]string, error) { b, e := apacheWAFBindings(source); return source, b, e }()
		if err != nil {
			t.Fatal(err)
		}
		rules, err := renderApacheWAFVersion(cfg, bindings, core.ApacheWAFNativeBodyVersion)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rulesPath, []byte(rules), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.Config.ApacheSiteConfig, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.CommandContext(ctx, record.ApacheBinary, "-t", "-f", s.Config.ApacheSiteConfig).CombinedOutput()
		if err != nil {
			t.Fatal("actual two-vhost native parser", err, string(output))
		}
	}
	write(base, previous)
	startup, err := os.OpenFile(filepath.Join(root, "startup.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer startup.Close()
	cmd := exec.CommandContext(ctx, record.ApacheBinary, "-DFOREGROUND", "-f", s.Config.ApacheSiteConfig)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = startup, startup
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case e := <-done:
			if e != nil {
				t.Error("owned Apache shutdown", e)
			}
		case <-time.After(10 * time.Second):
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
			t.Error("owned Apache did not exit")
		}
	}()
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	requestTyped := func(host, path, body, contentType string) (*http.Response, error) {
		r, e := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1:19080"+path, strings.NewReader(body))
		if e != nil {
			return nil, e
		}
		r.Host = host
		r.Header.Set("Content-Type", contentType)
		return client.Do(r)
	}
	request := func(host, path, body string) (*http.Response, error) {
		return requestTyped(host, path, body, "application/json")
	}
	wait := func(cfg core.WAFConfig) {
		t.Helper()
		for deadline := time.Now().Add(8 * time.Second); ; {
			r, e := request("protected-a.localhost", "/probe", `{"term":"ordinary"}`)
			if e == nil {
				valid := r.StatusCode == 200 && r.Header.Get("X-Panel-Apache-WAF") == apacheWAFProbeVersion(cfg, core.ApacheWAFNativeBodyVersion)
				r.Body.Close()
				if valid {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("actual new Apache generation not confirmed", e)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	wait(previous)
	longResponse, err := request("protected-b.localhost", "/long", "")
	if err != nil {
		t.Fatal(err)
	}
	defer longResponse.Body.Close()
	select {
	case <-longStarted:
	case <-ctx.Done():
		t.Fatal("long business not started")
	}
	results := []map[string]any{}
	source := base
	for i, pair := range [][2]string{{"block", "observe"}, {"observe", "block"}, {"off", "block"}, {"off", "off"}} {
		next := core.DefaultApacheWAFConfig()
		next.Policy.Revision = int64(i + 1)
		next.Body = &core.WAFBodyConfig{EngineJobID: job, Sites: []core.WAFBodySitePolicy{}}
		for j, id := range []string{apacheBodyConfigSiteA, apacheBodyConfigSiteB} {
			p := core.DefaultWAFBodyPolicy()
			p.Mode = pair[j]
			next.Body.Sites = append(next.Body.Sites, core.WAFBodySitePolicy{SiteID: id, Policy: p})
		}
		prepared, e := s.prepareApacheBodyTransition(ctx, source, previous, next)
		if e != nil {
			t.Fatal("privileged exact-authority transition preparation", e)
		}
		write(prepared, next)
		if e := cmd.Process.Signal(syscall.SIGUSR1); e != nil {
			t.Fatal("native graceful reload", e)
		}
		wait(next)
		if i == 0 {
			close(longRelease)
			body, e := io.ReadAll(io.LimitReader(longResponse.Body, 128))
			longResponse.Body.Close()
			if e != nil || string(body) != "before-reload\nafter-reload\n" {
				t.Fatal("pre-existing business response interrupted by native activation", e, string(body))
			}
			if mode := os.Getenv("PANEL_QA_APACHE_BODY_EXHAUSTION"); mode != "" {
				apacheBodyQuotaExhaustionHTTP(t, ctx, root, mode, requestTyped, &backendHits)
				return // Separate full-cache proof, not the 16-case transition receipt.
			}
		}
		for j, host := range []string{"protected-a.localhost", "protected-b.localhost"} {
			for _, payload := range []string{`{"term":"ordinary"}`, `{"term":"<script>alert('owned-private-body')</script>"}`} {
				before := backendHits.Load()
				r, e := request(host, "/probe", payload)
				if e != nil {
					t.Fatal(e)
				}
				_, e = io.Copy(io.Discard, io.LimitReader(r.Body, 8192))
				r.Body.Close()
				wanted := 200
				if pair[j] == "block" && strings.Contains(payload, "<script>") {
					wanted = 403
				}
				digest := sha256.Sum256([]byte(payload))
				if e != nil || r.StatusCode != wanted || (backendHits.Load() > before) != (wanted == 200) || wanted == 200 && r.Header.Get("X-Owned-Body-SHA") != hex.EncodeToString(digest[:]) || r.Header.Get("X-Panel-Apache-WAF") != apacheWAFProbeVersion(next, core.ApacheWAFNativeBodyVersion) {
					t.Fatal("independent native site mode/body/fingerprint", host, pair[j], wanted, r.StatusCode, e)
				}
				results = append(results, map[string]any{"host": host, "mode": pair[j], "attack": strings.Contains(payload, "<script>"), "status": r.StatusCode, "original_forwarded_body_checked": wanted == 200})
			}
		}
		if err := verifyApacheBodyBuildContext(ctx, job); err != nil {
			t.Fatal("native program changed during activation", err)
		}
		source, previous = prepared, next
	}
	if source != base || strings.Contains(source, "mod_security2.so") {
		t.Fatal("last site off failed exact main-source restoration")
	}
	log, err := openApacheBodyMetadataLog()
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := io.ReadAll(io.LimitReader(log, 4<<20))
	log.Close()
	if err != nil || len(metadata) == 0 || strings.Contains(string(metadata), "owned-private-body") {
		t.Fatal("native numeric log absent or leaked request bytes", err)
	}
	now, err := readApacheBodyBuildRecord(job)
	if err != nil || !reflect.DeepEqual(now, record) {
		t.Fatal("immutable ready authority was overwritten by activation", err)
	}
	if _, err := os.Stat(filepath.Join(apacheBodyTemporary, apacheBodyConfigSiteA)); errors.Is(err, os.ErrNotExist) {
		t.Fatal("disable removed retained request temp evidence")
	}
	proof := map[string]any{"passed": !t.Failed(), "published_application_activation": false, "signed_release_acceptance": false, "main_19100_started": false, "engine_job": job, "actual_native_http_cases": results, "preexisting_long_response_preserved": true, "exact_source_restored_after_last_site_off": source == base, "ready_record_preserved": true, "numeric_metadata_bytes": len(metadata), "request_marker_logged": false, "temporary_storage_is_not_a_disk_hard_quota": true}
	if err := moduleWrite(filepath.Join(root, "transition-proof.json"), proof); err != nil {
		t.Fatal(err)
	}
}
