package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"local/panel/internal/runtimecatalog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Actual browser -> actual Core authorization/SQLite queue/immutable bindings.
// The executor is a read-only empty-status fixture: there is intentionally no
// worker and no package installation, capture, service or main-panel mutation.
func TestRegistryRequestLiveBrowserQA(t *testing.T) {
	if os.Getenv("PANEL_REGISTRY_BROWSER_QA") != "1" {
		t.Skip("isolated actual-browser opt-in required")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || strings.TrimSpace(string(host)) != "lima-panel-ids24hj-clean-ubuntu24" || os.Geteuid() != 999 {
		t.Fatal("owned QA guest and unprivileged panel account required")
	}
	web := os.Getenv("PANEL_QA_WEB_DIR")
	if !strings.HasPrefix(web, "/var/tmp/panel-own-registry-browser24il-") || !strings.HasSuffix(web, "/web/dist") {
		t.Fatal("owned frozen web root required")
	}
	if _, err = os.Stat(web + "/index.html"); err != nil {
		t.Fatal(err)
	}
	s := testStore(t)
	accessUser(t, s, "registry-browser-qa", "admin", nil)
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: web, Origin: "http://127.0.0.1:19441", Listen: "127.0.0.1:19106", Socket: "/missing-registry-browser-qa-only.sock"})
	if err != nil {
		t.Fatal(err)
	}
	a.AppCatalog, _ = installSignedCatalog(t, "nginx", "runtime", runtimecatalog.Nginx[0].ID)
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			return nil, fmt.Errorf("QA executor mutation denied")
		}
		body := "{}"
		switch r.URL.Path {
		case "/v1/runtimes":
			body = `{"installed":[]}`
		case "/v1/software":
			body = `[]`
		case "/v1/docker/projects":
			body = `{"projects":[]}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	listener, err := net.Listen("tcp", a.Config.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	var installKeys []string
	var observations, closures int
	finish := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/app-registry/nginx/qa/finish", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var jobs, bindings, pending, closed, pulls int
		err := s.DB.QueryRow(`SELECT (SELECT count(*) FROM runtime_jobs),(SELECT count(*) FROM app_registry_install_requests),(SELECT count(*) FROM app_registry_pending),(SELECT count(*) FROM app_registry_request_closures),(SELECT count(*) FROM audit_logs WHERE action='app-registry.pull')`).Scan(&jobs, &bindings, &pending, &closed, &pulls)
		mu.Lock()
		valid := len(installKeys) >= 3 && installKeys[0] == installKeys[1] && installKeys[2] != installKeys[0] && observations >= 1 && closures == 1
		mu.Unlock()
		if err != nil || !valid || jobs != 1 || bindings != 1 || pending != 1 || closed != 1 || pulls != 1 {
			fail(w, 409, "actual browser request evidence incomplete")
			return
		}
		send(w, 200, map[string]any{"passed": true, "scope": "actual Core temporary SQLite queue and browser; read-only executor fixture; no native installation", "jobs": jobs, "bindings": bindings, "closures": closed, "original_key_replayed": true, "main_panel_changed": false})
		select {
		case finish <- struct{}{}:
		default:
		}
	}))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture := &cookieQAResponse{ResponseWriter: w}
		a.ServeHTTP(capture, r)
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" && r.URL.Path == "/api/app-registry/nginx/install" {
			installKeys = append(installKeys, r.Header.Get("Idempotency-Key"))
		}
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/app-registry/nginx/requests/") && capture.status == 200 {
			observations++
		}
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/close") && capture.status == 200 {
			closures++
		}
	}))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	go server.Serve(listener)
	t.Log("READY owned temporary Core browser fixture guest 19106 host 19441; no executor writes")
	select {
	case <-finish:
	case <-time.After(10 * time.Minute):
		t.Fatal("actual browser evidence timeout")
	}
	mu.Lock()
	raw, _ := json.Marshal(map[string]any{"install_attempts": len(installKeys), "original_key_replayed": installKeys[0] == installKeys[1], "state_reads": observations, "unsubmitted_closures": closures})
	mu.Unlock()
	t.Log(string(raw))
}
