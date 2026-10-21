//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Test-only origin selection. Never bind, proxy or replace the main panel ports;
// an external host browser speaks to this PRIVATE Core through its Unix socket.
func wafNativeBrowserOrigin(raw string, enabled bool) (string, error) {
	bad := errors.New("private browser witness requires a canonical distinct loopback origin")
	if raw == "" && !enabled {
		return "http://127.0.0.1:19100", nil
	}
	if !enabled || raw == "" || len(raw) > 64 {
		return "", bad
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", bad
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < 1024 || p > 65535 || p == 19100 || p == 19101 || u.Scheme != "http" || u.User != nil || u.Host != net.JoinHostPort("127.0.0.1", strconv.Itoa(p)) || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != raw {
		return "", bad
	}
	return raw, nil
}

func TestWAFNativeBrowserOrigin(t *testing.T) {
	if got, err := wafNativeBrowserOrigin("", false); err != nil || got != "http://127.0.0.1:19100" {
		t.Fatal(got, err)
	}
	if got, err := wafNativeBrowserOrigin("http://127.0.0.1:54321", true); err != nil || got != "http://127.0.0.1:54321" {
		t.Fatal(got, err)
	}
	for _, raw := range []string{"", "http://127.0.0.1:19100", "http://127.0.0.1:19101", "http://127.0.0.1:80", "http://127.0.0.1:65536", "http://127.0.0.1:054321", "http://127.0.0.1:54321/", "http://127.0.0.1:54321?", "http://127.0.0.1:54321#x", "http://user@127.0.0.1:54321", "https://127.0.0.1:54321", "http://localhost:54321", "http://[::1]:54321", "http://example.test:54321"} {
		if _, err := wafNativeBrowserOrigin(raw, true); err == nil {
			t.Fatal("non-private origin adopted", raw)
		}
	}
	if _, err := wafNativeBrowserOrigin("http://127.0.0.1:54321", false); err == nil {
		t.Fatal("browser fixture mode not explicit")
	}
}

type wafNativeWireWriter struct {
	http.ResponseWriter
	status int
}

// A legitimate restricted account starts on its first authorized menu, which
// is Security after the actual Core normalizes grants. Permit its exact GETs
// through Core, not through an invented healthy response or an extra executor
// capability. Existing executor exclusions and current-account guards remain.
func wafNativeWireAllowed(method, path string) bool {
	if method == "POST" {
		return path == "/api/login" || path == "/api/logout" || path == "/api/session/activity"
	}
	if method != "GET" {
		return false
	}
	switch path {
	case "/api/bootstrap", "/api/me", "/api/software", "/api/app-registry", "/api/runtimes",
		"/api/security/firewall", "/api/security/ssh", "/api/security/login-events", "/api/security/site-scan", "/api/security/fail2ban", "/api/certificates",
		"/api/software/nginx-waf/config", "/api/software/nginx-waf/sites", "/api/software/nginx-waf/report", "/api/software/nginx-waf/history", "/api/software/nginx-waf/engines", "/api/software/nginx-waf/body-report", "/api/software/nginx-waf/body-log/archives", "/api/software/nginx-waf/body-log/rotation", "/api/software/nginx-waf/requests":
		return true
	}
	for _, prefix := range []string{"/api/software/nginx-waf/requests/", "/api/software/nginx-waf/jobs/"} {
		if strings.HasPrefix(path, prefix) && core.ValidID(strings.TrimPrefix(path, prefix)) {
			return true
		}
	}
	return false
}

func TestWAFNativeBrowserReadOnlyWire(t *testing.T) {
	for _, path := range []string{"/api/security/firewall", "/api/security/ssh", "/api/security/login-events", "/api/security/site-scan", "/api/security/fail2ban", "/api/certificates", "/api/runtimes", "/api/software/nginx-waf/requests/" + strings.Repeat("a", 32), "/api/software/nginx-waf/jobs/" + strings.Repeat("b", 32)} {
		if !wafNativeWireAllowed("GET", path) || wafNativeWireAllowed("POST", path) || wafNativeWireAllowed("DELETE", path) {
			t.Fatal("read-only page request lost or widened", path)
		}
	}
	for _, path := range []string{"/api/security/firewall/confirm", "/api/security/fail2ban/unban", "/api/sites", "/api/audit", "/api/software/nginx-waf/install", "/api/software/nginx-waf/configure", "/api/software/nginx-waf/preview", "/api/software/nginx-waf/archive-config-backup", "/api/software/nginx-waf/requests/" + strings.Repeat("a", 31), "/api/software/apache-waf/requests/" + strings.Repeat("a", 32)} {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			if wafNativeWireAllowed(method, path) {
				t.Fatal("unrelated capability admitted", method, path)
			}
		}
	}
	for _, path := range []string{"/api/login", "/api/logout", "/api/session/activity"} {
		if !wafNativeWireAllowed("POST", path) || wafNativeWireAllowed("GET", path) {
			t.Fatal("authentication verb changed", path)
		}
	}
}

func (w *wafNativeWireWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *wafNativeWireWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

// Real HTTP parsing, cookies, login, current-role authorization and actual Core
// JSON. No mocked response is used here. This small read-only wire window is
// within the original 250s context and NEVER extends unit/test/client deadlines.
// Native trace alone is not Chrome acceptance; that proof belongs to the host.
func wafNativeBrowserWire(t *testing.T, ctx context.Context, panel *core.Server, store *core.Store, base, origin, original string) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) < 25*time.Second || !core.ValidID(original) {
		t.Fatal("no existing native context budget for the private wire window")
	}
	snapshot := func() string {
		t.Helper()
		rows, err := store.DB.QueryContext(ctx, `SELECT p.job_id,p.actor_id,p.app_id,p.kind,p.idempotency_key,p.payload_sha256,p.created_at,j.state,j.payload,j.error,j.created_at,j.updated_at FROM waf_apply_requests p JOIN runtime_jobs j ON j.id=p.job_id ORDER BY p.job_id`)
		if err != nil {
			t.Fatal(err)
		}
		values := [][12]string{}
		for rows.Next() {
			var row [12]string
			if err := rows.Scan(&row[0], &row[1], &row[2], &row[3], &row[4], &row[5], &row[6], &row[7], &row[8], &row[9], &row[10], &row[11]); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			values = append(values, row)
			if len(values) > 6 {
				rows.Close()
				t.Fatal("wire created another original request")
			}
		}
		err = rows.Err()
		closeErr := rows.Close()
		if err != nil || closeErr != nil || len(values) != 6 {
			t.Fatal("incomplete wire original snapshot", err, closeErr)
		}
		encoded, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		return core.Hash(string(encoded))
	}
	before := snapshot()
	socket := filepath.Join(base, "core-http.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil || os.Chmod(socket, 0600) != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	calls := 0
	trace := map[string]int{}
	denied := 0
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16384, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed := wafNativeWireAllowed(r.Method, r.URL.Path)
		mu.Lock()
		calls++
		if calls > 160 || r.ContentLength > 16<<10 {
			allowed = false
		}
		if !allowed {
			denied++
		}
		mu.Unlock()
		if !allowed {
			http.Error(w, "private browser wire denies software writes and unrelated capabilities", 503)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		writer := &wafNativeWireWriter{ResponseWriter: w}
		panel.ServeHTTP(writer, r)
		mu.Lock()
		trace[r.Method+" "+r.URL.Path+" "+strconv.Itoa(writer.status)]++
		mu.Unlock()
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	nonce := core.ID()
	if err := moduleWrite(filepath.Join(base, "wire-ready.json"), map[string]any{"format": 1, "origin": origin, "original_job_id": original, "nonce": nonce, "socket_basename": "core-http.sock", "read_only_software": true, "wire_window_seconds": 25}); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(25 * time.Second)
	defer timer.Stop()
	for {
		var done struct {
			Format int    `json:"format"`
			Nonce  string `json:"nonce"`
		}
		err := readAnalyticsHTMLPrivateJSON(filepath.Join(base, "wire-done.json"), 256, &done)
		if err == nil {
			if done.Format != 1 || done.Nonce != nonce {
				t.Fatal("wire closure witness not the original private nonce")
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal("wire closure witness malformed; not repaired", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("original native context expired; no deadline extension", ctx.Err())
		case <-timer.C:
			t.Fatal("private browser wire window expired; unverified closure")
		case <-time.After(25 * time.Millisecond):
		}
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if snapshot() != before {
		t.Fatal("browser changed original job states, payloads or identity bindings")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, key := range []string{"POST /api/login 200", "GET /api/me 200", "GET /api/software/nginx-waf/requests 200", "GET /api/software/nginx-waf/requests/" + original + " 200", "GET /api/software/nginx-waf/jobs/" + original + " 200", "GET /api/software/nginx-waf/config 200"} {
		if trace[key] == 0 {
			t.Fatal("missing actual Core wire operation", key)
		}
	}
	if denied != 0 || calls > 160 {
		t.Fatal("browser requested an unrelated operation or software write", denied, calls)
	}
	if err := moduleWrite(filepath.Join(base, "wire-acceptance.json"), map[string]any{"passed": true, "actual_core_http_login_cookies_authorization_and_original_json": true, "original_job_id": original, "original_bindings_and_jobs_sha256": before, "original_six_requests_and_job_states_unchanged": true, "software_writes_excluded": true, "actual_http_calls": calls, "actual_http_trace": trace, "native_context_seconds_unchanged": 250, "browser_verified_by_this_native_trace": false, "main_panel_changed": false, "cold_boot_verified": false, "all_50_commercial": false}); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS actual Core HTTP wire original request reads, real login/cookies/authorization, current configuration and unchanged original jobs; no fake JSON, software write or longer native deadline; native trace is not by itself Chrome acceptance")
}
