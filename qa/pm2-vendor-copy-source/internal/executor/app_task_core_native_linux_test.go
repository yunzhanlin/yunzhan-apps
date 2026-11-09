//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// Only called from the explicit fresh root-owned native fixture. No fabricated
// RPC reply: actual authenticated Core -> real private Unix -> actual executor
// handler/history -> kernel signal -> actual Core result audit. Module setup is
// an actual default-key signed registry install through the real Core worker.
func prepareTaskNativeAuthenticatedSignal(t *testing.T, ctx context.Context, base string) func(context.Context, core.AppModuleInput) (any, error) {
	t.Helper()
	for _, name := range []string{"data", "web", "security", "state"} {
		if err := os.Mkdir(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	svc := New(Config{SecurityDir: filepath.Join(base, "security"), StateDir: filepath.Join(base, "state")})
	if svc.moduleInstalled("task-manager") {
		t.Fatal("fresh fixture must not preinstall Task")
	}
	store, err := core.OpenStore(filepath.Join(base, "data", "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.DB.Close() })
	socket := filepath.Join(base, "executor.sock")
	panel, err := core.NewServer(store, core.Config{DataDir: filepath.Join(base, "data"), WebDir: filepath.Join(base, "web"), Origin: "http://127.0.0.1:19499", Socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(panel.Executor.Client.CloseIdleConnections)
	listener, err := net.Listen("unix", socket)
	if err != nil || os.Chmod(socket, 0600) != nil {
		t.Fatal("private actual Unix executor", err)
	}
	var signals atomic.Int32
	var installs atomic.Int32
	installEntered, installRelease := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseInstall := func() { releaseOnce.Do(func() { close(installRelease) }) }
	t.Cleanup(releaseInstall)
	var target atomic.Value
	target.Store("")
	handler := svc.Handler()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed := r.Method == "GET" && r.URL.Path == "/v1/app-modules/task-manager"
		if r.Method == "GET" && r.URL.Path == "/v1/software" {
			allowed = true
		}
		if r.Method == "POST" && r.URL.Path == "/v1/software/task-manager/install" {
			attempt := installs.Add(1)
			if attempt > 2 {
				respond(w, 409, map[string]string{"error": "native fixture refuses a repeated installation"})
				return
			}
			if attempt == 2 {
				close(installEntered)
				select {
				case <-r.Context().Done():
					return
				case <-installRelease:
				}
			}
			allowed = true
		}
		if r.Method == "POST" && r.URL.Path == "/v1/app-modules/task-manager/run" {
			allowed = true
		}
		if r.Method == "POST" && r.URL.Path == "/v1/app-modules/task-manager/terminate" {
			var requested int
			originalTarget := target.Load().(string)
			if originalTarget == "" {
				respond(w, 409, map[string]string{"error": "native child identity not selected"})
				return
			}
			if err := store.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='app-module.terminate.requested' AND target=?`, originalTarget).Scan(&requested); err != nil || requested != 1 || signals.Add(1) != 1 {
				respond(w, 500, map[string]string{"error": "native fixture refuses unaudited/repeated signal"})
				return
			}
			allowed = true
		}
		if !allowed {
			respond(w, 503, map[string]string{"error": "private fixture excludes unrelated executor endpoints"})
			return
		}
		handler.ServeHTTP(w, r)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Close() })
	requestWithContext := func(ctx context.Context, path string, body []byte, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(ctx, "POST", panel.Config.Origin+path, bytes.NewReader(body))
		r.Header.Set("Origin", panel.Config.Origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		panel.ServeHTTP(w, r)
		return w
	}
	token, err := os.ReadFile(filepath.Join(base, "data", "bootstrap-token"))
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, _ := json.Marshal(map[string]string{"username": "native-task-admin", "password": "private-native-task-password-long", "token": strings.TrimSpace(string(token))})
	if w := requestWithContext(ctx, "/api/bootstrap", bootstrap, "", nil); w.Code != 201 {
		t.Fatal("actual private task bootstrap", w.Code)
	}
	login := requestWithContext(ctx, "/api/login", []byte(`{"username":"native-task-admin","password":"private-native-task-password-long"}`), "", nil)
	var auth struct {
		CSRF string `json:"csrf"`
	}
	if login.Code != 200 || json.Unmarshal(login.Body.Bytes(), &auth) != nil || auth.CSRF == "" || len(login.Result().Cookies()) != 1 {
		t.Fatal("actual private task login", login.Code)
	}
	cookie := login.Result().Cookies()[0]
	var user string
	if err := store.DB.QueryRow(`SELECT id FROM users WHERE username='native-task-admin'`).Scan(&user); err != nil || !core.ValidID(user) {
		t.Fatal("actual current private task administrator", err)
	}
	menus := func(raw string) {
		t.Helper()
		if _, err := store.DB.Exec(`INSERT INTO app_user_menus(user_id,menu_ids,revision) VALUES(?,?,1) ON CONFLICT(user_id) DO UPDATE SET menu_ids=excluded.menu_ids,revision=app_user_menus.revision+1`, user, raw); err != nil {
			t.Fatal(err)
		}
	}
	menus(`["system-tools","runtimes"]`)
	taskNativeSignedRegistryInstall(t, ctx, base, panel, store, svc, cookie, auth.CSRF, &installs, installEntered, releaseInstall)
	menus(`["system-tools"]`)
	if ctx.Err() != nil || !svc.moduleInstalled("task-manager") {
		t.Fatal("actual Task setup not installed before the child window", ctx.Err())
	}
	if err := moduleWrite(filepath.Join(base, "core-install-window-acceptance.json"), map[string]any{"passed": true, "actual_signed_registry_worker_install_completed_before_child_spawn": true, "setup_context_seconds": 15, "child_context_seconds": 15, "enclosing_test_seconds": 45, "unit_runtime_seconds": 60, "no_manufactured_module_record": true, "main_panel_changed": false, "all_50_commercial": false}); err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, in core.AppModuleInput) (any, error) {
		originalTarget := fmt.Sprintf("pid:%d:start:%d", in.PID, in.StartTime)
		target.Store(originalTarget)
		request := func(path string, body []byte, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
			return requestWithContext(ctx, path, body, csrf, cookie)
		}
		// Read real kernel telemetry through the same authenticated Core and actual
		// Unix executor before signaling. No synthetic rows or permission fallback.
		snapshotReply := request("/api/app-modules/task-manager/run", []byte(`{}`), auth.CSRF, cookie)
		var snapshot map[string]any
		if snapshotReply.Code != 200 || json.Unmarshal(snapshotReply.Body.Bytes(), &snapshot) != nil || signals.Load() != 0 || unix.Kill(in.PID, 0) != nil {
			t.Fatal("actual authenticated task snapshot", snapshotReply.Code, signals.Load())
		}
		rows, rowsOK := snapshot["processes"].([]any)
		if !rowsOK || len(rows) > 500 || snapshot["sample_limit"] != float64(2000) || snapshot["display_limit"] != float64(500) || snapshot["displayed_processes"] != float64(len(rows)) {
			t.Fatal("actual snapshot omitted bounded counts")
		}
		var originalRow map[string]any
		for _, raw := range rows {
			row, ok := raw.(map[string]any)
			if !ok {
				t.Fatal("actual snapshot malformed row")
			}
			for key, flag := range map[string]string{"cpu_percent": "cpu_available", "read_rate": "io_available", "write_rate": "io_available"} {
				available, ok := row[flag].(bool)
				value, numeric := row[key].(float64)
				if !ok || available && (!numeric || math.IsNaN(value) || math.IsInf(value, 0) || value < 0) || !available && row[key] != nil {
					t.Fatal("unreadable actual counter presented as a known zero", key)
				}
			}
			if row["pid"] == float64(in.PID) {
				originalRow = row
			}
		}
		if originalRow == nil || originalRow["start_time"] != float64(in.StartTime) || originalRow["managed"] != true || originalRow["can_terminate"] != true {
			t.Fatal("actual snapshot did not retain original authorized child identity")
		}
		if err := moduleWrite(filepath.Join(base, "core-telemetry-acceptance.json"), map[string]any{"passed": true, "actual_authenticated_core_unix_kernel_snapshot": true, "original_pid": in.PID, "original_start_time": in.StartTime, "original_cpu_available": originalRow["cpu_available"], "original_io_available": originalRow["io_available"], "original_cpu_percent": originalRow["cpu_percent"], "original_read_rate": originalRow["read_rate"], "original_write_rate": originalRow["write_rate"], "unavailable_rates_are_null_not_zero": true, "sample_limit": snapshot["sample_limit"], "display_limit": snapshot["display_limit"], "sampled_processes": snapshot["sampled_processes"], "displayed_processes": len(rows), "partial": snapshot["partial"], "child_alive_and_signal_requests_zero_after_read": true, "atomic_full_snapshot": false, "browser_verified": false, "all_50_commercial": false}); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(in)
		path := "/api/app-modules/task-manager/terminate"
		denied := func(code int, csrf string, cookie *http.Cookie) {
			t.Helper()
			if w := request(path, body, csrf, cookie); w.Code != code || signals.Load() != 0 || unix.Kill(in.PID, 0) != nil {
				t.Fatal("actual denied Core request dispatched an original signal", w.Code, signals.Load())
			}
		}
		denied(401, "", nil)
		denied(403, "wrong-private-csrf", cookie)
		menus(`[]`)
		denied(403, auth.CSRF, cookie)
		menus(`["system-tools"]`)
		if _, err := store.DB.Exec(`CREATE TRIGGER task_native_refuse_request BEFORE INSERT ON audit_logs WHEN NEW.action='app-module.terminate.requested' BEGIN SELECT RAISE(ABORT,'private requested audit fixture'); END`); err != nil {
			t.Fatal(err)
		}
		denied(409, auth.CSRF, cookie)
		if _, err := store.DB.Exec(`DROP TRIGGER task_native_refuse_request`); err != nil {
			t.Fatal(err)
		}
		w := request(path, body, auth.CSRF, cookie)
		var out map[string]any
		if w.Code != 200 || signals.Load() != 1 || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out) != 4 || out["pid"] != float64(in.PID) || out["signal"] != "SIGTERM" || out["signal_accepted"] != true || out["exit_verified"] != false {
			return nil, errors.New("actual original Core/Unix signal reply not completely verified")
		}
		var requested, confirmed, unknown int
		if err := store.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE actor='native-task-admin' AND action='app-module.terminate.requested' AND target=? AND result='SIGTERM requested; exit unverified'`, originalTarget).Scan(&requested); err != nil {
			t.Fatal(err)
		}
		if err := store.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE actor='native-task-admin' AND action='app-module.terminate' AND target=? AND result='SIGTERM accepted; exit unverified'`, originalTarget).Scan(&confirmed); err != nil {
			t.Fatal(err)
		}
		if err := store.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='app-module.terminate.unknown'`).Scan(&unknown); err != nil || requested != 1 || confirmed != 1 || unknown != 0 {
			t.Fatal("actual original SQLite audit receipt", requested, confirmed, unknown, err)
		}
		var report map[string]any
		if err := moduleRead(filepath.Join(svc.moduleDir("task-manager"), "last-report.json"), &report); err != nil || report["action"] != "terminate" {
			t.Fatal("actual executor signal report not durably written", err)
		}
		if err := moduleWrite(filepath.Join(base, "core-signal-acceptance.json"), map[string]any{"passed": true, "actual_core_login_csrf_current_system_tools_permission": true, "actual_denied_unauthenticated_csrf_revoked_and_audit_failure_child_alive": true, "actual_unix_signal_requests": signals.Load(), "actual_original_request_and_result_audits": requested + confirmed, "original_pid": in.PID, "original_start_time": in.StartTime, "actual_executor_signal_history_and_report_written": true, "signal_receipt_is_not_exit": true, "module_setup_is_actual_signed_registry_worker_install": true, "catalog_manifest_transport_is_offline_verified_not_live_github": true, "cold_boot_verified": false, "browser_verified": false, "all_50_commercial": false}); err != nil {
			t.Fatal(err)
		}
		t.Log("PASS actual authenticated Task Core, real Unix executor and original kernel signal after durable request audit; denied CSRF/revocation/audit failures keep child alive; setup uses official signed-catalog package and actual Core worker; not real PM2/browser/cold-boot acceptance")
		return out, nil
	}
}
