//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The external harness binds a new immutable install-record directory and a
// closed systemctl broker. The broker maps only exact fixed job-unit queries
// to owned PID1 units and returns their actual output/status, never fixtures.
func TestRuntimeInstallNativeGETHonestStateAndEvidencePreservation(t *testing.T) {
	if os.Getenv("PANEL_QA_RUNTIME_STATUS_NATIVE") != "1" {
		t.Skip("explicit private genuine systemd runtime-status fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("private read-only Root fixture required")
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if identity["CapEff"] != "0000000000000004" || identity["CapBnd"] != "0000000000000004" || identity["NoNewPrivs"] != "1" {
		t.Fatal("GET observation widened privileges", identity)
	}
	const fixture = "/run/panel-runtime-observer24amd"
	var cases []struct {
		JobID string `json:"job_id"`
		Want  string `json:"want"`
	}
	data, err := os.ReadFile(filepath.Join(fixture, "cases.json"))
	if err != nil || json.Unmarshal(data, &cases) != nil || len(cases) != 8 {
		t.Fatal("private complete fixture cases missing", err)
	}
	mux := http.NewServeMux()
	runtimeRoutes(mux)
	results := []map[string]any{}
	for _, row := range cases {
		before, err := os.ReadFile(installPath(row.JobID))
		if err != nil {
			t.Fatal(err)
		}
		for repeat := 0; repeat < 2; repeat++ {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/runtimes/jobs/"+row.JobID, nil))
			var response struct {
				JobID     string `json:"job_id"`
				ReleaseID string `json:"release_id"`
				State     string `json:"state"`
				Error     string `json:"error"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.JobID != row.JobID || response.ReleaseID != "apache-2.4.68" || response.State != row.Want {
				t.Fatal("actual native GET observation", row, w.Code, w.Body.String())
			}
			if (row.Want == "failed" || row.Want == "needs_attention") && response.Error == "" {
				t.Fatal("failed or uncertain native result has no explanation")
			}
			results = append(results, map[string]any{"job_id": row.JobID, "repeat": repeat, "actual_state": response.State, "actual_http_status": w.Code})
		}
		after, err := os.ReadFile(installPath(row.JobID))
		if err != nil || string(before) != string(after) {
			t.Fatal("GET rewrote native evidence", row.JobID, err)
		}
	}
	// An unavailable actual command is unknown, not success or a writable
	// native failure receipt. The record remains immutable after cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/runtimes/jobs/"+cases[0].JobID, nil).WithContext(ctx))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "未修改原记录") {
		t.Fatal("cancelled real command was interpreted as completion", w.Code, w.Body.String())
	}
	proof, _ := json.MarshalIndent(map[string]any{"passed": true, "actual_executor_get_routes_executed": true, "actual_pid1_commands_via_closed_owned_unit_translation": true, "original_native_records_read_only": true, "cases": results, "cancelled_read_is_503_not_completion": true, "application_installed": false, "runtime_installed": false, "public_core_api_or_ui_verified": false}, "", "  ")
	if err := atomicWrite(filepath.Join(fixture, "proof.json"), proof, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("NATIVE_RUNTIME_STATUS_READONLY_PROOF", len(results))
}

func TestRuntimeInstallNativePOSTResumeNeverCreatesAnotherAttempt(t *testing.T) {
	if os.Getenv("PANEL_QA_RUNTIME_STATUS_NATIVE") != "1" {
		t.Skip("explicit private genuine systemd read-only resume fixture required")
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if os.Geteuid() != 0 || identity["CapEff"] != "0000000000000004" || identity["CapBnd"] != "0000000000000004" || identity["NoNewPrivs"] != "1" {
		t.Fatal("native resume widened privileges", identity)
	}
	const fixture = "/run/panel-runtime-observer24amd"
	var cases []struct {
		JobID string `json:"job_id"`
		Want  string `json:"want"`
	}
	data, err := os.ReadFile(filepath.Join(fixture, "cases.json"))
	if err != nil || json.Unmarshal(data, &cases) != nil || len(cases) != 8 {
		t.Fatal("private complete resume fixture missing", err)
	}
	mux := http.NewServeMux()
	runtimeRoutes(mux)
	results := []map[string]any{}
	for _, row := range cases {
		before, err := os.ReadFile(installPath(row.JobID))
		if err != nil {
			t.Fatal(err)
		}
		for repeat := 0; repeat < 2; repeat++ {
			body, _ := json.Marshal(map[string]any{"job_id": row.JobID, "release_id": "apache-2.4.68", "retry": false})
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest("POST", "/v1/runtimes/install", strings.NewReader(string(body))))
			var response InstallStatus
			if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.JobID != row.JobID || response.ReleaseID != "apache-2.4.68" || response.State != row.Want {
				t.Fatal("resume created a new attempt or changed result", row, w.Code, w.Body.String())
			}
			if (row.Want == "failed" || row.Want == "needs_attention") && response.Error == "" {
				t.Fatal("uncertain resume has no explanation")
			}
			results = append(results, map[string]any{"job_id": row.JobID, "repeat": repeat, "actual_state": response.State, "actual_http_status": w.Code})
		}
		after, err := os.ReadFile(installPath(row.JobID))
		if err != nil || string(before) != string(after) {
			t.Fatal("resume rewrote native evidence", row.JobID, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(installState, ".native-start.lock")); !os.IsNotExist(err) {
		t.Fatal("observation created a writable native start lock", err)
	}
	if _, err := os.Lstat(filepath.Join(installState, "retained")); !os.IsNotExist(err) {
		t.Fatal("observation created retry history", err)
	}
	proof, _ := json.MarshalIndent(map[string]any{"passed": true, "actual_executor_post_resume_routes_executed": true, "retry_false": true, "cases": results, "no_native_record_or_start_lock_or_history_write": true, "actual_pid1_commands_via_closed_owned_unit_translation": true, "runtime_installed": false, "application_installed": false, "public_core_api_or_ui_verified": false}, "", "  ")
	if err := atomicWrite(filepath.Join(fixture, "resume-proof.json"), proof, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("NATIVE_RUNTIME_POST_READONLY_RESUME_PROOF", len(results))
}
