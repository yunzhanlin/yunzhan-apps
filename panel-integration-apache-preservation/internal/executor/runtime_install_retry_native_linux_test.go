//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRuntimeInstallNativeExplicitRetryRetainsAndRefusesForeignEvidence(t *testing.T) {
	if os.Getenv("PANEL_QA_RUNTIME_RETRY_NATIVE") != "1" {
		t.Skip("explicit private Root mutation / genuine owned PID1 fixture required")
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if os.Geteuid() != 0 || identity["CapEff"] != "00000000000000e5" || identity["CapBnd"] != "00000000000000e5" || identity["NoNewPrivs"] != "1" {
		t.Fatal("private retry supervisor identity changed", identity)
	}
	const fixture = "/run/panel-runtime-retry24ami"
	var cases []struct {
		JobID string `json:"job_id"`
		Kind  string `json:"kind"`
	}
	data, err := os.ReadFile(filepath.Join(fixture, "cases.json"))
	if err != nil || json.Unmarshal(data, &cases) != nil || len(cases) != 14 {
		t.Fatal("complete private retry fixture missing", err)
	}
	mux := http.NewServeMux()
	runtimeRoutes(mux)
	post := func(id, release string, retry bool) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"job_id": id, "release_id": release, "retry": retry})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("POST", "/v1/runtimes/install", strings.NewReader(string(body))))
		return w
	}
	results := []map[string]any{}
	for _, row := range cases {
		// FIFO and symlink bytes are intentionally never opened by the test.
		var before []byte
		if row.Kind != "fifo" && row.Kind != "symlink" {
			before, err = os.ReadFile(installPath(row.JobID))
			if err != nil {
				t.Fatal(err)
			}
		}
		release := "apache-2.4.68"
		if row.Kind == "docker-active" {
			release = runtimecatalog.Docker[0].ID
		}
		w := post(row.JobID, release, true)
		if row.Kind == "retry" {
			var status InstallStatus
			if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.JobID != row.JobID || status.State != "queued" || len(status.Steps) != 0 {
				t.Fatal("explicit retry not dispatched as new private attempt", w.Code, w.Body.String())
			}
			digest := sha256.Sum256(before)
			name := row.JobID + "-" + hex.EncodeToString(digest[:]) + ".json"
			root, err := os.OpenRoot(filepath.Join(installState, "retained"))
			if err != nil {
				t.Fatal(err)
			}
			retained, err := readRuntimeInstallPrivateFile(root, name)
			root.Close()
			if err != nil || string(retained) != string(before) {
				t.Fatal("old attempt not retained exactly before reset", err)
			}
			queued, err := os.ReadFile(installPath(row.JobID))
			if err != nil {
				t.Fatal(err)
			}
			for _, retry := range []bool{false, false, true} {
				w := post(row.JobID, release, retry)
				var status InstallStatus
				if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.State != "queued" {
					t.Fatal("pending/active attempt restarted or reset", retry, w.Code, w.Body.String())
				}
				after, err := os.ReadFile(installPath(row.JobID))
				if err != nil || string(queued) != string(after) {
					t.Fatal("active attempt record replaced", err)
				}
			}
			results = append(results, map[string]any{"job_id": row.JobID, "kind": row.Kind, "http_status": 202, "old_record_sha256": hex.EncodeToString(digest[:]), "retained_file": name, "repeat_observations_without_restart": 3})
			continue
		}
		want := 409
		if row.Kind == "succeeded" {
			want = 202
		}
		if w.Code != want {
			t.Fatal("foreign or active evidence admitted/changed", row.Kind, w.Code, w.Body.String())
		}
		if row.Kind == "succeeded" {
			var status InstallStatus
			if json.Unmarshal(w.Body.Bytes(), &status) != nil || status.State != "succeeded" {
				t.Fatal("completed record was restarted", w.Body.String())
			}
		}
		if before != nil {
			after, err := os.ReadFile(installPath(row.JobID))
			if err != nil || string(before) != string(after) {
				t.Fatal("rejected record overwritten", row.Kind, err)
			}
		}
		results = append(results, map[string]any{"job_id": row.JobID, "kind": row.Kind, "http_status": w.Code})
	}
	entries, err := os.ReadDir(filepath.Join(installState, "retained"))
	if err != nil || len(entries) != 2 {
		t.Fatal("unexpected retained record set (one valid old record plus one pre-existing conflict)", len(entries), err)
	}
	for _, row := range cases {
		if row.Kind == "retry" || row.Kind == "retained-conflict" {
			continue
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), row.JobID+"-") {
				t.Fatal("invalid/active evidence created retry history", row.Kind)
			}
		}
	}
	proof, _ := json.MarshalIndent(map[string]any{"passed": true, "cases": results, "actual_executor_retry_post_routes_executed": true, "old_attempt_retained_byte_exact": true, "actual_pid1_start_translated_only_to_owned_sleep_unit_not_a_compiler": true, "runtime_installed": false, "application_installed": false, "public_core_api_or_ui_verified": false, "private_fixture_records_are_not_install_receipts": true}, "", "  ")
	if err := atomicWrite(filepath.Join(fixture, "proof.json"), proof, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("NATIVE_RUNTIME_EXPLICIT_RETRY_PROOF", len(results), core.Hash(string(proof)))
}

func TestRuntimeInstallNativeDaemonGroupDoesNotGrantPanelReadAccess(t *testing.T) {
	if os.Getenv("PANEL_QA_RUNTIME_RETRY_NATIVE") != "1" {
		t.Skip("explicit private production root:panel group fixture required")
	}
	const fixture = "/run/panel-runtime-retry24ami"
	var group struct {
		GID int `json:"gid"`
	}
	data, err := os.ReadFile(filepath.Join(fixture, "group.json"))
	if err != nil || json.Unmarshal(data, &group) != nil || os.Geteuid() != 0 || os.Getegid() != group.GID || group.GID < 1 {
		t.Fatal("actual root:panel producer group required", os.Getegid(), group, err)
	}
	info, err := os.Lstat(installState)
	if err != nil || !runtimeInstallPrivateDirectory(info) || info.Sys().(*syscall.Stat_t).Gid != uint32(group.GID) {
		t.Fatal("actual daemon-group private state is not accepted", err)
	}
	probe := `import json,os,pathlib
assert os.geteuid()!=0
try: list(pathlib.Path('/var/lib/panel-executor/installs').iterdir())
except PermissionError: pass
else: raise AssertionError('panel group could read root-private install authority')
identity={}
for line in pathlib.Path('/proc/self/status').read_text().splitlines():
 if line.startswith(('Uid:','Gid:','CapInh:','CapPrm:','CapEff:','CapAmb:','NoNewPrivs:')):
  key,value=line.split(':',1);identity[key]=value.strip()
assert all(identity[k]=='0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapAmb')) and identity['NoNewPrivs']=='1'
print(json.dumps({'passed':True,'actual_panel_user_denied_private_state':True,'identity':identity},sort_keys=True))`
	result, err := RunCommand(context.Background(), "/usr/sbin/runuser", "-u", "panel", "--", "/usr/bin/setpriv", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", "/usr/bin/python3", "-c", probe)
	var child map[string]any
	if err != nil || json.Unmarshal([]byte(result), &child) != nil || child["passed"] != true {
		t.Fatal("actual panel account accessed native authority", err, result)
	}
	proof, _ := json.MarshalIndent(map[string]any{"passed": true, "actual_root_daemon_gid": group.GID, "root_private_gid_preserved_not_reowned": true, "actual_panel_user": child, "runtime_installed": false, "application_installed": false, "public_core_api_or_ui_verified": false}, "", "  ")
	if err := atomicWrite(filepath.Join(fixture, "group-proof.json"), proof, 0600); err != nil {
		t.Fatal(err)
	}
}
