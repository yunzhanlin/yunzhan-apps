//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Read-only inventory using separately genuine sealed YZ4 and YZ5 programs.
// The outer runner may corrupt its OWN COPY of the old DSO for the negative
// case. Neither this test nor the API migrates/repairs/deletes any stored bytes.
func TestApacheBodyNativeRetainedInventoryNeverAuthorizesOldProgram(t *testing.T) {
	if os.Getenv("PANEL_QA_APACHE_BODY_RETAINED_API") != "1" {
		t.Skip("explicit private genuine old/current sealed inventory required")
	}
	old, current := os.Getenv("PANEL_QA_APACHE_BODY_RETAINED_OLD"), os.Getenv("PANEL_QA_APACHE_BODY_RETAINED_CURRENT")
	tampered := os.Getenv("PANEL_QA_APACHE_BODY_RETAINED_TAMPERED") == "1"
	if os.Geteuid() != 0 || !core.ValidID(old) || !core.ValidID(current) || old == current {
		t.Fatal("actual private root and two distinct genuine sealed programs required")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !strings.Contains(string(status), "CapEff:\t0000000000000004\n") || !strings.Contains(string(status), "NoNewPrivs:\t1\n") {
		t.Fatal("readonly native inventory retained excess capabilities", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := VerifyApacheBodyBuild(current); err != nil {
		t.Fatal("current program has no genuine sealed authority", err)
	}
	if VerifyApacheBodyBuild(old) == nil {
		t.Fatal("historical program gained current activation authority")
	}
	oldRecord, err := readApacheBodyBuildRecord(old)
	if err != nil || apacheBodyRetainedRecordContract(oldRecord) != nil {
		t.Fatal("no exact genuine previous source/pin/ABI/build record", err)
	}
	before := map[string]string{}
	for _, id := range []string{old, current} {
		b, err := os.ReadFile(filepath.Join(apacheBodyJobs, id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		before[id] = string(b)
	}
	s := nativeWAFService()
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Error("readonly inventory attempted an external command")
		return "", errors.New("external execution forbidden in this read-only fixture")
	}
	m := http.NewServeMux()
	s.apacheBodyEngineRoutes(m)
	call := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		m.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal("readonly inventory failed", path, w.Code, w.Body.String())
		}
		return w
	}
	assertRow := func(out core.ApacheBodyEngineStatus, id string) {
		t.Helper()
		if out.JobID != id || !out.BuildOnly || out.HistoricalIntegrityVerified && out.IntegrityVerified {
			t.Fatal("inventory identity or current/historical authority mixed", out)
		}
		if id == current {
			if out.State != "ready" || out.Engine != apacheBodyEngineVersion || !out.IntegrityVerified || !out.ABIValidated || !out.HardeningValidated || !out.CompilerCollected || out.HistoricalIntegrityVerified || out.Error != "" {
				t.Fatal("current genuine readiness lost", out)
			}
			return
		}
		want := "retained_unsupported"
		if tampered {
			want = "needs_attention"
		}
		if id != old || out.State != want || out.Engine != "2.9.15-yz4" || out.Error == "" || out.HistoricalIntegrityVerified == tampered || out.IntegrityVerified || out.ABIValidated || out.HardeningValidated || out.CompilerCollected {
			t.Fatal("old program relabeled, trusted, enabled or tamper hidden", out)
		}
	}
	base := "/v1/software/apache-waf/"
	for _, id := range []string{old, current, old} {
		var out core.ApacheBodyEngineStatus
		w := call(base + "body-engine/jobs/" + id)
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		assertRow(out, id)
	}
	var inventory struct {
		Entries   []core.ApacheBodyEngineStatus `json:"entries"`
		BuildOnly bool                          `json:"build_only"`
		Explicit  bool                          `json:"activation_requires_explicit_site_policy"`
	}
	w := call(base + "body-engines")
	if json.Unmarshal(w.Body.Bytes(), &inventory) != nil || !inventory.BuildOnly || !inventory.Explicit || len(inventory.Entries) != 2 {
		t.Fatal("partial, duplicate or missing complete inventory", w.Body.String())
	}
	seen := map[string]bool{}
	for _, row := range inventory.Entries {
		if seen[row.JobID] {
			t.Fatal("duplicate inventory identity")
		}
		seen[row.JobID] = true
		assertRow(row, row.JobID)
	}
	if len(seen) != 2 || !seen[old] || !seen[current] {
		t.Fatal("original historical/current inventory omitted")
	}
	retainedSHA := map[string]string{}
	for id, original := range before {
		b, err := os.ReadFile(filepath.Join(apacheBodyJobs, id+".json"))
		if err != nil || string(b) != original {
			t.Fatal("readonly migration rewrote original record", id, err)
		}
		digest := sha256.Sum256(b)
		retainedSHA[id] = hex.EncodeToString(digest[:])
	}
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
	proof := map[string]any{"passed": true, "old_job": old, "current_job": current, "own_copy_tampered": tampered, "historical_only_no_activation": true, "all_stored_records_preserved": true, "record_sha256": retainedSHA, "inventory": inventory, "root_effective_capabilities": "0x4", "no_new_privileges": true, "actual_public_panel_api_or_ui": false}
	b, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/run/panel-apache-retained24alf/proof.json", b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("NATIVE_APACHE_RETAINED_READONLY_INVENTORY", old, current, tampered)
}
