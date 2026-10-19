//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

// Genuine sealed-byte API fixture. It proves readonly inventory and ready
// replay, not systemd dispatch, an installed application, or site activation.
func TestApacheBodyNativeReadOnlyAPIReadyReplayClosedInputs(t *testing.T) {
	if os.Getenv("PANEL_QA_APACHE_BODY_API") != "1" {
		t.Skip("explicit private sealed Apache API fixture required")
	}
	id := os.Getenv("PANEL_QA_APACHE_BODY_WORKER_JOB")
	if os.Geteuid() != 0 || !core.ValidID(id) {
		t.Fatal("private root-backed sealed build required")
	}
	if err := VerifyApacheBodyBuild(id); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(apacheBodyJobs, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	s := nativeWAFService()
	s.Config.Run = func(ctx context.Context, program string, args ...string) (string, error) {
		t.Errorf("readonly/ready replay attempted an external command: %s %v", program, args)
		return "", errors.New("external mutation is not allowed by this readonly fixture")
	}
	m := http.NewServeMux()
	s.apacheBodyEngineRoutes(m)
	call := func(method, path, body string, want int) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		m.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: got %d want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		return w
	}
	base := "/v1/software/apache-waf/"
	assertReady := func(w *httptest.ResponseRecorder) {
		var got core.ApacheBodyEngineStatus
		if json.Unmarshal(w.Body.Bytes(), &got) != nil || got.JobID != id || got.State != "ready" || !got.BuildOnly || !got.IntegrityVerified || !got.ABIValidated || !got.HardeningValidated || !got.CompilerCollected || got.Error != "" || got.Engine != apacheBodyEngineVersion || got.YAJL != apacheBodyYAJLVersion || got.ApacheVersion != "2.4.68" {
			t.Fatal("ready API lacks all independently verified program facts", w.Body.String())
		}
	}
	assertReady(call("GET", base+"body-engine/jobs/"+id, "", 200))
	var inventory struct {
		Entries   []core.ApacheBodyEngineStatus `json:"entries"`
		BuildOnly bool                          `json:"build_only"`
		Explicit  bool                          `json:"activation_requires_explicit_site_policy"`
	}
	w := call("GET", base+"body-engines", "", 200)
	if json.Unmarshal(w.Body.Bytes(), &inventory) != nil || !inventory.BuildOnly || !inventory.Explicit || len(inventory.Entries) != 2 {
		t.Fatal("complete private namespace inventory", w.Body.String())
	}
	found := 0
	for _, row := range inventory.Entries {
		if row.JobID == id && row.State == "ready" {
			found++
		}
	}
	if found != 1 {
		t.Fatal("ready row missing or duplicated")
	}
	call("GET", base+"body-engine/jobs/"+core.ID(), "", 409)
	call("GET", base+"body-engine/jobs/not-a-managed-id", "", 409)
	for _, body := range []string{`{"job_id":"` + id + `","url":"https://example.com/source"}`, `{"job_id":"` + id + `","flags":["shell"]}`, `{} {}`} {
		call("POST", base+"body-engine/build", body, 400)
	}
	for _, body := range []string{`{"unit":"nginx.service"}`, `{"signal":"KILL"}`, `{} {}`} {
		call("POST", base+"body-engine/jobs/"+id+"/cancel", body, 400)
	}
	// Both requests attach to completed proof. They never rewrite a receipt,
	// create a cancellation barrier or start/stop an existing web service.
	assertReady(call("POST", base+"body-engine/build", `{"job_id":"`+id+`"}`, 200))
	assertReady(call("POST", base+"body-engine/jobs/"+id+"/cancel", `{}`, 200))
	after, err := os.ReadFile(filepath.Join(apacheBodyJobs, id+".json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("readonly inspection or ready replay rewrote proof", err)
	}
	if _, err := os.Lstat(filepath.Join(apacheBodyCancellations, id+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("completed ready task gained a cancellation barrier", err)
	}
	t.Log("NATIVE_APACHE_READONLY_API_READY_REPLAY", id)
}
