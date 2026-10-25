//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestWAFEngineUnitStatesNeverInferSuccess(t *testing.T) {
	for _, tc := range []struct{ output, want string }{{"LoadState=loaded\nActiveState=activating\nResult=success\nExecMainStartTimestampMonotonic=10\n", "activating"}, {"LoadState=loaded\nActiveState=inactive\nResult=success\nExecMainStartTimestampMonotonic=0\n", "not-started"}, {"LoadState=loaded\nActiveState=inactive\nResult=success\nExecMainStartTimestampMonotonic=10\n", "inactive"}, {"LoadState=not-found\n", "missing"}, {"LoadState=loaded\nActiveState=failed\nResult=signal\nExecMainStartTimestampMonotonic=10\n", "failed"}} {
		s := testService(t, func(_ context.Context, name string, args ...string) (string, error) {
			if name != "/usr/bin/systemctl" || len(args) != 3 || args[2] != "panel-waf-engine-build@"+strings.Repeat("a", 32)+".service" {
				t.Fatal("not a fixed unit", name, args)
			}
			return tc.output, nil
		})
		state, _, err := s.wafEngineUnitState(context.Background(), strings.Repeat("a", 32))
		if err != nil || state != tc.want {
			t.Fatal(state, tc.want, err)
		}
	}
}

func TestWAFEngineBuildRejectsFakeEnvironmentAndArbitraryInput(t *testing.T) {
	s := wafPolicyFixture(t)
	for _, body := range []string{`{"job_id":"../bad"}`, `{"job_id":"` + core.ID() + `"}`, `{"job_id":"` + core.ID() + `","url":"https://example.com"}`, `{"job_id":"` + core.ID() + `","flags":["--injected"]}`} {
		r := httptest.NewRequest("POST", "/v1/software/nginx-waf/engine/build", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 400 && w.Code != 409 {
			t.Fatal("fake/arbitrary native build accepted", w.Code, w.Body.String())
		}
	}
}

func TestWAFEngineAPIActualProgramNativeQA(t *testing.T) {
	id := os.Getenv("PANEL_WAF_ENGINE_API_QA")
	if id == "" {
		t.Skip("explicit disposable QA gate required")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || os.Geteuid() != 0 || !core.ValidID(id) || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") {
		t.Fatal("refuse main or unknown environment")
	}
	s := nativeWAFService()
	if err := VerifyWAFEngineBuild(id); err != nil {
		t.Fatal(err)
	}
	record, err := os.ReadFile(wafEngineJobs + "/" + id + ".json")
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "POST", "POST"} {
		path, body := "/v1/software/nginx-waf/engine/jobs/"+id, ""
		if method == "POST" {
			path, body = "/v1/software/nginx-waf/engine/build", `{"job_id":"`+id+`"}`
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		var out core.WAFEngineStatus
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.State != "ready" || !out.IntegrityVerified || !out.ABIValidated || !out.BuildOnly || out.JobID != id {
			t.Fatal("actual program API verification/replay failed", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/nginx-waf/engines", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), id) {
		t.Fatal(w.Code, w.Body.String())
	}
	actual, err := os.ReadFile(wafEngineJobs + "/" + id + ".json")
	if err != nil || string(actual) != string(record) {
		t.Fatal("immutable engine record changed")
	}
}
