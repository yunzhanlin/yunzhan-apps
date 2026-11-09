package core

import (
	"encoding/json"
	"io"
	"local/panel/internal/appcatalog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func registryStatusHTTP(a *Server, app, key, actor string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/api/app-registry/"+app+"/requests/"+key, nil)
	r.SetPathValue("id", app)
	r.SetPathValue("key", key)
	w := httptest.NewRecorder()
	a.registryRequestStatus(w, r, identity{ID: actor})
	return w
}

func TestRegistryRequestStatusReadOnlyRetainedTerminalIdentity(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		for _, state := range []string{"queued", "running", "succeeded", "failed", "needs_attention"} {
			t.Run(action+"/"+state, func(t *testing.T) {
				s := testStore(t)
				actor := ID()
				var item appcatalog.CatalogItem
				var job string
				if action == "install" {
					item, _, job = installReplayFixture(t, s, "original", actor)
				} else {
					item, job = registryReplayFixture(t, s, "original", actor)
				}
				if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state=?,error='private-job-error-password' WHERE id=?`, state, job); err != nil {
					t.Fatal(err)
				}
				if _, err := s.DB.Exec(`DELETE FROM app_registry_pending WHERE job_id=?`, job); err != nil {
					t.Fatal(err)
				}
				before := installReplayCounts(t, s)
				w := registryStatusHTTP(&Server{Store: s}, item.ID, "original", actor)
				var out registryRequestOutcome
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Action != action || out.JobID != job || out.State != state || !out.StateKnown || out.Version != item.Version || out.SHA256 != item.SHA256 || strings.Contains(w.Body.String(), "private-job-error-password") || !reflect.DeepEqual(before, installReplayCounts(t, s)) {
					t.Fatal(w.Code, w.Body.String())
				}
				for _, changed := range []struct{ app, actor string }{{item.ID, ID()}, {"nginx", actor}} {
					if w := registryStatusHTTP(&Server{Store: s}, changed.app, "original", changed.actor); w.Code != 409 || strings.Contains(w.Body.String(), job) {
						t.Fatal("foreign identity leak", w.Code, w.Body.String())
					}
				}
			})
		}
	}
}

func TestRegistryRequestStatusNeverAdoptsMissingCorruptOrUnboundJobs(t *testing.T) {
	for _, mutation := range []string{`UPDATE runtime_jobs SET kind='software_uninstall'`, `UPDATE runtime_jobs SET payload='{}'`, `UPDATE runtime_jobs SET idempotency_key='other'`, `UPDATE runtime_jobs SET state='healthy'`, `DELETE FROM runtime_jobs`, `UPDATE app_registry_install_requests SET request_sha256=upper(request_sha256)`} {
		s := testStore(t)
		actor := ID()
		item, _, _ := installReplayFixture(t, s, "original", actor)
		if mutation == `DELETE FROM runtime_jobs` {
			if _, err := s.DB.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.DB.Exec(mutation); err != nil {
			t.Fatal(err)
		}
		if w := registryStatusHTTP(&Server{Store: s}, item.ID, "original", actor); w.Code != 409 {
			t.Fatal("adopted corrupt request", mutation, w.Code, w.Body.String())
		}
	}
	s := testStore(t)
	if w := registryStatusHTTP(&Server{Store: s}, "load-balance", "unbound", ID()); w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestRegistryRequestStatusComposeOnlyFixedReadAndUnknownIsNotSuccess(t *testing.T) {
	s := testStore(t)
	actor := ID()
	item := appcatalog.CatalogItem{ID: "memcached", Target: "memcached-cache", Provider: "compose", Version: "1.2.0", SHA256: strings.Repeat("a", 64)}
	in := registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256, HostPort: 21211}
	compose, err := dockerTemplate(item.Target, in.HostPort)
	if err != nil {
		t.Fatal(err)
	}
	op := DockerProjectRequest{JobID: ID(), ProjectID: ID(), Action: "create", Name: "own-qa", Compose: compose, TemplateID: item.Target}
	if _, fresh, err := s.reserveRegistryCompose(item, "compose-original", identity{ID: actor, Username: "admin"}, in, op); err != nil || !fresh {
		t.Fatal(err)
	}
	a := &Server{Store: s}
	before := installReplayCounts(t, s)
	for _, mode := range []string{"offline", "good", "foreign-job", "foreign-project", "foreign-kind", "unknown-state"} {
		calls := 0
		if mode != "offline" {
			a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/v1/docker/jobs/"+op.JobID {
					t.Fatal("mutation or wrong identity", r.Method, r.URL.Path)
				}
				result := DockerJobResult{JobID: op.JobID, ProjectID: op.ProjectID, Kind: "compose", State: "succeeded", Error: "secret-password"}
				switch mode {
				case "foreign-job":
					result.JobID = ID()
				case "foreign-project":
					result.ProjectID = ID()
				case "foreign-kind":
					result.Kind = "prune"
				case "unknown-state":
					result.State = "healthy"
				}
				raw, _ := json.Marshal(result)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
		} else {
			a.Executor = nil
		}
		w := registryStatusHTTP(a, item.ID, "compose-original", actor)
		var out registryRequestOutcome
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.StateKnown != (mode == "good") || (mode != "good" && out.State != "unknown") || strings.Contains(w.Body.String(), "secret-password") || !reflect.DeepEqual(before, installReplayCounts(t, s)) {
			t.Fatal(mode, w.Code, w.Body.String())
		}
		if mode != "offline" && calls != 1 {
			t.Fatal(calls)
		}
	}
}
