package core

import (
	"encoding/json"
	"local/panel/internal/appcatalog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestRegistryRequestCloseFencesAllLateModuleRuntimeComposeAndUpdateQueues(t *testing.T) {
	s := testStore(t)
	actor := ID()
	item := appcatalog.CatalogItem{ID: "load-balance", Version: SoftwareImplementationVersion("load-balance"), SHA256: strings.Repeat("a", 64), Provider: "panel-module", Target: "load-balance"}
	in := registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}
	closed := registryRequestCloseInput{Action: "install", ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}
	out, err := s.closeRegistryRequest(item.ID, actor, "closed", closed)
	if err != nil || out.State != "closed_without_submission" || out.JobID != "" || !out.StateKnown {
		t.Fatal(out, err)
	}
	before := installReplayCounts(t, s)
	for i := 0; i < 3; i++ {
		if _, err = s.queueSoftwareActionBound(item.Target, "install", nil, "", "closed", "admin", s.bindRegistryInstall(item, item.Target, "closed", actor, in)); err == nil {
			t.Fatal("late install queued")
		}
		if _, err = s.queueSoftwareActionBound(item.Target, "update", nil, item.Version, "closed", "admin", s.bindRegistryUpdate(item, item.Target, "closed", actor)); err == nil {
			t.Fatal("late update queued")
		}
		if w := installReplayHTTP(&Server{Store: s}, item.ID, "closed", identity{ID: actor}, in); w.Code != 409 {
			t.Fatal("closed replay fetched catalog", w.Code)
		}
	}
	compose := appcatalog.CatalogItem{ID: "memcached", Version: "1.2.0", SHA256: item.SHA256, Provider: "compose", Target: "memcached-cache"}
	yaml, err := dockerTemplate(compose.Target, 21211)
	if err != nil {
		t.Fatal(err)
	}
	op := DockerProjectRequest{JobID: ID(), ProjectID: ID(), Action: "create", Name: "late-own-qa", Compose: yaml, TemplateID: compose.Target}
	if _, fresh, err := s.reserveRegistryCompose(compose, "closed", identity{ID: actor}, registryInstallInput{ExpectedVersion: compose.Version, ExpectedSHA256: compose.SHA256}, op); err == nil || fresh {
		t.Fatal("late compose reserved")
	}
	if !reflect.DeepEqual(before, installReplayCounts(t, s)) {
		t.Fatal("late attempts changed jobs, audit or receipts")
	}
	for _, change := range []struct {
		app, who string
		input    registryRequestCloseInput
	}{{item.ID, ID(), closed}, {"nginx", actor, closed}, {item.ID, actor, registryRequestCloseInput{Action: "update", ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}}} {
		if _, err := s.closeRegistryRequest(change.app, change.who, "closed", change.input); err == nil {
			t.Fatal("closure identity changed")
		}
	}
	if again, err := s.closeRegistryRequest(item.ID, actor, "closed", closed); err != nil || again != out {
		t.Fatal("closure replay", again, err)
	}
	if w := registryStatusHTTP(&Server{Store: s}, item.ID, "closed", actor); w.Code != 200 || !strings.Contains(w.Body.String(), "closed_without_submission") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestRegistryRequestCloseNeverCancelsBoundTerminalOrUnknownJobs(t *testing.T) {
	for _, state := range []string{"queued", "running", "succeeded", "failed", "needs_attention"} {
		s := testStore(t)
		actor := ID()
		item, _, job := installReplayFixture(t, s, "bound", actor)
		if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state=? WHERE id=?`, state, job); err != nil {
			t.Fatal(err)
		}
		before := installReplayCounts(t, s)
		if _, err := s.closeRegistryRequest(item.ID, actor, "bound", registryRequestCloseInput{Action: "install", ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}); err == nil {
			t.Fatal("bound job closed", state)
		}
		if !reflect.DeepEqual(before, installReplayCounts(t, s)) {
			t.Fatal("bound job changed")
		}
		var n int
		if err := s.DB.QueryRow(`SELECT count(*) FROM app_registry_request_closures`).Scan(&n); err != nil || n != 0 {
			t.Fatal(n, err)
		}
	}
}

func TestRegistryRequestCloseQueueRaceHasOnlyOneCommittedOutcome(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		for i := 0; i < 24; i++ {
			s := testStore(t)
			actor := ID()
			item := appcatalog.CatalogItem{ID: "load-balance", Target: "load-balance", Provider: "panel-module", Version: SoftwareImplementationVersion("load-balance"), SHA256: strings.Repeat("a", 64)}
			key := ID()
			start := make(chan struct{})
			var wg sync.WaitGroup
			var closeErr, queueErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				_, closeErr = s.closeRegistryRequest(item.ID, actor, key, registryRequestCloseInput{Action: action, ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256})
			}()
			go func() {
				defer wg.Done()
				<-start
				if action == "install" {
					_, queueErr = s.queueSoftwareActionBound(item.Target, action, nil, "", key, "admin", s.bindRegistryInstall(item, item.Target, key, actor, registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}))
				} else {
					_, queueErr = s.queueSoftwareActionBound(item.Target, action, nil, item.Version, key, "admin", s.bindRegistryUpdate(item, item.Target, key, actor))
				}
			}()
			close(start)
			wg.Wait()
			if (closeErr == nil) == (queueErr == nil) {
				t.Fatal("two or zero winners", action, closeErr, queueErr)
			}
			var jobs, closures int
			if err := s.DB.QueryRow(`SELECT (SELECT count(*) FROM runtime_jobs),(SELECT count(*) FROM app_registry_request_closures)`).Scan(&jobs, &closures); err != nil || jobs+closures != 1 {
				t.Fatal(jobs, closures, err)
			}
		}
	}
}

func TestRegistryRequestStatusAndClosureHTTPAccountMenuAndCSRF(t *testing.T) {
	s := testStore(t)
	owner := accessUser(t, s, "request-owner", "admin", nil)
	other := accessUser(t, s, "request-other", "admin", nil)
	viewer := accessUser(t, s, "request-viewer", "viewer", nil)
	restricted := accessUser(t, s, "request-restricted", "admin", []string{"files"})
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	item, _, job := installReplayFixture(t, s, "http-bound", owner.ID)
	a.AppCatalog, a.Executor = nil, nil
	call := func(method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	path := "/api/app-registry/" + item.ID + "/requests/http-bound"
	if w := call("GET", path, "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, test := range []struct {
		name string
		want int
	}{{owner.Username, 200}, {other.Username, 409}, {viewer.Username, 403}, {restricted.Username, 403}} {
		w := call("POST", "/api/login", `{"username":"`+test.name+`","password":"access-test-password-long"}`, "", nil)
		var session accountSession
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &session) != nil {
			t.Fatal("login", w.Code)
		}
		cookie := w.Result().Cookies()[0]
		if w := call("GET", path, "", "", cookie); w.Code != test.want || (test.want != 200 && strings.Contains(w.Body.String(), job)) {
			t.Fatal(test.name, w.Code, w.Body.String())
		}
		body := `{"action":"install","expected_version":"` + item.Version + `","expected_sha256":"` + item.SHA256 + `"}`
		if w := call("POST", path+"/close", body, "wrong", cookie); w.Code != 403 {
			t.Fatal("CSRF bypass", w.Code)
		}
		fresh := "/api/app-registry/" + item.ID + "/requests/" + ID() + "/close"
		want := 403
		if test.name == owner.Username || test.name == other.Username {
			want = 200
		}
		if w := call("POST", fresh, body, session.CSRF, cookie); w.Code != want {
			t.Fatal("closure role", test.name, w.Code, w.Body.String())
		}
		if w := call("GET", "/api/me", "", "", cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"user_id":`) {
			t.Fatal("stable account identity", w.Code)
		}
	}
}
