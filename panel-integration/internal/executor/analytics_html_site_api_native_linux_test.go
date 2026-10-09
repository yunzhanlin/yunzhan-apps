//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Called only by the private canonical namespace fixture. Initial website
// creation remains fixture setup; all following analytics changes go through
// authenticated HTTP, the actual core worker, a real private Unix executor
// socket, production Apply, actual Nginx and production SQLite Finish.
func analyticsHTMLNativeAuthenticatedSiteAPI(t *testing.T, ctx context.Context, base string, s *Service, panel *core.Server, store *core.Store, site core.Site, endpoint string) {
	t.Helper()
	if site.PHPVersionID != "" || site.Settings.AnalyticsInjectHTML || site.Settings.AnalyticsEndpoint != "" || !strings.HasPrefix(base, "/tmp/analytics-native-") || core.ValidateAnalyticsEndpoint(endpoint) != nil {
		t.Fatal("authenticated static-site API fixture baseline invalid")
	}
	panel.Config.Listen = endpoint
	// install.sh / provision-app.sh create this root-owned 0600 lock before
	// starting the executor. This fresh private /var/lib has not run either
	// installer; reproduce that prerequisite without weakening runtimeUseLock.
	lock, err := os.OpenFile(filepath.Join(s.Config.StateDir, "runtime-lifecycle.lock"), os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal("private installer-equivalent runtime lock", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	marker, _ := json.Marshal(map[string]string{"id": site.ID, "domain": site.Domain})
	if err := atomicWrite(filepath.Join(s.Config.SitesDir, site.ID, ".panel-site.json"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	// These two initial sites were deliberately seeded by the containing
	// fixture, not created by this worker. Do not dispatch their setup jobs.
	if _, err := store.DB.Exec(`UPDATE jobs SET state='succeeded' WHERE kind='create_site' AND state='queued'`); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(s.Config.ConfDir, site.ID+".conf")
	baseline, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	contentPath := filepath.Join(s.Config.SitesDir, site.ID, "public/index.html")
	original, err := os.ReadFile(contentPath)
	if err != nil {
		t.Fatal(err)
	}
	public := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/collect/analytics/auto.js?site="+site.ID, nil)
		r.Host = site.Domain
		w := httptest.NewRecorder()
		panel.ServeHTTP(w, r)
		return w
	}
	var mu sync.Mutex
	preCommitChecks, foregroundCalls := 0, 0
	handler := s.Handler()
	socket := filepath.Join(base, "site-api-executor.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil || os.Chmod(socket, 0600) != nil {
		t.Fatal("private actual executor socket", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/app-modules/website-analytics" && r.URL.Path != "/v1/sites/preview" && r.URL.Path != "/v1/sites/apply" {
			// RunWorker also starts monitoring workers. A missing fixture
			// overview is a real recorded failure, never invented success, and
			// cannot dispatch any original service or other module mutation.
			respond(w, 503, map[string]string{"error": "private site API fixture excludes other executor capabilities"})
			return
		}
		mu.Lock()
		foregroundCalls++
		mu.Unlock()
		var apply core.ApplyRequest
		if r.URL.Path == "/v1/sites/apply" {
			data, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
			if err != nil || len(data) > 64<<10 || json.Unmarshal(data, &apply) != nil || apply.Site.ID != site.ID {
				respond(w, 500, map[string]string{"error": "private executor received an unexpected site mutation"})
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
		}
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, r)
		if r.URL.Path == "/v1/sites/apply" && result.Code == 200 {
			// Buffer the actual executor reply until the check finishes: the
			// core must not commit concurrently before this assertion.
			current, err := store.Site(site.ID)
			wantOld := !apply.Site.Settings.AnalyticsInjectHTML
			wantCode := 404
			if wantOld {
				wantCode = 200
			}
			if err != nil || current.Settings.AnalyticsInjectHTML != wantOld || public().Code != wantCode {
				respond(w, 500, map[string]string{"error": "private QA: applied database state or public script changed before Finish"})
				return
			}
			mu.Lock()
			preCommitChecks++
			mu.Unlock()
		}
		for k, values := range result.Header() {
			w.Header()[k] = values
		}
		w.WriteHeader(result.Code)
		_, _ = w.Write(result.Body.Bytes())
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	panel.Executor = core.NewExecutorClient(socket)
	t.Cleanup(panel.Executor.Client.CloseIdleConnections)
	request := func(method, path, body, csrf, key string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, panel.Config.Origin+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", panel.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		panel.ServeHTTP(w, r)
		return w
	}
	token, err := os.ReadFile(filepath.Join(panel.Config.DataDir, "bootstrap-token"))
	if err != nil || store.UserCount() != 0 {
		t.Fatal("private bootstrap identity", err)
	}
	data, _ := json.Marshal(map[string]string{"username": "qaadmin", "password": "qa-site-api-password-long", "token": strings.TrimSpace(string(token))})
	if w := request("POST", "/api/bootstrap", string(data), "", "", nil); w.Code != 201 {
		t.Fatal("actual private administrator bootstrap failed", w.Code)
	}
	login := request("POST", "/api/login", `{"username":"qaadmin","password":"qa-site-api-password-long"}`, "", "", nil)
	var auth struct {
		CSRF string `json:"csrf"`
	}
	if login.Code != 200 || json.Unmarshal(login.Body.Bytes(), &auth) != nil || auth.CSRF == "" || len(login.Result().Cookies()) != 1 {
		t.Fatal("actual private administrator login failed", login.Code)
	}
	cookie := login.Result().Cookies()[0]
	path := "/api/analytics/sites/" + site.ID + "/config"
	read := func() core.AnalyticsConfig {
		t.Helper()
		w := request("GET", path, "", auth.CSRF, "", cookie)
		var cfg core.AnalyticsConfig
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &cfg) != nil || cfg.AutoInjectHTML == nil {
			t.Fatal("actual applied configuration GET", w.Code)
		}
		return cfg
	}
	initial := read()
	if initial.Enabled || *initial.AutoInjectHTML || initial.ProxyEndpoint != "" || public().Code != 404 {
		t.Fatal("private baseline was already opted in")
	}
	enable := initial
	enable.Enabled = true
	yes := true
	enable.AutoInjectHTML = &yes
	data, _ = json.Marshal(enable)
	if w := request("POST", path, string(data), "", "site-api-enable", cookie); w.Code != 403 {
		t.Fatal("native workflow CSRF bypass", w.Code)
	}
	w := request("POST", path, string(data), auth.CSRF, "site-api-enable", cookie)
	var queued map[string]string
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &queued) != nil || !core.ValidID(queued["job_id"]) {
		t.Fatal("actual native API failed to queue", w.Code, w.Body.String())
	}
	before, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(before, baseline) || read().Enabled || public().Code != 404 {
		t.Fatal("queue wrote configuration or public metadata before the worker")
	}
	mu.Lock()
	countBefore := foregroundCalls
	mu.Unlock()
	if retry := request("POST", path, string(data), auth.CSRF, "site-api-enable", cookie); retry.Code != 202 || !strings.Contains(retry.Body.String(), queued["job_id"]) {
		t.Fatal("actual queued lost reply changed the task")
	}
	mu.Lock()
	unchanged := foregroundCalls == countBefore
	mu.Unlock()
	if !unchanged {
		t.Fatal("lost reply dispatched another preview or mutation")
	}
	workerCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { core.RunWorker(workerCtx, store, panel.Executor); close(done) }()
	defer func() {
		stop()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("private actual core worker did not stop")
		}
	}()
	wait := func(id string) {
		t.Helper()
		deadline := time.Now().Add(40 * time.Second)
		for time.Now().Before(deadline) && ctx.Err() == nil {
			job, err := store.Job(id)
			if err != nil {
				t.Fatal(err)
			}
			if job.State == "succeeded" {
				return
			}
			if job.State == "failed" || job.State == "needs_attention" {
				t.Fatal("actual native site API worker failed", job.State, job.Error)
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("actual native site API worker did not complete")
	}
	wait(queued["job_id"])
	active := read()
	if !active.Enabled || !*active.AutoInjectHTML || active.ProxyEndpoint != endpoint || active.Key != initial.Key || active.Revision != initial.Revision+1 || public().Code != 200 {
		t.Fatal("real worker failed to atomically commit the enabled collector")
	}
	current, err := store.Site(site.ID)
	if err != nil || current.SettingsRevision != site.SettingsRevision+1 {
		t.Fatal("actual website revision did not advance exactly once", err)
	}
	if retry := request("POST", path, string(data), auth.CSRF, "site-api-enable", cookie); retry.Code != 202 || !strings.Contains(retry.Body.String(), queued["job_id"]) {
		t.Fatal("actual committed lost reply changed the task")
	}
	active.Enabled = false
	no := false
	active.AutoInjectHTML = &no
	data, _ = json.Marshal(active)
	w = request("POST", path, string(data), auth.CSRF, "site-api-disable", cookie)
	queued = nil
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &queued) != nil || !core.ValidID(queued["job_id"]) {
		t.Fatal("actual disable API failed to queue", w.Code, w.Body.String())
	}
	wait(queued["job_id"])
	disabled := read()
	actual, err := os.ReadFile(configPath)
	content, e2 := os.ReadFile(contentPath)
	if err != nil || e2 != nil || !bytes.Equal(actual, baseline) || !bytes.Equal(content, original) || disabled.Enabled || *disabled.AutoInjectHTML || disabled.ProxyEndpoint != "" || disabled.Key != initial.Key || disabled.Revision != initial.Revision+2 || public().Code != 404 {
		t.Fatal("native disable failed to restore the exact config/template or public state", errors.Join(err, e2))
	}
	mu.Lock()
	checks := preCommitChecks
	mu.Unlock()
	if checks != 2 {
		t.Fatal("both actual executor replies were not checked before the core committed", checks)
	}
	t.Log("PASS authenticated private static-site HTTP/Unix executor/actual core worker/Nginx/SQLite enable-disable; precommit public-script boundary and immutable lost replies; exact config/template restoration; fixture initial sites, NOT signed release, PHP API or power-loss acceptance")
}
