//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

func lbHTTPPolicy() *core.LoadBalanceHTTPHealth {
	return &core.LoadBalanceHTTPHealth{Path: "/ready?check=1", Interval: 30, TimeoutMS: 500, ExpectedStatus: 200, BodyContains: "READY", Failures: 2, Successes: 2}
}
func lbHTTPFixture(t *testing.T, handler http.HandlerFunc) (*Service, core.AppModuleInput) {
	t.Helper()
	first := httptest.NewServer(handler)
	second := httptest.NewServer(handler)
	t.Cleanup(first.Close)
	t.Cleanup(second.Close)
	s := wafPolicyFixture(t)
	if e := moduleWrite(filepath.Join(s.moduleDir("load-balance"), "installed.json"), map[string]any{"id": "load-balance", "version": "1.4.1", "installed_at": core.Now(), "updated_at": core.Now(), "settings": map[string]any{}}); e != nil {
		t.Fatal(e)
	}
	in := lbFixtureInput()
	in.HealthCheck = lbHTTPPolicy()
	in.Nodes = []core.AppUpstream{{Address: strings.TrimPrefix(first.URL, "http://"), Weight: 1}, {Address: strings.TrimPrefix(second.URL, "http://"), Weight: 3}}
	lbSave(t, s, in)
	in.ExpectedRevision = 1
	return s, in
}
func lbHTTPCheck(t *testing.T, s *Service, in core.AppModuleInput) []map[string]any {
	t.Helper()
	out, e := s.checkLoadBalanceHTTP(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	return out.(map[string]any)["http_health"].([]map[string]any)
}
func TestLoadBalanceHTTPHysteresisPersistenceCadenceAndStale(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	var requests atomic.Int32
	s, in := lbHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != "lb-fixture.example.test" || r.URL.RequestURI() != "/ready?check=1" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("probe leaked headers or changed fixed host/path")
		}
		w.WriteHeader(int(status.Load()))
		w.Write([]byte("READY"))
	})
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	files := lbFiles(t, s, in.Domain)
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Error("observation invoked a system command")
		return "", errors.New("unexpected mutation")
	}
	if rows := lbHTTPCheck(t, s, in); rows[0]["state"] != "unknown" || rows[0]["successes"] != 1 {
		t.Fatal(rows)
	}
	if rows := lbHTTPCheck(t, s, in); rows[0]["state"] != "healthy" || rows[1]["state"] != "healthy" {
		t.Fatal(rows)
	}
	// A fresh service resumes only this exact configuration's persisted counters.
	fresh := New(s.Config)
	status.Store(503)
	if rows := lbHTTPCheck(t, fresh, in); rows[0]["state"] != "healthy" || rows[0]["last_success"] != false || rows[0]["http_status"] != 503 {
		t.Fatal(rows)
	}
	if rows := lbHTTPCheck(t, fresh, in); rows[0]["state"] != "unhealthy" || rows[0]["failures"] != 2 {
		t.Fatal(rows)
	}
	status.Store(200)
	if rows := lbHTTPCheck(t, fresh, in); rows[0]["state"] != "unhealthy" {
		t.Fatal(rows)
	}
	if rows := lbHTTPCheck(t, fresh, in); rows[0]["state"] != "healthy" {
		t.Fatal(rows)
	}
	v, _, e := fresh.readLoadBalanceEntry(in.Domain)
	if e != nil {
		t.Fatal(e)
	}
	state, e := fresh.readLoadBalanceHTTPState(v, time.Now().UTC())
	if e != nil || state.Sequence != 6 || len(state.Transitions) != 6 {
		t.Fatal(state, e)
	}
	before := requests.Load()
	if e = fresh.runLoadBalanceHTTPBatch(context.Background(), time.Now().UTC(), nil); e != nil || requests.Load() != before {
		t.Fatal("cadence not respected", e)
	}
	report, e := fresh.loadBalanceHealthReports([]loadBalanceEntry{v}, time.Now().Add(91*time.Second))
	if e != nil || report[0]["state"] != "stale" || report[0]["stale"] != true {
		t.Fatal(report, e)
	}
	lbAssertFiles(t, s, in.Domain, files)
}
func TestLoadBalanceHTTPBoundedFailuresAndNoRedirect(t *testing.T) {
	var followed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1); w.Write([]byte("READY")) }))
	defer target.Close()
	for _, tc := range []struct {
		name, reason string
		handler      http.HandlerFunc
	}{
		{"redirect", "status_mismatch", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }},
		{"service503", "status_mismatch", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503); w.Write([]byte("READY")) }},
		{"missing", "content_missing", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("NOT YET")) }},
		{"large", "body_too_large", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("READY" + strings.Repeat("x", lbHealthBodyLimit)))
		}},
		{"slow", "timeout", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }},
		{"incomplete", "body_incomplete", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "128")
			w.Write([]byte("READY"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, in := lbHTTPFixture(t, tc.handler)
			for _, row := range lbHTTPCheck(t, s, in) {
				if row["reason"] != tc.reason || row["last_success"] != false || row["state"] != "unknown" {
					t.Fatal(row)
				}
			}
		})
	}
	if followed.Load() != 0 {
		t.Fatal("redirect reached a different server")
	}
}
func TestLoadBalanceHTTPRevisionResetAndCorruptRecordPreservation(t *testing.T) {
	s, in := lbHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("READY")) })
	lbHTTPCheck(t, s, in)
	lbHTTPCheck(t, s, in)
	in.HealthCheck = &core.LoadBalanceHTTPHealth{Path: "/changed", Interval: 30, TimeoutMS: 500, ExpectedStatus: 200, BodyContains: "READY", Failures: 2, Successes: 2}
	lbSave(t, s, in)
	in.ExpectedRevision = 2
	v, _, e := s.readLoadBalanceEntry(in.Domain)
	if e != nil {
		t.Fatal(e)
	}
	if rows, e := s.loadBalanceHealthReports([]loadBalanceEntry{v}, time.Now()); e != nil || rows[0]["state"] != "unknown" {
		t.Fatal(rows, e)
	}
	if rows := lbHTTPCheck(t, s, in); rows[0]["state"] != "unknown" || rows[0]["successes"] != 1 {
		t.Fatal("old counters reused", rows)
	}
	path := s.loadBalanceHealthPath(in.Domain)
	b, _ := os.ReadFile(path)
	for _, edit := range []func(){
		func() { os.WriteFile(path, []byte("{broken"), 0600) },
		func() { os.Chmod(path, 0644) },
		func() { os.Link(path, path+".hardlink") },
		func() {
			var v map[string]any
			json.Unmarshal(b, &v)
			v["fingerprint"] = loadBalanceID(in.Domain) + ":2:" + strings.Repeat("0", 24)
			raw, _ := json.Marshal(v)
			os.WriteFile(path, raw, 0600)
		},
	} {
		edit()
		before, _ := os.ReadFile(path)
		if _, e := s.checkLoadBalanceHTTP(context.Background(), in); e == nil {
			t.Fatal("untrusted state overwritten")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("damaged state changed")
		}
		os.Remove(path + ".hardlink")
		os.Chmod(path, 0600)
		os.WriteFile(path, b, 0600)
	}
}
func TestLoadBalanceHTTPConcurrentPolicyChangeDropsAllResults(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	s, in := lbHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		w.Write([]byte("READY"))
	})
	finished := make(chan error, 1)
	go func() { _, e := s.checkLoadBalanceHTTP(context.Background(), in); finished <- e }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	changed := in
	changed.HealthCheck = nil
	lbSave(t, s, changed)
	close(release)
	if e := <-finished; e == nil || !strings.Contains(e.Error(), "旧结果") {
		t.Fatal("stale result committed", e)
	}
	if _, e := os.Lstat(s.loadBalanceHealthPath(in.Domain)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("old probe published a record", e)
	}
	changed.ExpectedRevision = 2
	if _, e := s.checkLoadBalanceHTTP(context.Background(), changed); e == nil {
		t.Fatal("disabled policy still checked")
	}
}
func TestLoadBalanceHTTPReplacedLeaseDoesNotPublish(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	s, in := lbHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		w.Write([]byte("READY"))
	})
	finished := make(chan error, 1)
	go func() { _, e := s.checkLoadBalanceHTTP(context.Background(), in); finished <- e }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	lock := filepath.Join(filepath.Dir(s.loadBalanceHealthPath(in.Domain)), "worker.lock")
	if e := atomicWrite(lock, nil, 0600); e != nil {
		close(release)
		t.Fatal(e)
	}
	close(release)
	if e := <-finished; e == nil || !strings.Contains(e.Error(), "锁身份") {
		t.Fatal("replaced lease committed", e)
	}
	if _, e := os.Lstat(s.loadBalanceHealthPath(in.Domain)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("unowned lease published state", e)
	}
}
func TestLoadBalanceHTTPLeaseAndUninstalledModuleNoSideEffects(t *testing.T) {
	var requests atomic.Int32
	s, in := lbHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write([]byte("READY")) })
	lease, e := s.loadBalanceHealthLease()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.checkLoadBalanceHTTP(context.Background(), in); !errors.Is(e, syscall.EWOULDBLOCK) {
		t.Fatal("concurrent lease not rejected", e)
	}
	if requests.Load() != 0 {
		t.Fatal("duplicate worker probed before lease")
	}
	lease.Close()
	manifest := filepath.Join(s.moduleDir("load-balance"), "installed.json")
	if e = os.Remove(manifest); e != nil {
		t.Fatal(e)
	}
	if e = s.runLoadBalanceHTTPBatch(context.Background(), time.Now(), nil); e != nil || requests.Load() != 0 {
		t.Fatal(e)
	}
	absent := wafPolicyFixture(t)
	if e = absent.runLoadBalanceHTTPBatch(context.Background(), time.Now(), nil); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(absent.Config.SecurityDir); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("absent module created root resources")
	}
}
func TestLoadBalanceHTTPBudgetAndLegacyFingerprint(t *testing.T) {
	in := lbFixtureInput()
	base := loadBalanceEntry{Format: 1, Revision: 1, Domain: in.Domain, Port: in.Port, Nodes: in.Nodes}
	// Adding an omitted optional policy must not alter old configuration
	// fingerprints, so historical committed transactions remain recoverable.
	b, _ := json.Marshal(base)
	if strings.Contains(string(b), "health_check") {
		t.Fatal("historical identity changed")
	}
	base.HealthCheck = lbHTTPPolicy()
	entries := []loadBalanceEntry{}
	for i := 0; i < 8; i++ {
		v := base
		v.Domain = "entry" + string(rune('a'+i)) + ".example.test"
		entries = append(entries, v)
	}
	next := base
	next.Domain = "new.example.test"
	if validateLoadBalanceHealthBudget(entries, next) == nil {
		t.Fatal("nine policies accepted")
	}
	next = entries[0]
	next.Revision++
	if e := validateLoadBalanceHealthBudget(entries, next); e != nil {
		t.Fatal("updating one policy counted twice", e)
	}
	next.Nodes = append(next.Nodes, next.Nodes...)
	for i := range entries {
		entries[i].Nodes = append(entries[i].Nodes, entries[i].Nodes...)
	}
	next.Nodes = append(next.Nodes, base.Nodes...)
	if validateLoadBalanceHealthBudget(entries, next) == nil {
		t.Fatal("node budget exceeded")
	}
	if _, _, e := loadBalanceNodeAddress("[fd00:ec2::254]:80"); e == nil {
		t.Fatal("IPv6 metadata target accepted")
	}
	if _, _, e := loadBalanceNodeAddress("100.100.100.200:80"); e == nil {
		t.Fatal("Alibaba metadata target accepted")
	}
}
func TestLoadBalanceHTTPActualModuleUpgradeManifestIsAccepted(t *testing.T) {
	s := wafPolicyFixture(t)
	path := filepath.Join(s.moduleDir("load-balance"), "installed.json")
	original := map[string]any{"id": "load-balance", "version": "1.3.1", "installed_at": core.Now(), "settings": map[string]any{}}
	if e := moduleWrite(path, original); e != nil {
		t.Fatal(e)
	}
	if s.loadBalanceHealthInstalled() {
		t.Fatal("old package enabled new automation")
	}
	if e := s.updateSoftware(context.Background(), "load-balance", core.SoftwareImplementationVersion("load-balance"), func(string) {}); e != nil {
		t.Fatal(e)
	}
	if !s.loadBalanceHealthInstalled() {
		t.Fatal("actual upgrade's updated_at rejected")
	}
	var upgraded map[string]any
	if e := moduleRead(path, &upgraded); e != nil {
		t.Fatal(e)
	}
	if upgraded["installed_at"] != original["installed_at"] || upgraded["updated_at"] == nil || upgraded["version"] != "1.8.1" {
		t.Fatal(upgraded)
	}
	upgraded["unexpected_field"] = true
	if e := moduleWrite(path, upgraded); e != nil {
		t.Fatal(e)
	}
	if s.loadBalanceHealthInstalled() {
		t.Fatal("unknown manifest field adopted")
	}
	delete(upgraded, "unexpected_field")
	upgraded["updated_at"] = "not-a-time"
	if e := moduleWrite(path, upgraded); e != nil {
		t.Fatal(e)
	}
	if s.loadBalanceHealthInstalled() {
		t.Fatal("malformed update time accepted")
	}
}
func TestLoadBalanceHTTPBackgroundWorkerRunsWithoutBrowserAndCancels(t *testing.T) {
	var requests atomic.Int32
	s, in := lbHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write([]byte("READY")) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.runLoadBalanceHealthWorker(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		if requests.Load() == 2 {
			v, _, e := s.readLoadBalanceEntry(in.Domain)
			if e != nil {
				t.Fatal(e)
			}
			// Network completion alone does not prove that private state persisted.
			if state, e := s.readLoadBalanceHTTPState(v, time.Now()); e == nil && state != nil {
				if state.Nodes[0].Successes != 1 || state.Nodes[0].State != "unknown" {
					t.Fatal(state)
				}
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("worker ignored cancellation")
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("background worker did not publish real HTTP results")
}
