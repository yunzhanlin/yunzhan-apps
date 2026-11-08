package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"local/panel/internal/diskjob"
	"local/panel/internal/diskusage"
)

func hostObservationFixture(t *testing.T, s *Store, actor string) (HostDiskJob, diskjob.Observation) {
	t.Helper()
	j, _, err := s.QueueHostDisk(context.Background(), hostSelectionFixture(), ID(), actor)
	if err != nil {
		t.Fatal(err)
	}
	j, only, err := s.HostDiskDispatchBoundary(context.Background(), j.ID, actor)
	if err != nil || only {
		t.Fatal(err)
	}
	unit, _ := diskjob.UnitName(j.ID, false)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	started := diskjob.Started{Format: 1, JobID: j.ID, RequestSHA: diskjob.RequestSHA(j.Request), ExecutorSHA: strings.Repeat("4", 64), PID: "4321", StartTicks: "5678", At: now, Policy: diskjob.Policy{Host: diskjob.Host{BootID: j.Request.Selection.BootID, NamespaceID: j.Request.Selection.NamespaceID}, Cgroup: "/system.slice/" + unit, Threads: 4, Capabilities: "CAP_DAC_READ_SEARCH", NoNewPrivileges: true, CPUQuota: "20000 100000", MemoryMax: "536870912", MemoryHigh: "402653184", MemorySwapMax: "0", TasksMax: "32", IOWeight: "default 10", FileDescriptorsMax: 2048, FileBytesMax: 1 << 30}}
	r := diskjob.Result{Format: 1, Request: j.Request, RequestSHA: started.RequestSHA, Started: started, State: "canceled", ErrorCode: "canceled", At: now, Capacity: diskusage.Capacity{State: "unavailable", InodeState: "unavailable", MayOverlap: true}}
	o := diskjob.Observation{Format: 1, Request: j.Request, State: "settling", Process: "alive", Scope: "busy", Started: &started, Result: &r, ResultSHA: diskjob.ResultSHA(r)}
	if err := diskjob.ValidateObservation(o, j.Request); err != nil {
		t.Fatal(err)
	}
	return j, o
}

func TestHostDiskObservationCancelIntentDoesNotReleaseSlotAndTerminalIsImmutable(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	u := accessUser(t, s, "observe-owner", "admin", nil)
	j, o := hostObservationFixture(t, s, u.ID)
	if err := s.CheckHostDiskUpgrade(ctx); err == nil {
		t.Fatal("queued/dispatching source intent ignored by upgrade")
	}
	if _, err := s.RequestHostDiskCancel(ctx, j.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.ObserveHostDisk(ctx, o, u.ID)
	if err != nil || got.State != "cancel_requested" {
		t.Fatal("saved result released live original", got.State, err)
	}
	if _, _, err := s.QueueHostDisk(ctx, hostSelectionFixture(), ID(), u.ID); err == nil {
		t.Fatal("cancel intent released active slot")
	}
	if err := s.CheckHostDiskUpgrade(ctx); err == nil {
		t.Fatal("cancel-requested job allowed upgrade")
	}
	o.Process = "gone"
	o.Scope = "empty"
	o.RunLeaseFree = true
	o.TerminalVerified = true
	o.State = "canceled"
	got, err = s.ObserveHostDisk(ctx, o, u.ID)
	if err != nil || got.State != "canceled" {
		t.Fatal(got.State, err)
	}
	for range 3 {
		if _, err := s.ObserveHostDisk(ctx, o, u.ID); err != nil {
			t.Fatal("terminal GET reconciliation was not idempotent", err)
		}
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='disk.host.result' AND target=?", j.ID).Scan(&count)
	if count != 1 {
		t.Fatal("duplicate terminal audit", count)
	}
	if err := s.CheckHostDiskUpgrade(ctx); err != nil {
		t.Fatal(err)
	}
	stored, found, err := s.HostDiskResultForActor(ctx, j.ID, u.ID)
	if err != nil || !found || diskjob.ResultSHA(stored) != o.ResultSHA {
		t.Fatal(found, err)
	}
	changed := *o.Result
	changed.At = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
	o.Result = &changed
	o.ResultSHA = diskjob.ResultSHA(changed)
	if _, err := s.ObserveHostDisk(ctx, o, u.ID); err == nil {
		t.Fatal("terminal original was replaced by new valid receipt")
	}
	if _, _, err := s.QueueHostDisk(ctx, hostSelectionFixture(), ID(), u.ID); err != nil {
		t.Fatal("verified terminal never released slot", err)
	}
}

func TestHostDiskObservationRevocationCrossActorAndCorruptionRefuse(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	u := accessUser(t, s, "observe-full", "admin", nil)
	other := accessUser(t, s, "observe-other", "admin", nil)
	j, o := hostObservationFixture(t, s, u.ID)
	if _, err := s.ObserveHostDisk(ctx, o, other.ID); err == nil {
		t.Fatal("other full administrator adopted observation")
	}
	if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'[]',2)", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObserveHostDisk(ctx, o, u.ID); err == nil {
		t.Fatal("revoked owner observed private report")
	}
	if err := s.ValidateHostDiskObservation(ctx, j.Request); err == nil {
		t.Fatal("Root observer expanded revoked permissions")
	}
	if _, err := s.DB.Exec("UPDATE app_user_menus SET menu_ids='null',revision=3 WHERE user_id=?", u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateHostDiskObservation(ctx, j.Request); err != nil {
		t.Fatal("restored full original owner cannot observe old history", err)
	}
	if err := s.ValidateHostDiskNative(ctx, j.Request); err == nil {
		t.Fatal("observation restored stale worker authorization revision")
	}
	o.Process = "gone"
	o.Scope = "empty"
	o.RunLeaseFree = true
	o.TerminalVerified = true
	o.State = "canceled"
	if _, err := s.ObserveHostDisk(ctx, o, u.ID); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(o.Result)
	if _, err := s.DB.Exec("UPDATE disk_host_job_results SET result=?", strings.Replace(string(raw), `"no_new_privileges":true`, `"no_new_privileges":null`, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HostDiskForActor(ctx, j.ID, u.ID); err == nil {
		t.Fatal("corrupt typed terminal record accepted")
	}
	if err := s.CheckHostDiskUpgrade(ctx); err == nil {
		t.Fatal("corrupt terminal proof allowed upgrade")
	}
}

func TestHostDiskObservationUncertainKeepsOriginalWorkerAuthorityAndNoRedispatch(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	u := accessUser(t, s, "observe-unknown", "admin", nil)
	j, o := hostObservationFixture(t, s, u.ID)
	o.Result = nil
	o.ResultSHA = ""
	o.State = "uncertain"
	o.Process = "unknown"
	o.Scope = "unknown"
	got, err := s.ObserveHostDisk(ctx, o, u.ID)
	if err != nil || got.State != "uncertain" {
		t.Fatal(got.State, err)
	}
	if err := s.ValidateHostDiskNative(ctx, j.Request); err != nil {
		t.Fatal("lost observation revoked same authorized original worker", err)
	}
	if _, only, err := s.HostDiskDispatchBoundary(ctx, j.ID, u.ID); err != nil || !only {
		t.Fatal("uncertain original redispatched", only, err)
	}
	if err := s.CheckHostDiskUpgrade(ctx); err == nil {
		t.Fatal("uncertain original allowed upgrade")
	}
}

func TestHostDiskObservationHTTPChecksOwnerBeforeExecutorAndOnlyObservesOriginal(t *testing.T) {
	s := testStore(t)
	u := accessUser(t, s, "http-disk-owner", "admin", nil)
	other := accessUser(t, s, "http-disk-other", "admin", nil)
	limited := accessUser(t, s, "http-disk-limited", "admin", []string{"system-tools", "runtimes"})
	j, o := hostObservationFixture(t, s, u.ID)
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/v1/disk-host-jobs/observe" {
			t.Fatal("GET redispatched or reached another operation", r.Method, r.URL.Path)
		}
		var in diskjob.Request
		if json.NewDecoder(r.Body).Decode(&in) != nil || in != j.Request {
			t.Fatal("observation lost original private actor/intent")
		}
		raw, _ := json.Marshal(o)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
	request := func(method, url, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, url, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := func(name string) *http.Cookie {
		w := request("POST", "/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, nil)
		if w.Code != 200 {
			t.Fatal("fixture login", w.Code, w.Body.String())
		}
		return w.Result().Cookies()[0]
	}
	ownerCookie, otherCookie, limitedCookie := login(u.Username), login(other.Username), login(limited.Username)
	url := "/api/software/disk-analysis/host/jobs/" + j.ID
	for _, cookie := range []*http.Cookie{otherCookie, limitedCookie} {
		if w := request("GET", url, "", cookie); w.Code != 403 || calls != 0 {
			t.Fatal("nonowner/limited role reached Root host report", w.Code, calls)
		}
	}
	if w := request("GET", url, `{"state":"complete","terminal_verified":true}`, ownerCookie); w.Code != 200 || calls != 1 {
		t.Fatal("original owner cannot observe", w.Code, w.Body.String(), calls)
	}
	got, err := s.HostDiskForActor(context.Background(), j.ID, u.ID)
	if err != nil || got.State != "uncertain" {
		t.Fatal("public fake GET body completed native task", got.State, err)
	}
	// A false Root completion is rejected even on the trusted socket.
	o.State = "canceled"
	o.TerminalVerified = true
	if w := request("GET", url, "", ownerCookie); w.Code != 409 || calls != 2 {
		t.Fatal("live worker became terminal", w.Code, calls)
	}
	o.Process = "gone"
	o.Scope = "empty"
	o.RunLeaseFree = true
	if w := request("GET", url, "", ownerCookie); w.Code != 200 || calls != 3 {
		t.Fatal("verified original exit refused", w.Code, w.Body.String(), calls)
	}
	for range 3 {
		if w := request("GET", url, "", ownerCookie); w.Code != 200 || calls != 3 {
			t.Fatal("cached original terminal was redispatched/requeried", w.Code, calls)
		}
	}
	if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'[]',2)", u.ID); err != nil {
		t.Fatal(err)
	}
	if w := request("GET", url, "", ownerCookie); w.Code != 403 || calls != 3 {
		t.Fatal("cached report leaked after revocation", w.Code, calls)
	}
}
