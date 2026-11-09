package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"local/panel/internal/diskjob"
	"local/panel/internal/diskusage"
)

func diskHostHTTPStateFixture(t *testing.T) (diskjob.HostState, diskjob.Selection) {
	t.Helper()
	in := hostSelectionFixture()
	mounts, err := diskusage.ParseMountInfo(strings.NewReader("31 1 8:1 / / rw - ext4 /dev/source-fixture rw\n"))
	if err != nil {
		t.Fatal(err)
	}
	in.MountID = mounts.Mounts[0].ID
	in.MountSHA = mounts.Mounts[0].BindingSHA
	state := diskjob.HostState{Format: 1, Installed: true, AppVersion: diskjob.HostAppVersion, InstallationID: in.InstallationID, AppSHA: in.AppSHA, Inventory: &diskjob.Inventory{Host: diskjob.Host{BootID: in.BootID, NamespaceID: in.NamespaceID}, Mounts: mounts}}
	if diskjob.ValidateHostState(state) != nil {
		t.Fatal("invalid original source transport fixture")
	}
	return state, in
}

func diskHostHTTPServer(t *testing.T, s *Store) (*Server, func(string, string, string, *http.Cookie, string) *httptest.ResponseRecorder, func(string) (*http.Cookie, string)) {
	t.Helper()
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, url, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, url, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", strings.Repeat("a", 32))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := func(name string) (*http.Cookie, string) {
		w := request("POST", "/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, nil, "")
		if w.Code != 200 {
			t.Fatal("source login fixture", w.Code, w.Body.String())
		}
		var session accountSession
		if json.Unmarshal(w.Body.Bytes(), &session) != nil {
			t.Fatal("source login fixture response")
		}
		return w.Result().Cookies()[0], session.CSRF
	}
	return a, request, login
}

func TestHostDiskHTTPDispatchLostReplyIsSingleIntentAndCancelIsNotCompletion(t *testing.T) {
	s := testStore(t)
	owner := accessUser(t, s, "dispatch-owner", "admin", nil)
	other := accessUser(t, s, "dispatch-other", "admin", nil)
	limited := accessUser(t, s, "dispatch-limited", "admin", []string{"runtimes", "system-tools"})
	a, request, login := diskHostHTTPServer(t, s)
	state, selection := diskHostHTTPStateFixture(t)
	counts := map[string]int{}
	var original diskjob.Request
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		counts[r.URL.Path]++
		if r.Method != "POST" {
			t.Fatal("unexpected native operation")
		}
		var value any
		switch r.URL.Path {
		case "/v1/disk-host-jobs/inventory":
			var in diskjob.InventoryRequest
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.ActorID != owner.ID || in.AccessRevision != "1" {
				t.Fatal("inventory actor/revision not server-bound")
			}
			value = state
		case "/v1/disk-host-jobs/dispatch":
			if json.NewDecoder(r.Body).Decode(&original) != nil || original.ActorID != owner.ID || original.Selection != selection {
				t.Fatal("dispatch original request changed")
			}
			return nil, errors.New("owned source fixture lost reply")
		case "/v1/disk-host-jobs/cancel":
			var in diskjob.Request
			if json.NewDecoder(r.Body).Decode(&in) != nil || in != original {
				t.Fatal("cancel changed original native identity")
			}
			value = diskjob.CancelAck{Format: 1, JobID: in.JobID, RequestSHA: diskjob.RequestSHA(in), SignalRequested: true}
		default:
			t.Fatal("reached arbitrary native path", r.URL.Path)
		}
		raw, _ := json.Marshal(value)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
	oc, csrf := login(owner.Username)
	otherCookie, otherCSRF := login(other.Username)
	lc, lcsrf := login(limited.Username)
	raw, _ := json.Marshal(selection)
	url := "/api/software/disk-analysis/host/jobs"
	if w := request("POST", url, string(raw), lc, lcsrf); w.Code != 403 || len(counts) != 0 {
		t.Fatal("limited role reached host collector", w.Code, counts)
	}
	if w := request("POST", url, string(raw), oc, ""); w.Code != 403 || len(counts) != 0 {
		t.Fatal("missing CSRF reached native dispatcher", w.Code, counts)
	}
	w := request("POST", url, string(raw), oc, csrf)
	if w.Code != 202 || !strings.Contains(w.Body.String(), `"dispatch_uncertain":true`) || counts["/v1/disk-host-jobs/dispatch"] != 1 {
		t.Fatal(w.Code, w.Body.String(), counts)
	}
	for range 3 {
		w = request("POST", url, string(raw), oc, csrf)
		if w.Code != 202 || !strings.Contains(w.Body.String(), `"dispatch_uncertain":true`) {
			t.Fatal("replay denied/false certainty", w.Code, w.Body.String())
		}
	}
	if counts["/v1/disk-host-jobs/inventory"] != 1 || counts["/v1/disk-host-jobs/dispatch"] != 1 {
		t.Fatal("lost reply re-enumerated/reposted", counts)
	}
	if w := request("POST", url, string(raw), otherCookie, otherCSRF); w.Code != 409 || counts["/v1/disk-host-jobs/dispatch"] != 1 {
		t.Fatal("another admin adopted original key", w.Code, counts)
	}
	cancelURL := url + "/" + original.JobID + "/cancel"
	if w := request("POST", cancelURL, "{}", otherCookie, otherCSRF); w.Code != 403 || counts["/v1/disk-host-jobs/cancel"] != 0 {
		t.Fatal("another admin canceled original", w.Code, counts)
	}
	w = request("POST", cancelURL, "{}", oc, csrf)
	if w.Code != 202 || !strings.Contains(w.Body.String(), `"terminal_verified":false`) {
		t.Fatal("native signal became completed cancellation", w.Code, w.Body.String())
	}
	j, err := s.HostDiskForActor(context.Background(), original.JobID, owner.ID)
	if err != nil || j.State != "cancel_requested" {
		t.Fatal(j.State, err)
	}
	if _, _, err := s.QueueHostDisk(context.Background(), selection, ID(), owner.ID); err == nil {
		t.Fatal("native signal released active slot")
	}
	if w := request("GET", url, "", otherCookie, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"jobs":[]`) {
		t.Fatal("other owner read private history", w.Code, w.Body.String())
	}
}

func TestHostDiskHTTPInventoryRevocationAndStaleMountNeverQueue(t *testing.T) {
	for _, kind := range []string{"revoked", "stale-mount", "remote"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			u := accessUser(t, s, "stale-owner", "admin", nil)
			a, request, login := diskHostHTTPServer(t, s)
			state, in := diskHostHTTPStateFixture(t)
			a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/v1/disk-host-jobs/inventory" {
					t.Fatal("denied selector reached dispatch", r.URL.Path)
				}
				switch kind {
				case "revoked":
					if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'[]',2)", u.ID); err != nil {
						t.Fatal(err)
					}
				case "stale-mount":
					state.Inventory.Mounts.Mounts[0].BindingSHA = strings.Repeat("f", 64)
				case "remote":
					state.Inventory.Mounts.Mounts[0].Class = "remote_or_userspace"
				}
				raw, _ := json.Marshal(state)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			cookie, csrf := login(u.Username)
			raw, _ := json.Marshal(in)
			if w := request("POST", "/api/software/disk-analysis/host/jobs", string(raw), cookie, csrf); w.Code != 409 {
				t.Fatal(w.Code, w.Body.String())
			}
			var count int
			if s.DB.QueryRow("SELECT count(*) FROM disk_host_jobs").Scan(&count) != nil || count != 0 {
				t.Fatal("denied selector left native queue intent")
			}
		})
	}
}

func TestHostDiskLifecycleMutualQueueProtection(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	u := accessUser(t, s, "lifecycle-owner", "admin", nil)
	j, _, err := s.QueueHostDisk(ctx, hostSelectionFixture(), ID(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.QueueSoftwareAction("disk-analysis", "uninstall", nil, ID(), u.ID); err == nil {
		t.Fatal("uninstall queued over original scan")
	}
	if _, err := s.queueSoftwareAction("disk-analysis", "update", nil, DiskAnalysisAppVersion, ID(), u.ID); err == nil {
		t.Fatal("update queued over original scan")
	}
	if _, err := s.RequestHostDiskCancel(ctx, j.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	job, err := s.QueueSoftwareAction("disk-analysis", "uninstall", nil, ID(), u.ID)
	if err != nil {
		t.Fatal("undispatched canceled original never released lifecycle", err)
	}
	if _, _, err := s.QueueHostDisk(ctx, hostSelectionFixture(), ID(), u.ID); err == nil {
		t.Fatal("scan queued over native app lifecycle")
	}
	// Isolated queue fixture only; no actual uninstall or acceptance claim.
	if _, err := s.DB.Exec("UPDATE runtime_jobs SET state='succeeded' WHERE id=?", job); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.QueueHostDisk(ctx, hostSelectionFixture(), ID(), u.ID); err != nil {
		t.Fatal("completed app queue kept refusing new scan", err)
	}
}
