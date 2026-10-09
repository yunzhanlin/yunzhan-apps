package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"local/panel/internal/appcatalog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNetworkIDSRuleFeedIndependentChannelReadSubmitAndWorker(t *testing.T) {
	repository, selection, requests := networkRuleFeedRepositoryFixtureMode(t, true)
	store := testStore(t)
	user := accessUser(t, store, "admin", "admin", nil)
	a, err := NewServer(store, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	a.AppCatalog = repository
	mutations := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		var out any
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/app-modules/network-threat-detection":
			out = map[string]any{"status": SoftwareAppStatus{Installed: true}}
		case r.Method == "GET" && r.URL.Path == "/v1/network-ids/rule-feeds":
			out = NetworkIDSRuleFeedInventory{StateKnown: true, Rows: []NetworkIDSRuleFeedStored{}}
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/network-ids/rule-feeds/jobs/"):
			mutations++
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			in, err := appcatalog.DecodeRuleFeedEnvelope(raw)
			if err != nil || len(in.DataCatalog) == 0 || len(in.DataSignature) == 0 {
				t.Fatalf("missing dual signature carrier: %v", err)
			}
			if _, _, err := repository.VerifyRuleFeedEnvelope(context.Background(), in, selection.AppVersion, selection.AppManifestSHA); err != nil {
				t.Fatal(err)
			}
			out = NetworkIDSRuleFeedStatus{JobID: strings.TrimPrefix(r.URL.Path, "/v1/network-ids/rule-feeds/jobs/"), State: "ready-data", Selection: selection, DataOnly: true}
		default:
			t.Fatal("unexpected channel dispatch", r.Method, r.URL)
		}
		raw, _ := json.Marshal(out)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}}
	login := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"access-test-password-long"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", a.Config.Origin)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, login)
	if w.Code != 200 {
		t.Fatal("fixture login", w.Code)
	}
	cookie := w.Result().Cookies()[0]
	var auth accountSession
	if err := json.Unmarshal(w.Body.Bytes(), &auth); err != nil || auth.CSRF == "" {
		t.Fatal("fixture CSRF missing", err)
	}
	request := func(method, path string, body []byte, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", auth.CSRF)
		out := httptest.NewRecorder()
		a.ServeHTTP(out, r)
		return out
	}
	endpoint := "/api/software/network-threat-detection/rule-feeds"
	read := request("GET", endpoint+"?refresh=1", nil, "")
	var page NetworkIDSRuleFeedPage
	if err := json.Unmarshal(read.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if read.Code != 200 || len(page.Available) != 1 || page.Available[0].Selection != selection || !page.Available[0].Supported || requests.Load() != 5 || mutations != 0 {
		t.Fatal("channel metadata fetched assets or false selection", read.Code, requests.Load(), read.Body.String())
	}
	bad := selection
	bad.RuleManifestSHA = strings.Repeat("0", 64)
	raw, _ := json.Marshal(bad)
	if rejected := request("POST", endpoint+"/install", raw, "own-data-channel-bad"); rejected.Code != 409 || mutations != 0 {
		t.Fatal("bad channel choice accepted", rejected.Code)
	}
	raw, _ = json.Marshal(selection)
	accepted := request("POST", endpoint+"/install", raw, "own-data-channel-job")
	var reply struct {
		JobID string `json:"job_id"`
	}
	if accepted.Code != 202 || json.Unmarshal(accepted.Body.Bytes(), &reply) != nil || !ValidID(reply.JobID) || mutations != 0 {
		t.Fatal("channel install did not queue data only", accepted.Code, accepted.Body.String())
	}
	job, err := store.nextRuntimeInstallJob()
	if err != nil || job.ID != reply.JobID {
		t.Fatal("queued channel job missing", err)
	}
	runNetworkIDSRuleFeedJob(context.Background(), store, a.Executor, job, repository)
	var state string
	store.DB.QueryRow(`SELECT state FROM runtime_jobs WHERE id=?`, job.ID).Scan(&state)
	if state != "succeeded" || mutations != 1 {
		t.Fatal("fake offline data result not complete", state, mutations)
	}
	before := requests.Load()
	repeat := request("POST", endpoint+"/install", raw, "own-data-channel-job")
	if repeat.Code != 202 || requests.Load() != before || mutations != 1 {
		t.Fatal("replayed channel request downloaded or dispatched again", repeat.Code)
	}
	var actor string
	if err := store.DB.QueryRow(`SELECT actor FROM audit_logs WHERE action='network.ids.rules.install' AND target=?`, job.ID).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if actor != user.ID {
		t.Fatal("channel job replay not actor bound")
	}
}
