package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const countryTestAPI = "/api/software/nginx-waf/country-data"

func countryTestPost(t *testing.T, a *Server, path string, cookie *http.Cookie, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.AddCookie(cookie)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", a.Config.Origin)
	u, err := a.Store.sessionIdentity(Hash(cookie.Value), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-CSRF-Token", u.CSRF)
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestWAFCountryReadOnlyHTTPRequiresBothCurrentMenusAndNeverCallsRootOrRepository(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	key := ID()
	id, _, err := s.queueWAFCountryData(context.Background(), countryDataSelectionFixture(), key, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	admin := login("waf-admin")
	for _, path := range []string{countryTestAPI + "/jobs", countryTestAPI + "/jobs/" + id, countryTestAPI + "/requests/" + key, countryTestAPI + "/requests/" + ID()} {
		w := wafTaskTestRead(a, path, admin)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("actual authenticated read-only original lookup failed", path, w.Code, w.Body.String())
		}
	}
	for _, name := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		cookie := login(name)
		for _, path := range []string{countryTestAPI, countryTestAPI + "/jobs", countryTestAPI + "/jobs/" + id, countryTestAPI + "/requests/" + key} {
			w := wafTaskTestRead(a, path, cookie)
			if w.Code != 403 {
				t.Fatal("country API admitted missing current role/menu", name, path, w.Code)
			}
		}
	}
	for _, path := range []string{countryTestAPI + "/jobs?source=anything", countryTestAPI + "/jobs?cursor=" + ID() + "&cursor=" + ID(), countryTestAPI + "/jobs?bad=%ZZ", countryTestAPI + "/jobs/" + id + "?source=anything", countryTestAPI + "/requests/" + key + "?replay=1"} {
		if w := wafTaskTestRead(a, path, admin); w.Code != 400 {
			t.Fatal("ambiguous original lookup accepted", path, w.Code)
		}
	}
	var audits, requests int
	if s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action LIKE 'waf.country.%'`).Scan(&audits) != nil || audits != 1 || s.DB.QueryRow(`SELECT count(*) FROM waf_country_requests`).Scan(&requests) != nil || requests != 1 {
		t.Fatal("read-only HTTP lookup mutated application intent", audits, requests)
	}
}

func TestWAFCountryRequestUnknownIsNotNotSubmittedAndForeignOrCorruptKeysCannotBeAdopted(t *testing.T) {
	s, _, _ := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	ctx := context.Background()
	key := ID()
	unknown, err := s.readWAFCountryRequestKey(ctx, u.ID, key)
	if err != nil || unknown.StateKnown || unknown.Request != nil || !unknown.ReadOnly || unknown.AutomaticReplayAllowed || unknown.RequestID != key {
		t.Fatal("unknown original granted automatic fresh submission", unknown, err)
	}
	id, _, err := s.queueWAFCountryData(ctx, countryDataSelectionFixture(), key, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	known, err := s.readWAFCountryRequestKey(ctx, u.ID, key)
	if err != nil || !known.StateKnown || known.Request == nil || known.Request.Request.ID != id || known.AutomaticReplayAllowed {
		t.Fatal(known, err)
	}
	other := accessUser(t, s, "country-key-other-admin", "admin", []string{"runtimes", "security"})
	if _, err := s.readWAFCountryRequestKey(ctx, other.ID, key); err == nil {
		t.Fatal("other current admin adopted another actor's original key")
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='succeeded' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readWAFCountryRequestKey(ctx, u.ID, key); err == nil {
		t.Fatal("invented success without whole Root result was accepted")
	}
	if page, err := s.readWAFCountryRequests(ctx, u.ID, ""); err == nil || len(page.Entries) != 0 {
		t.Fatal("page returned partial or invented prepared data", page, err)
	}
}

func TestWAFCountryHTTPOriginalReplayIsObservationOnlyEvenAfterInstallChanges(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	in, key := countryDataSelectionFixture(), ID()
	id, _, err := s.queueWAFCountryData(context.Background(), in, key, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='failed',error='original pre-submission failure fixture' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	a.AppCatalog = nil // Any new-source access would be wrong for this original.
	body, _ := json.Marshal(map[string]any{"actor_id": u.ID, "selection": in})
	w := countryTestPost(t, a, countryTestAPI, login("waf-admin"), key, string(body))
	var reply struct {
		Job      string `json:"job_id"`
		Replayed bool   `json:"replayed"`
		DataOnly bool   `json:"data_only"`
	}
	if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Job != id || !reply.Replayed || !reply.DataOnly || countryWorkerState(t, s, id) != "failed" {
		t.Fatal("known original became fresh work", w.Code, w.Body.String())
	}
	changed := in
	changed.Countries = []string{"US"}
	body, _ = json.Marshal(map[string]any{"actor_id": u.ID, "selection": changed})
	w = countryTestPost(t, a, countryTestAPI, login("waf-admin"), key, string(body))
	if w.Code != 409 {
		t.Fatal("changed country selection adopted known original", w.Code)
	}
}

func TestWAFCountryOldInstalledVersionCannotQueueOrFetchCountryData(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	u := wafArchivePendingIdentity(t, s, "waf-admin")
	var reads atomic.Int32
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: countryWorkerTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/v1/waf/country" {
			t.Fatal("old app caused a native write or wrong metadata request", r.Method, r.URL)
		}
		reads.Add(1)
		state := WAFCountryDataState{Installed: true, AppVersion: "2.5.1", MaxCountries: 32, MaxBytes: 64 << 20, MaxNetworks: 1 << 20, DownloadsDoNotActivatePolicy: true}
		raw, _ := json.Marshal(state)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
	a.AppCatalog = nil
	cookie := login("waf-admin")
	if w := wafTaskTestRead(a, countryTestAPI, cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"available":null`) || !strings.Contains(w.Body.String(), `"supported":false`) {
		t.Fatal("old installed version borrowed availability", w.Code, w.Body.String())
	}
	body, _ := json.Marshal(map[string]any{"actor_id": u.ID, "selection": countryDataSelectionFixture()})
	if w := countryTestPost(t, a, countryTestAPI, cookie, ID(), string(body)); w.Code != 409 {
		t.Fatal("old installed version queued country data", w.Code, w.Body.String())
	}
	var jobs int
	if reads.Load() != 2 || s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE kind='waf_country_data'`).Scan(&jobs) != nil || jobs != 0 {
		t.Fatal("unsupported data action created work", reads.Load(), jobs)
	}
}

func TestWAFCountryResultLookupRejectsAlteredBodyStateOrHashWithoutPartialData(t *testing.T) {
	for _, mutation := range []string{`UPDATE waf_country_results SET result_sha256='` + strings.Repeat("a", 64) + `'`, `UPDATE waf_country_results SET body=body||' '`, `UPDATE waf_country_results SET request_sha256='` + strings.Repeat("b", 64) + `'`, `UPDATE waf_country_results SET state='failed'`} {
		t.Run(mutation[:45], func(t *testing.T) {
			s, j, original, out := countryWorkerFixture(t)
			raw, _ := json.Marshal(out)
			if err := s.finishWAFCountryResult(context.Background(), j, raw, original.Actor, original.Selection, nil); err != nil {
				t.Fatal(err)
			}
			if got, err := s.readWAFCountryRequest(context.Background(), original.Actor, j.ID); err != nil || got.Result == nil || got.ResultSHA != Hash(string(raw)) || got.Result.Cache.ActivatedNginxPolicy {
				t.Fatal("complete data-only original result unavailable", got, err)
			}
			if _, err := s.DB.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			if got, err := s.readWAFCountryRequest(context.Background(), original.Actor, j.ID); err == nil || got.Result != nil {
				t.Fatal("altered result accepted as prepared data", got, err)
			}
		})
	}
}
