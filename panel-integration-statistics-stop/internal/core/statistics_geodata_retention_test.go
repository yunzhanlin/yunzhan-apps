package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Real session/CSRF/SQLite path with a declared executor inventory fixture.
// Not proof of an actual signed database or native maintenance operation.
func TestStatisticsGeoRetentionHTTPProtectsSelectionAndArchiveLocation(t *testing.T) {
	s := testStore(t)
	admin := accessUser(t, s, "geo-retention-admin", "admin", nil)
	in := statisticsGeoSelectionFixture()
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	state := StatisticsGeoState{Installed: true, AppVersion: in.AppVersion, InstallationID: in.InstallationID, Stored: []StatisticsGeoStored{{Release: "2026-10", ManifestSHA: Hash("2026-10"), AppSHA: in.AppManifestSHA, Selected: true, HighWater: true}, {Release: "2026-09", ManifestSHA: Hash("2026-09"), AppSHA: in.AppManifestSHA, Previous: true}, {Release: "2026-08", ManifestSHA: Hash("2026-08"), AppSHA: in.AppManifestSHA}, {Release: "2026-07", ManifestSHA: Hash("2026-07"), AppSHA: in.AppManifestSHA, Archived: true}}}
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/v1/statistics/geodata" {
			t.Fatal("controller dispatched mutation instead of bounded queue", r.Method, r.URL)
		}
		raw, _ := json.Marshal(state)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}}
	request := func(path, body, csrf, key string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	w := request("/api/login", `{"username":"`+admin.Username+`","password":"access-test-password-long"}`, "", "", nil)
	var auth accountSession
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &auth) != nil {
		t.Fatal("login", w.Code)
	}
	cookie := w.Result().Cookies()[0]
	endpoint := "/api/software/website-statistics-v2/geodata"
	for _, denied := range []struct{ action, month string }{{"archive", "2026-10"}, {"archive", "2026-09"}, {"restore", "2026-08"}, {"rollback", "2026-07"}, {"archive", "2026-07"}} {
		selection := in
		selection.Action = denied.action
		selection.Release = denied.month
		selection.DataManifestSHA = Hash(denied.month)
		raw, _ := json.Marshal(selection)
		if w := request(endpoint, string(raw), auth.CSRF, "denied-"+denied.action+denied.month, cookie); w.Code != 409 {
			t.Fatal("protected/location mismatch queued", denied, w.Code)
		}
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM runtime_jobs WHERE kind='statistics_geodata'").Scan(&count)
	if count != 0 || calls != 5 {
		t.Fatal("denial created jobs or bypassed inventory", count, calls)
	}
	for _, allowed := range []struct{ action, month string }{{"archive", "2026-08"}, {"restore", "2026-07"}} {
		selection := in
		selection.Action = allowed.action
		selection.Release = allowed.month
		selection.DataManifestSHA = Hash(allowed.month)
		raw, _ := json.Marshal(selection)
		w := request(endpoint, string(raw), auth.CSRF, "allowed-"+allowed.action, cookie)
		if w.Code != 202 {
			t.Fatal("eligible closed maintenance selection rejected", allowed, w.Code, w.Body.String())
		}
		job, err := s.nextRuntimeInstallJob()
		if err != nil || job.Kind != "statistics_geodata" {
			t.Fatal(job, err)
		}
		decoded, err := DecodeStatisticsGeoSelection([]byte(job.Payload))
		if err != nil || decoded != selection {
			t.Fatal("queued maintenance changed immutable intent", err)
		}
		if err = s.finishRuntime(job, "synthetic controller-only fixture; not native acceptance", nil, false); err != nil {
			t.Fatal(err)
		}
	}
}
