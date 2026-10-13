package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func geoArchiveFixture(id string) (StatisticsGeoArchiveInput, StatisticsGeoArchiveResult) {
	in := StatisticsGeoArchiveInput{JobID: id, SHA: strings.Repeat("a", 64), Confirm: "ARCHIVE GEODATA JOB " + id}
	return in, StatisticsGeoArchiveResult{Record: StatisticsGeoJobRecord{JobID: id, SHA: in.SHA, State: "failed", Bytes: 321, Archived: true}}
}
func TestStatisticsGeoArchiveClosedRequestsInventoryAndReceipt(t *testing.T) {
	in, out := geoArchiveFixture(strings.Repeat("d", 32))
	raw, _ := json.Marshal(in)
	if got, err := DecodeStatisticsGeoArchive(raw); err != nil || got != in {
		t.Fatal(got, err)
	}
	for _, bad := range []string{string(raw) + "{}", strings.Replace(string(raw), `"job_id"`, `"Job_ID"`, 1), `{"job_id":"` + in.JobID + `",` + string(raw[1:]), strings.Replace(string(raw), `"expected_sha256":"`+in.SHA+`"`, `"expected_sha256":null`, 1), strings.Replace(string(raw), `"confirm"`, `"path"`, 1)} {
		if _, err := DecodeStatisticsGeoArchive([]byte(bad)); err == nil {
			t.Fatal("ambiguous archive accepted", bad)
		}
	}
	wire, _ := json.Marshal(out)
	if _, err := DecodeStatisticsGeoArchiveResult(wire, in); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*StatisticsGeoArchiveResult){func(v *StatisticsGeoArchiveResult) { v.Record.Archived = false }, func(v *StatisticsGeoArchiveResult) { v.Record.JobID = ID() }, func(v *StatisticsGeoArchiveResult) { v.Record.SHA = strings.Repeat("b", 64) }, func(v *StatisticsGeoArchiveResult) { v.Record.State = "pending" }} {
		v := out
		change(&v)
		bad, _ := json.Marshal(v)
		if _, err := DecodeStatisticsGeoArchiveResult(bad, in); err == nil {
			t.Fatal("false receipt accepted", string(bad))
		}
	}
	inv := StatisticsGeoJobInventory{Entries: []StatisticsGeoJobRecord{out.Record}, ActiveMax: 128, ArchiveMax: 512, ReadOnly: true}
	wire, _ = json.Marshal(inv)
	if _, err := DecodeStatisticsGeoJobInventory(wire); err != nil {
		t.Fatal(err)
	}
	inv.Entries = append(inv.Entries, out.Record)
	wire, _ = json.Marshal(inv)
	if _, err := DecodeStatisticsGeoJobInventory(wire); err == nil {
		t.Fatal("duplicate inventory accepted")
	}
}
func TestStatisticsGeoArchiveFreesOnlyVerifiedTerminalCapacityAndKeepsReplay(t *testing.T) {
	s := testStore(t)
	actor := strings.Repeat("b", 32)
	selection := statisticsGeoSelectionFixture()
	for i := 0; i < 128; i++ {
		id := fmt.Sprintf("%032x", i+1)
		raw, _ := json.Marshal(selection)
		if _, err := s.DB.Exec("INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at) VALUES(?,'website-statistics-v2','statistics_geodata','failed',?,?,?,?)", id, string(raw), fmt.Sprintf("archive-fixture-%d", i), Now(), Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec("INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'statistics.geodata.queue',?,'queued',?)", actor, id, Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.QueueStatisticsGeo(selection, "new-before-archive", actor); err == nil {
		t.Fatal("128 limit bypassed")
	}
	id := fmt.Sprintf("%032x", 1)
	in, out := geoArchiveFixture(id)
	audit, err := s.DB.Exec("INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'statistics.geodata.archive.request',?,?,?)", actor, id, in.SHA, Now())
	if err != nil {
		t.Fatal(err)
	}
	auditID, _ := audit.LastInsertId()
	wrong := out
	wrong.Record.State = "succeeded"
	if err = s.finishStatisticsGeoArchive(context.Background(), actor, in, wrong, auditID); err == nil {
		t.Fatal("mismatched root success freed capacity")
	}
	if err = s.finishStatisticsGeoArchive(context.Background(), actor, in, out, auditID+999); err == nil {
		t.Fatal("no original audit freed capacity")
	}
	before, err := s.Job(id)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.finishStatisticsGeoArchive(context.Background(), actor, in, out, auditID); err != nil {
		t.Fatal(err)
	}
	if err = s.finishStatisticsGeoArchive(context.Background(), actor, in, out, auditID); err != nil {
		t.Fatal("same request not recoverable", err)
	}
	after, err := s.Job(id)
	if err != nil || before.State != after.State || before.Error != after.Error || before.CreatedAt != after.CreatedAt || before.UpdatedAt != after.UpdatedAt {
		t.Fatal("archive changed original job", before, after, err)
	}
	if replay, found, err := statisticsGeoReplay(s.DB, selection, "archive-fixture-0", actor); err != nil || !found || replay != id {
		t.Fatal("archived original key became replayable as new job", replay, found, err)
	}
	if _, err := s.QueueStatisticsGeo(selection, "new-after-archive", actor); err != nil {
		t.Fatal("verified archive did not free slot", err)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM runtime_jobs WHERE kind='statistics_geodata'").Scan(&count)
	if count != 129 {
		t.Fatal("old evidence deleted", count)
	}
	changed := in
	changed.SHA = strings.Repeat("c", 64)
	changedOut := out
	changedOut.Record.SHA = changed.SHA
	if err = s.finishStatisticsGeoArchive(context.Background(), actor, changed, changedOut, auditID); err == nil {
		t.Fatal("archived digest overwritten")
	}
}
func TestStatisticsGeoArchiveHTTPAdminCSRFAndTerminalBinding(t *testing.T) {
	s := testStore(t)
	admin := accessUser(t, s, "geo-archive-admin", "admin", nil)
	accessUser(t, s, "geo-archive-viewer", "viewer", nil)
	accessUser(t, s, "geo-archive-restricted", "admin", []string{"overview"})
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	selection := statisticsGeoSelectionFixture()
	id, err := s.QueueStatisticsGeo(selection, "http-archive-original", admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	in, out := geoArchiveFixture(id)
	raw, _ := json.Marshal(in)
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/v1/statistics/geodata-job-records/archive" {
			t.Fatal(r.Method, r.URL)
		}
		body, _ := io.ReadAll(r.Body)
		got, err := DecodeStatisticsGeoArchive(body)
		if err != nil || got != in {
			t.Fatal("executor received changed identity", err)
		}
		v, _ := json.Marshal(out)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(v)))}, nil
	})}}
	request := func(path, body, csrf, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Origin", origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := func(name string) (*http.Cookie, string) {
		w := request("/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", a.Config.Origin, nil)
		var auth accountSession
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &auth) != nil {
			t.Fatal("login", w.Code)
		}
		return w.Result().Cookies()[0], auth.CSRF
	}
	endpoint := "/api/software/website-statistics-v2/geodata-job-records/archive"
	for _, name := range []string{"geo-archive-viewer", "geo-archive-restricted"} {
		cookie, csrf := login(name)
		if w := request(endpoint, string(raw), csrf, a.Config.Origin, cookie); w.Code != 403 || calls != 0 {
			t.Fatal("ACL reached root", w.Code, calls)
		}
	}
	cookie, csrf := login(admin.Username)
	for _, denied := range []struct {
		token, origin string
		cookie        *http.Cookie
	}{{"wrong", a.Config.Origin, cookie}, {csrf, "https://wrong.invalid", cookie}, {csrf, a.Config.Origin, nil}} {
		if w := request(endpoint, string(raw), denied.token, denied.origin, denied.cookie); w.Code < 400 || calls != 0 {
			t.Fatal("session/CSRF/origin reached root", w.Code, calls)
		}
	}
	if w := request(endpoint, string(raw), csrf, a.Config.Origin, cookie); w.Code != 409 || calls != 0 {
		t.Fatal("queued job archived", w.Code, calls)
	}
	if _, err = s.DB.Exec("UPDATE runtime_jobs SET state='failed',error='synthetic failure' WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		w := request(endpoint, string(raw), csrf, a.Config.Origin, cookie)
		if w.Code != 200 {
			t.Fatal("archive normal core HTTP", w.Code, w.Body.String())
		}
	}
	if calls != 2 {
		t.Fatal(calls)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM statistics_geodata_job_archives WHERE job_id=?", id).Scan(&count)
	if count != 1 {
		t.Fatal("duplicate marker", count)
	}
}
