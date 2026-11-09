package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Synthetic evidence only; no provider signature or installed-software proof.
func geoExportFixture(id string) (StatisticsGeoExportInput, StatisticsGeoExportResult) {
	files := map[string][]byte{"request.json": []byte(`{"original":"request"}`), "envelope.json": []byte("{}"), "started.json": []byte(`{"original":"start"}`), "result.json": []byte(`{"state":"failed"}`), "install.lock": {}}
	h := sha256.New()
	var total int64
	for _, name := range statisticsGeoEvidenceNames {
		h.Write([]byte(name))
		h.Write([]byte{0})
		d := sha256.Sum256(files[name])
		h.Write(d[:])
		total += int64(len(files[name]))
	}
	row := StatisticsGeoJobRecord{JobID: id, State: "failed", SHA: hex.EncodeToString(h.Sum(nil)), Bytes: total, Archived: true}
	bundle, _ := json.Marshal(StatisticsGeoEvidenceBundle{Format: 1, Record: row, Files: files})
	return StatisticsGeoExportInput{JobID: id, SHA: row.SHA}, StatisticsGeoExportResult{Record: row, Bundle: bundle, BundleSHA: Hash(string(bundle))}
}
func TestStatisticsGeoExportClosedFieldsAndByteExactEvidence(t *testing.T) {
	in, out := geoExportFixture(strings.Repeat("c", 32))
	raw, _ := json.Marshal(in)
	if got, err := DecodeStatisticsGeoExport(raw); err != nil || got != in {
		t.Fatal(got, err)
	}
	for _, bad := range []string{string(raw) + "{}", strings.Replace(string(raw), `"job_id"`, `"Job_ID"`, 1), `{"job_id":"` + in.JobID + `",` + string(raw[1:]), strings.Replace(string(raw), `"expected_sha256"`, `"path"`, 1), `{"job_id":"` + in.JobID + `","expected_sha256":null}`} {
		if _, err := DecodeStatisticsGeoExport([]byte(bad)); err == nil {
			t.Fatal("ambiguous export accepted")
		}
	}
	wire, _ := json.Marshal(out)
	if got, err := DecodeStatisticsGeoExportResult(wire, in); err != nil || string(got.Bundle) != string(out.Bundle) {
		t.Fatal(err)
	}
	for _, mode := range []string{"changed-byte", "wrong-job", "wrong-state", "wrong-record", "unknown-file", "missing-file", "null-lock", "oversized-leaf", "duplicate-file", "unknown-bundle", "changed-bundle-sha", "trailing-json"} {
		t.Run(mode, func(t *testing.T) {
			copy := out
			var b StatisticsGeoEvidenceBundle
			_ = json.Unmarshal(out.Bundle, &b)
			switch mode {
			case "changed-byte":
				b.Files["envelope.json"] = []byte("{ }")
			case "wrong-job":
				copy.Record.JobID = ID()
			case "wrong-state":
				copy.Record.State = "pending"
			case "wrong-record":
				b.Record.Bytes++
			case "unknown-file":
				b.Files["../other"] = []byte("private")
			case "missing-file":
				delete(b.Files, "started.json")
			case "null-lock":
				b.Files["install.lock"] = nil
			case "oversized-leaf":
				b.Files["request.json"] = []byte(strings.Repeat("a", 4097))
			}
			copy.Bundle, _ = json.Marshal(b)
			switch mode {
			case "duplicate-file":
				copy.Bundle = []byte(strings.Replace(string(copy.Bundle), `"files":{`, `"files":{"install.lock":"",`, 1))
			case "unknown-bundle":
				copy.Bundle = []byte(strings.Replace(string(copy.Bundle), `"format":1`, `"format":1,"path":"/etc/shadow"`, 1))
			case "trailing-json":
				copy.Bundle = append(copy.Bundle, []byte("{}")...)
			}
			copy.BundleSHA = Hash(string(copy.Bundle))
			if mode == "changed-bundle-sha" {
				copy.BundleSHA = strings.Repeat("a", 64)
			}
			wire, _ := json.Marshal(copy)
			if _, err := DecodeStatisticsGeoExportResult(wire, in); err == nil {
				t.Fatal("invalid original evidence accepted", mode)
			}
		})
	}
}
func TestStatisticsGeoExportMaximumLegitimateLeavesFitUnchangedRPCBudget(t *testing.T) {
	in, out := geoExportFixture(strings.Repeat("e", 32))
	var b StatisticsGeoEvidenceBundle
	_ = json.Unmarshal(out.Bundle, &b)
	h := sha256.New()
	b.Record.Bytes = 0
	for _, name := range statisticsGeoEvidenceNames {
		b.Files[name] = []byte(strings.Repeat("a", statisticsGeoEvidenceLimits[name]))
		h.Write([]byte(name))
		h.Write([]byte{0})
		d := sha256.Sum256(b.Files[name])
		h.Write(d[:])
		b.Record.Bytes += int64(len(b.Files[name]))
	}
	b.Record.SHA = hex.EncodeToString(h.Sum(nil))
	in.SHA = b.Record.SHA
	out.Record = b.Record
	out.Bundle, _ = json.Marshal(b)
	out.BundleSHA = Hash(string(out.Bundle))
	wire, _ := json.Marshal(out)
	if len(wire) > 7<<20 || len(wire) >= 16<<20 {
		t.Fatal("unbounded export")
	}
	if _, err := DecodeStatisticsGeoExportResult(wire, in); err != nil {
		t.Fatal("maximum legitimate original leaves rejected", err)
	}
}
func TestStatisticsGeoExportRejectsNullArchiveIdentity(t *testing.T) {
	for _, where := range []string{"bundle", "reply"} {
		t.Run(where, func(t *testing.T) {
			in, out := geoExportFixture(strings.Repeat("d", 32))
			out.Record.Archived = false
			var b StatisticsGeoEvidenceBundle
			_ = json.Unmarshal(out.Bundle, &b)
			b.Record = out.Record
			out.Bundle, _ = json.Marshal(b)
			out.BundleSHA = Hash(string(out.Bundle))
			wire, _ := json.Marshal(out)
			if _, err := DecodeStatisticsGeoExportResult(wire, in); err != nil {
				t.Fatal("valid active evidence rejected", err)
			}
			if where == "bundle" {
				out.Bundle = []byte(strings.Replace(string(out.Bundle), `"archived":false`, `"archived":null`, 1))
				out.BundleSHA = Hash(string(out.Bundle))
				wire, _ = json.Marshal(out)
			} else {
				wire = []byte(strings.Replace(string(wire), `"archived":false`, `"archived":null`, 1))
			}
			if _, err := DecodeStatisticsGeoExportResult(wire, in); err == nil {
				t.Fatal("null archive identity accepted as active")
			}
		})
	}
}
func TestStatisticsGeoExportHTTPAdminCSRFAndAuditPreserveOriginalJob(t *testing.T) {
	s := testStore(t)
	admin := accessUser(t, s, "geo-export-admin", "admin", nil)
	accessUser(t, s, "geo-export-viewer", "viewer", nil)
	accessUser(t, s, "geo-export-restricted", "admin", []string{"overview"})
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.QueueStatisticsGeo(statisticsGeoSelectionFixture(), "http-export-original", admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	in, out := geoExportFixture(id)
	raw, _ := json.Marshal(in)
	calls := 0
	badReply := false
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/v1/statistics/geodata-job-records/export" {
			t.Fatal(r.Method, r.URL)
		}
		body, _ := io.ReadAll(r.Body)
		got, err := DecodeStatisticsGeoExport(body)
		if err != nil || got != in {
			t.Fatal("changed identity", err)
		}
		result := out
		if badReply {
			result.BundleSHA = strings.Repeat("b", 64)
		}
		wire, _ := json.Marshal(result)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(wire)))}, nil
	})}}
	request := func(endpoint, body, csrf, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", endpoint, strings.NewReader(body))
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
	endpoint := "/api/software/website-statistics-v2/geodata-job-records/export"
	for _, name := range []string{"geo-export-viewer", "geo-export-restricted"} {
		cookie, csrf := login(name)
		if w := request(endpoint, string(raw), csrf, a.Config.Origin, cookie); w.Code != 403 || calls != 0 {
			t.Fatal("ACL reached Root", w.Code, calls)
		}
	}
	cookie, csrf := login(admin.Username)
	for _, denied := range []struct {
		token, origin string
		cookie        *http.Cookie
	}{{"wrong", a.Config.Origin, cookie}, {csrf, "https://wrong.invalid", cookie}, {csrf, a.Config.Origin, nil}} {
		if w := request(endpoint, string(raw), denied.token, denied.origin, denied.cookie); w.Code < 400 || calls != 0 {
			t.Fatal("CSRF/session/origin reached Root", w.Code, calls)
		}
	}
	if w := request(endpoint, string(raw), csrf, a.Config.Origin, cookie); w.Code != 409 || calls != 0 {
		t.Fatal("nonterminal evidence exported", w.Code, calls)
	}
	if _, err = s.DB.Exec("UPDATE runtime_jobs SET state='failed',error='retained synthetic failure' WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	before, err := s.Job(id)
	if err != nil {
		t.Fatal(err)
	}
	badReply = true
	if w := request(endpoint, string(raw), csrf, a.Config.Origin, cookie); w.Code != 503 {
		t.Fatal("corrupt reply returned", w.Code)
	}
	badReply = false
	for range 2 {
		w := request(endpoint, string(raw), csrf, a.Config.Origin, cookie)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("normal export", w.Code, w.Body.String())
		}
	}
	after, err := s.Job(id)
	if err != nil || before.State != after.State || before.Error != after.Error || before.UpdatedAt != after.UpdatedAt || before.CreatedAt != after.CreatedAt {
		t.Fatal("original job mutated", err)
	}
	var requests, completed, archived int
	s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE actor=? AND action='statistics.geodata.export.request' AND target=? AND result=?", admin.ID, id, in.SHA).Scan(&requests)
	s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE actor=? AND action='statistics.geodata.export.complete' AND target=? AND result=?", admin.ID, id, out.BundleSHA).Scan(&completed)
	s.DB.QueryRow("SELECT count(*) FROM statistics_geodata_job_archives").Scan(&archived)
	if requests != 3 || completed != 2 || archived != 0 || calls != 3 {
		t.Fatal("audit or archive effect wrong", requests, completed, archived, calls)
	}
	if replay, found, err := statisticsGeoReplay(s.DB, statisticsGeoSelectionFixture(), "http-export-original", admin.ID); err != nil || !found || replay != id {
		t.Fatal("original idempotency identity lost", err)
	}
}
