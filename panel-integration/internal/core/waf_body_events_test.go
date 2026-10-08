package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestWAFBodyReportCountsRulesNotHTTPAndRejectsInventedFields(t *testing.T) {
	now := time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC)
	id := strings.Repeat("a", 32)
	snapshot := WAFBodyEventsPage{Available: true, Partial: true, Rejected: 1, Events: []WAFBodyEvent{{Time: now.Add(-time.Minute).Format(time.RFC3339), SiteID: id, RuleID: 941100, Phase: 2, Severity: 2, Disruptive: true}, {Time: now.Add(-time.Minute).Format(time.RFC3339), SiteID: id, RuleID: 949110, Phase: 2, Severity: 2, Disruptive: true}}}
	snapshot.LogBytes = 32 << 20
	snapshot.MaxBytes = 32 << 20
	snapshot.CapacityExhausted = true
	snapshot.LegacyLog = true
	snapshot.BestEffort = true
	out, err := BuildWAFBodyReport(snapshot, url.Values{"limit": {"1"}}, now)
	if err != nil || out.Matches != 2 || len(out.Events) != 1 || out.Counting != "rule_matches_not_http_requests_or_blocks" || !out.Partial || out.Rejected != 1 {
		t.Fatal(out, err)
	}
	if out.LogBytes != snapshot.LogBytes || out.MaxBytes != snapshot.MaxBytes || !out.CapacityExhausted || !out.LegacyLog || !out.BestEffort {
		t.Fatal("log safety/degradation boundaries were dropped", out)
	}
	data, _ := json.Marshal(out)
	for _, field := range []string{`"blocked"`, `"requests"`, `"ip"`, `"path"`, `"body"`, `"cookie"`} {
		if strings.Contains(string(data), field) {
			t.Fatal("invented request or private field", field)
		}
	}
	filtered, err := BuildWAFBodyReport(snapshot, url.Values{"rule": {"941100"}, "phase": {"2"}, "site_id": {id}}, now)
	if err != nil || filtered.Matches != 1 {
		t.Fatal(filtered, err)
	}
	for _, query := range []url.Values{{"action": {"block"}}, {"ip": {"127.0.0.1"}}, {"rule": {"1' OR 1=1"}}, {"rule": {"0"}}, {"phase": {"6"}}, {"phase": {"02"}}, {"site_id": {"bad"}}, {"limit": {"5001"}}, {"rule": {"1", "2"}}} {
		if _, err := WAFBodyReportQuery(query, now); err == nil {
			t.Fatal("invalid filter accepted", query)
		}
	}
	missing, err := BuildWAFBodyReport(WAFBodyEventsPage{Events: []WAFBodyEvent{}}, url.Values{}, now)
	if err != nil || missing.Available {
		t.Fatal("absent log presented as available zero", missing, err)
	}
}

func TestWAFBodyLogGovernanceAdministratorMenuCSRFClosedInputs(t *testing.T) {
	s := testStore(t)
	for _, u := range []struct {
		name, role string
		menus      []string
	}{{"admin", "admin", nil}, {"limited", "admin", []string{"runtimes"}}, {"viewer", "viewer", nil}} {
		accessUser(t, s, u.name, u.role, u.menus)
	}
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	archiveID := ID()
	removeBody := `{"sha256":"` + strings.Repeat("a", 64) + `","acknowledge_bounded_export_and_permanent_removal":true}`
	retainBody := `{"index_sha256":"` + strings.Repeat("a", 64) + `","snapshot_sha256":"` + strings.Repeat("b", 64) + `","snapshot_missing":false,"acknowledge_unknown_rotation_and_incomplete_snapshot":true}`
	indexBody := `{"sha256":"` + strings.Repeat("c", 64) + `","acknowledge_uncommitted_index_not_applied":true}`
	rotationBody := `{"sha256":"` + strings.Repeat("d", 64) + `","acknowledge_unknown_rotation_not_repeated":true}`
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if !strings.HasPrefix(r.URL.Path, "/v1/software/nginx-waf/body-log/") || r.URL.RawQuery != "" {
			t.Fatal("nonfixed privileged path", r.URL)
		}
		if r.Method == "POST" {
			data, err := io.ReadAll(r.Body)
			expected := "{}"
			if strings.HasSuffix(r.URL.Path, "/remove") {
				expected = removeBody
				if r.URL.Path != "/v1/software/nginx-waf/body-log/archives/"+archiveID+"/remove" {
					t.Fatal("arbitrary removal target", r.URL.Path)
				}
			}
			if r.URL.Path == "/v1/software/nginx-waf/body-log/rotation/retain" {
				expected = rotationBody
			} else if strings.Contains(r.URL.Path, "/index-stages/") {
				expected = indexBody
				if r.URL.Path != "/v1/software/nginx-waf/body-log/index-stages/"+archiveID+"/retain" {
					t.Fatal("arbitrary index-stage target", r.URL.Path)
				}
			} else if strings.HasSuffix(r.URL.Path, "/retain") {
				expected = retainBody
				if r.URL.Path != "/v1/software/nginx-waf/body-log/archives/"+archiveID+"/retain" {
					t.Fatal("arbitrary recovery target", r.URL.Path)
				}
			}
			if err != nil || string(data) != expected {
				t.Fatal("arbitrary governance body", string(data))
			}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"entries":[],"no_nginx_reload":true}`))}, nil
	})}}
	request := func(method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
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
	base := "/api/software/nginx-waf/body-log/"
	for _, method := range []string{"GET", "POST"} {
		path, body := "rotation", ""
		if method == "POST" {
			path, body = "rotation/retain", rotationBody
		}
		if w := request(method, base+path, body, "", nil); w.Code != 401 {
			t.Fatal("anonymous automatic rotation governance", method, w.Code)
		}
	}
	if w := request("POST", base+"rotate", "{}", "", nil); w.Code != 401 {
		t.Fatal("anonymous rotation", w.Code)
	}
	if w := request("POST", base+"archives/"+archiveID+"/remove", removeBody, "", nil); w.Code != 401 {
		t.Fatal("anonymous snapshot removal", w.Code)
	}
	if w := request("POST", base+"archives/"+archiveID+"/retain", retainBody, "", nil); w.Code != 401 {
		t.Fatal("anonymous retention", w.Code)
	}
	if w := request("POST", base+"index-stages/"+archiveID+"/retain", indexBody, "", nil); w.Code != 401 {
		t.Fatal("anonymous index recovery", w.Code)
	}
	for _, name := range []string{"viewer", "limited", "admin"} {
		login := request("POST", "/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", nil)
		if login.Code != 200 {
			t.Fatal(login.Body.String())
		}
		var auth accountSession
		json.Unmarshal(login.Body.Bytes(), &auth)
		cookie := login.Result().Cookies()[0]
		before := calls
		if w := request("POST", base+"rotation/retain", rotationBody, "", cookie); w.Code != 403 || calls != before {
			t.Fatal("automatic rotation CSRF", name, w.Code)
		}
		if w := request("POST", base+"rotate", "{}", "", cookie); w.Code != 403 {
			t.Fatal("rotation CSRF", name, w.Code)
		}
		if w := request("POST", base+"archives/"+archiveID+"/remove", removeBody, "", cookie); w.Code != 403 || calls != before {
			t.Fatal("snapshot removal CSRF", name, w.Code)
		}
		if w := request("POST", base+"archives/"+archiveID+"/retain", retainBody, "", cookie); w.Code != 403 || calls != before {
			t.Fatal("retention CSRF bypass", name, w.Code)
		}
		if w := request("POST", base+"index-stages/"+archiveID+"/retain", indexBody, "", cookie); w.Code != 403 || calls != before {
			t.Fatal("index recovery CSRF bypass", w.Code)
		}
		if name != "admin" {
			for _, path := range []string{"archives", "archives/" + ID(), "rotation"} {
				if w := request("GET", base+path, "", auth.CSRF, cookie); w.Code != 403 {
					t.Fatal("unauthorized metadata backup", name, w.Code)
				}
			}
			if w := request("POST", base+"rotate", "{}", auth.CSRF, cookie); w.Code != 403 || calls != before {
				t.Fatal("unauthorized rotation called executor", name, w.Code)
			}
			if w := request("POST", base+"archives/"+archiveID+"/remove", removeBody, auth.CSRF, cookie); w.Code != 403 || calls != before {
				t.Fatal("unauthorized removal called executor", name, w.Code)
			}
			if w := request("POST", base+"archives/"+archiveID+"/retain", retainBody, auth.CSRF, cookie); w.Code != 403 || calls != before {
				t.Fatal("unauthorized retention", name, w.Code)
			}
			if w := request("POST", base+"index-stages/"+archiveID+"/retain", indexBody, auth.CSRF, cookie); w.Code != 403 || calls != before {
				t.Fatal("unauthorized index recovery", w.Code)
			}
			if w := request("POST", base+"rotation/retain", rotationBody, auth.CSRF, cookie); w.Code != 403 || calls != before {
				t.Fatal("unauthorized automatic rotation retention", name, w.Code)
			}
			continue
		}
		for _, body := range []string{`{}`, `null`, strings.Replace(rotationBody, "true", "false", 1), strings.Replace(rotationBody, strings.Repeat("d", 64), strings.Repeat("D", 64), 1), strings.Replace(rotationBody, "true", "null", 1), strings.TrimSuffix(rotationBody, "}") + `,"path":"/etc/shadow"}`, rotationBody + ` {}`, strings.TrimSuffix(rotationBody, "}") + `,"acknowledge_unknown_rotation_not_repeated":null}`, strings.TrimSuffix(rotationBody, "}") + `,"sha256":"` + strings.Repeat("d", 64) + `"}`} {
			if w := request("POST", base+"rotation/retain", body, auth.CSRF, cookie); w.Code != 400 || calls != before {
				t.Fatal("unclosed automatic rotation retention", body, w.Code)
			}
		}
		for _, method := range []string{"GET", "POST"} {
			path, body := "rotation?force=true", ""
			if method == "POST" {
				path, body = "rotation/retain?path=/private", rotationBody
			}
			if w := request(method, base+path, body, auth.CSRF, cookie); w.Code != 400 || calls != before {
				t.Fatal("automatic rotation query injection", w.Code)
			}
		}
		for _, body := range []string{`{"path":"/var/log/nginx/access.log"}`, `{"truncate":true}`, `{"signal":"KILL"}`, `{} {}`} {
			if w := request("POST", base+"rotate", body, auth.CSRF, cookie); w.Code != 400 || calls != before {
				t.Fatal("unclosed rotation", body, w.Code)
			}
		}
		for _, body := range []string{`{}`, `{"sha256":"` + strings.Repeat("a", 64) + `"}`, strings.Replace(removeBody, "true", "false", 1), strings.Replace(removeBody, strings.Repeat("a", 64), strings.Repeat("A", 64), 1), strings.Replace(removeBody, strings.Repeat("a", 64), "bad", 1), strings.TrimSuffix(removeBody, "}") + `,"path":"/var/log/nginx/access.log"}`, removeBody + ` {}`} {
			if w := request("POST", base+"archives/"+archiveID+"/remove", body, auth.CSRF, cookie); w.Code != 400 || calls != before {
				t.Fatal("unclosed or unacknowledged removal", body, w.Code)
			}
		}
		for _, path := range []string{"archives/not-an-id/remove", "archives/" + archiveID + "/remove?path=/private"} {
			if w := request("POST", base+path, removeBody, auth.CSRF, cookie); w.Code != 400 || calls != before {
				t.Fatal("removal path injection", path, w.Code)
			}
		}
		for _, body := range []string{`{}`, strings.Replace(retainBody, `incomplete_snapshot":true`, `incomplete_snapshot":false`, 1), strings.Replace(retainBody, strings.Repeat("a", 64), "invalid", 1), strings.Replace(retainBody, `"snapshot_missing":false`, `"snapshot_missing":true`, 1), strings.TrimSuffix(retainBody, "}") + `,"path":"/private"}`, retainBody + ` {}`} {
			if w := request("POST", base+"archives/"+archiveID+"/retain", body, auth.CSRF, cookie); w.Code != 400 || calls != before {
				t.Fatal("unclosed retention", body, w.Code)
			}
		}
		for _, path := range []string{"archives/not-an-id/retain", "archives/" + archiveID + "/retain?path=/private"} {
			if w := request("POST", base+path, retainBody, auth.CSRF, cookie); w.Code != 400 || calls != before {
				t.Fatal("retention path injection", w.Code)
			}
		}
		for _, body := range []string{`{}`, strings.Replace(indexBody, "true", "false", 1), strings.Replace(indexBody, strings.Repeat("c", 64), "bad", 1), strings.Replace(indexBody, strings.Repeat("c", 64), strings.Repeat("C", 64), 1), strings.TrimSuffix(indexBody, "}") + `,"path":"/etc/passwd"}`, indexBody + ` {}`} {
			if w := request("POST", base+"index-stages/"+archiveID+"/retain", body, auth.CSRF, cookie); w.Code != 400 || calls != before {
				t.Fatal("unclosed index recovery", w.Code, w.Body.String())
			}
		}
		for _, path := range []string{"index-stages/not-an-id/retain", "index-stages/" + archiveID + "/retain?path=/private"} {
			if w := request("POST", base+path, indexBody, auth.CSRF, cookie); w.Code != 400 || calls != before {
				t.Fatal("index path injection", w.Code)
			}
		}
		for _, path := range []string{"archives?path=/private", "archives/not-an-id", "rotate?unit=nginx"} {
			method := "GET"
			body := ""
			if strings.HasPrefix(path, "rotate") {
				method = "POST"
				body = "{}"
			}
			if w := request(method, base+path, body, auth.CSRF, cookie); w.Code != 400 || calls != before {
				t.Fatal("path injection", path, w.Code)
			}
		}
		if w := request("GET", base+"archives", "", auth.CSRF, cookie); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if w := request("GET", base+"archives/"+ID(), "", auth.CSRF, cookie); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if w := request("POST", base+"rotate", "{}", auth.CSRF, cookie); w.Code != 200 || calls != before+3 {
			t.Fatal("closed authorized rotation", w.Code, w.Body.String())
		}
		if w := request("POST", base+"archives/"+archiveID+"/remove", removeBody, auth.CSRF, cookie); w.Code != 200 || calls != before+4 {
			t.Fatal("closed authorized removal", w.Code, w.Body.String())
		}
		if w := request("POST", base+"archives/"+archiveID+"/retain", retainBody, auth.CSRF, cookie); w.Code != 200 || calls != before+5 {
			t.Fatal("closed retention", w.Code, w.Body.String())
		}
		if w := request("POST", base+"index-stages/"+archiveID+"/retain", indexBody, auth.CSRF, cookie); w.Code != 200 || calls != before+6 {
			t.Fatal("closed index recovery", w.Code, w.Body.String())
		}
		if w := request("GET", base+"rotation", "", auth.CSRF, cookie); w.Code != 200 || calls != before+7 {
			t.Fatal("authorized automatic rotation status", w.Code)
		}
		if w := request("POST", base+"rotation/retain", rotationBody, auth.CSRF, cookie); w.Code != 200 || calls != before+8 {
			t.Fatal("authorized automatic rotation retention", w.Code, w.Body.String())
		}
	}
	var audits int
	if err := s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='waf.body-log.rotate'").Scan(&audits); err != nil || audits != 1 {
		t.Fatal("missing scoped audit", audits, err)
	}
	if err := s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='waf.body-log.remove'").Scan(&audits); err != nil || audits != 1 {
		t.Fatal("missing removal audit", audits, err)
	}
	if err := s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='waf.body-log.retain'").Scan(&audits); err != nil || audits != 1 {
		t.Fatal("missing retention audit", audits, err)
	}
	if err := s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='waf.body-log.index-retain'").Scan(&audits); err != nil || audits != 1 {
		t.Fatal("missing index recovery audit", audits, err)
	}
	if err := s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='waf.body-log.rotation-retain'").Scan(&audits); err != nil || audits != 1 {
		t.Fatal("missing automatic rotation audit", audits, err)
	}
}
