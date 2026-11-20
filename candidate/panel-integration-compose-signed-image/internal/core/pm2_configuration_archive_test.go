package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPM2JournalArchiveInputIsIndependentCanonicalAndBounded(t *testing.T) {
	id, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	base := `{"pm2_installation_id":"` + strings.Repeat("7", 32) + `","pm2_operation_id":"` + id + `","expected_sha":"` + sha + `","confirm":"ARCHIVE PM2 CONFIGURATIONS ` + sha + `"}`
	if _, err := DecodePM2ConfigurationArchiveInput("archive-configurations", []byte(base)); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`null`, `[]`, base + base, strings.TrimSuffix(base, "}"), strings.TrimSuffix(base, "}") + `,"resource_id":""}`, strings.TrimSuffix(base, "}") + `,"password":""}`, strings.Replace(base, `"expected_sha":"`+sha+`"`, `"expected_sha":null`, 1), strings.Replace(base, `"pm2_operation_id":`, `"pm2_operation_id":"`+id+`","pm2_operation_id":`, 1), strings.Replace(base, `"confirm":`, `"confirm":"bad","conf\u0069rm":`, 1), strings.Replace(base, `ARCHIVE PM2 CONFIGURATIONS `, `RECOVER PM2 CONFIG ARCHIVE `, 1)} {
		if _, err := DecodePM2ConfigurationArchiveInput("archive-configurations", []byte(body)); err == nil {
			t.Fatal("ambiguous or unrelated archive input accepted", body)
		}
	}
	for _, bad := range []string{strings.Replace(base, `"pm2_installation_id":"`+strings.Repeat("7", 32)+`",`, "", 1), strings.Replace(base, `"pm2_installation_id":`, `"pm2_installation_id":null,"pm2_installation_id":`, 1)} {
		if _, err := DecodePM2ConfigurationArchiveInput("archive-configurations", []byte(bad)); err == nil {
			t.Fatal("missing or duplicate installation authority accepted")
		}
	}
	for action, phrase := range map[string]string{"recover-configuration-archive": "RECOVER PM2 CONFIG ARCHIVE ", "restore-configuration-archive": "RESTORE PM2 CONFIG ARCHIVE "} {
		body := `{"pm2_installation_id":"` + strings.Repeat("7", 32) + `","pm2_operation_id":"` + id + `","expected_sha":"` + sha + `","confirm":"` + phrase + id + `"}`
		if _, err := DecodePM2ConfigurationArchiveInput(action, []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{"resource_id=owned-project", "limit=33", "limit=01", "offset=513", "limit=1&limit=2", "confirm=anything"} {
		if _, err := ParsePM2ConfigurationArchiveQuery("pm2_installation_id=" + strings.Repeat("7", 32) + "&" + raw); err == nil {
			t.Fatal("unbounded archive read accepted", raw)
		}
	}
	if _, err := ParsePM2ConfigurationArchiveQuery("pm2_installation_id=" + strings.Repeat("7", 32) + "&pm2_operation_id=" + id + "&limit=32&offset=512"); err != nil {
		t.Fatal(err)
	}
}
func TestPM2JournalArchiveHTTPRequiresFullAdminCSRFExactVersionAndRevocation(t *testing.T) {
	s := testStore(t)
	admin := accessUser(t, s, "pm2-archive-master", "admin", nil)
	limited := accessUser(t, s, "pm2-archive-limited", "admin", []string{"system-tools"})
	viewer := accessUser(t, s, "pm2-archive-viewer", "viewer", nil)
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	version := PM2ConfigurationArchiveAppVersion
	calls, writes := 0, 0
	revoke := false
	lastBody := ""
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		body := `{"configuration_archives":[],"private_result":"must-not-return-after-revocation"}`
		if r.URL.Path == "/v1/app-modules/pm2-manager" {
			raw, _ := json.Marshal(map[string]any{"status": SoftwareAppStatus{ID: "pm2-manager", Installed: true, Version: version, InstallationID: strings.Repeat("7", 32)}})
			body = string(raw)
		} else {
			if r.Method == "POST" {
				writes++
				raw, _ := io.ReadAll(r.Body)
				lastBody = string(raw)
			}
			if revoke {
				if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?, '[]', 1)", admin.ID); err != nil {
					t.Fatal(err)
				}
			}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	request := func(method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := func(name string) (*http.Cookie, string) {
		w := request("POST", "/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", nil)
		var out accountSession
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return w.Result().Cookies()[0], out.CSRF
	}
	id, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	body := `{"pm2_installation_id":"` + strings.Repeat("7", 32) + `","pm2_operation_id":"` + id + `","expected_sha":"` + sha + `","confirm":"ARCHIVE PM2 CONFIGURATIONS ` + sha + `"}`
	post := "/api/app-modules/pm2-manager/archive-configurations"
	get := "/api/app-modules/pm2-manager/configuration-archives?pm2_installation_id=" + strings.Repeat("7", 32) + "&limit=32"
	for _, u := range []identity{limited, viewer} {
		cookie, csrf := login(u.Username)
		before := calls
		for _, method := range []string{"GET", "POST"} {
			path := get
			raw := ""
			if method == "POST" {
				path = post
				raw = body
			}
			if w := request(method, path, raw, csrf, cookie); w.Code != 403 || calls != before {
				t.Fatal("partial administrator reached private archive", w.Code, calls, before)
			}
		}
	}
	cookie, csrf := login(admin.Username)
	before := calls
	if w := request("POST", post, body, "wrong", cookie); w.Code != 403 || calls != before {
		t.Fatal("archive bypassed CSRF")
	}
	if w := request("POST", post, strings.TrimSuffix(body, "}")+`,"entry":""}`, csrf, cookie); w.Code != 400 || calls != before {
		t.Fatal("unrelated zero-valued field reached executor", w.Code)
	}
	version = "7.0.4-compat11"
	if w := request("POST", post, body, csrf, cookie); w.Code != 409 || writes != 0 {
		t.Fatal("old application borrowed archive authority", w.Code)
	}
	version = PM2ConfigurationArchiveAppVersion
	staleBody := strings.Replace(body, strings.Repeat("7", 32), strings.Repeat("8", 32), 1)
	if w := request("POST", post, staleBody, csrf, cookie); w.Code != 409 || writes != 0 {
		t.Fatal("Core forwarded stale installation authority", w.Code)
	}
	if w := request("POST", post, body, csrf, cookie); w.Code != 200 || writes != 1 || lastBody != body {
		t.Fatal("exact body was not forwarded", w.Code, lastBody)
	}
	if w := request("GET", get, "", csrf, cookie); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("readonly archive response not private", w.Code)
	}
	revoke = true
	if w := request("GET", get, "", csrf, cookie); w.Code != 403 || strings.Contains(w.Body.String(), "must-not-return") {
		t.Fatal("revoked admin received archive data", w.Code)
	}
	if _, err := s.DB.Exec("DELETE FROM app_user_menus WHERE user_id=?", admin.ID); err != nil {
		t.Fatal(err)
	}
	if w := request("POST", post, body, csrf, cookie); w.Code != 403 || strings.Contains(w.Body.String(), "must-not-return") {
		t.Fatal("revoked admin received mutation output", w.Code)
	}
}
