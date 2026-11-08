package core

import (
	"encoding/json"
	"io"
	"local/panel/internal/appcatalog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRemoteUnpublishedCopyInputCannotBorrowCopySourceOrUnknownFields(t *testing.T) {
	id, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	base := `{"remote_target_id":"owned-target","expected_revision":7,"resource_id":"` + id + `","expected_sha":"` + sha + `","confirm":"RETAIN FRAGMENTS ` + id + `"}`
	if in, err := DecodeRemoteIndependentInput("retain-remote-copy-fragments", []byte(base)); err != nil || in.ExpectedSHA != sha || in.ResourceID != id {
		t.Fatal(in, err)
	}
	for name, body := range map[string]string{
		"old copy authority":      strings.Replace(base, "RETAIN FRAGMENTS ", "COPY BACKUP ", 1),
		"old retention authority": strings.Replace(base, "RETAIN FRAGMENTS ", "RETAIN COPY ", 1),
		"duplicate revision":      strings.Replace(base, `"expected_revision":7`, `"expected_revision":6,"expected_revision":7`, 1),
		"escaped key":             strings.Replace(base, `resource_id`, `resource\u005fid`, 1),
		"unreviewed source path":  strings.TrimSuffix(base, "}") + `,"path":"/tmp/other"}`,
		"unknown source":          strings.TrimSuffix(base, "}") + `,"source_snapshot_sha256":"` + sha + `"}`,
		"null confirmation":       strings.Replace(base, `"confirm":"RETAIN FRAGMENTS `+id+`"`, `"confirm":null`, 1),
		"mutation pagination":     strings.TrimSuffix(base, "}") + `,"limit":16}`,
		"short digest":            strings.Replace(base, sha, "short", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRemoteIndependentInput("retain-remote-copy-fragments", []byte(body)); err == nil {
				t.Fatal("unbound fragment retention input accepted")
			}
		})
	}
	read := `{"remote_target_id":"owned-target","expected_revision":7,"limit":16,"offset":0}`
	if _, err := DecodeRemoteIndependentInput("remote-copy-fragments", []byte(read)); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRemoteIndependentInput("remote-copy-fragments", []byte(base)); err == nil {
		t.Fatal("read-only fragment inventory accepted mutation authority")
	}
	if _, err := DecodeRemoteIndependentInput("copy-remote-backup", []byte(base)); err == nil {
		t.Fatal("fragment retention authorized a source copy")
	}
}

func TestRemoteUnpublishedCopyHTTPRequiresExact201AndFullAdministrator(t *testing.T) {
	s := testStore(t)
	admin := accessUser(t, s, "fragment-master", "", nil)
	limited := accessUser(t, s, "fragment-limited", "admin", []string{"overview", "system-tools"})
	viewer := accessUser(t, s, "fragment-viewer", "viewer", nil)
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	version := appcatalog.FilesSyncUnpublishedRetentionVersion
	calls, posts := 0, 0
	lastPath, lastBody := "", ""
	revoke := false
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		lastPath = r.URL.Path
		body := `{}`
		if r.URL.Path == "/v1/app-modules/files-sync" {
			raw, _ := json.Marshal(map[string]any{"status": SoftwareAppStatus{ID: "files-sync", Installed: true, Version: version}})
			body = string(raw)
		}
		if r.Method == "POST" {
			posts++
			raw, _ := io.ReadAll(r.Body)
			lastBody = string(raw)
			body = `{"private_result":"original-fragment-observation"}`
			if revoke {
				if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?, '[]', 1)", admin.ID); err != nil {
					t.Fatal(err)
				}
			}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	request := func(path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
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
	login := func(name string) (*http.Cookie, string) {
		w := request("/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", nil)
		var session accountSession
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &session) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return w.Result().Cookies()[0], session.CSRF
	}
	id, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	for _, action := range []string{"remote-copy-fragments", "retain-remote-copy-fragments"} {
		t.Run(action, func(t *testing.T) {
			body := `{"remote_target_id":"owned-target","expected_revision":7,"limit":16,"offset":0}`
			if action == "retain-remote-copy-fragments" {
				body = `{"remote_target_id":"owned-target","expected_revision":7,"resource_id":"` + id + `","expected_sha":"` + sha + `","confirm":"RETAIN FRAGMENTS ` + id + `"}`
			}
			path := "/api/app-modules/files-sync/" + action
			for _, user := range []identity{limited, viewer} {
				cookie, csrf := login(user.Username)
				before := calls
				w := request(path, body, csrf, cookie)
				if w.Code != 403 || calls != before {
					t.Fatal("partial administrator reached private original fragments", w.Code)
				}
			}
			cookie, csrf := login(admin.Username)
			for _, old := range []string{appcatalog.FilesSyncIndependentBackupVersion, "2.0.1-compat1", "2.0.2"} {
				version = old
				before := posts
				w := request(path, body, csrf, cookie)
				if w.Code != 409 || posts != before {
					t.Fatal("unsupported installed label borrowed201 authority", old, w.Code)
				}
			}
			version = appcatalog.FilesSyncUnpublishedRetentionVersion
			before := calls
			w := request(path, body, "invalid-CSRF", cookie)
			if w.Code != 403 || calls != before {
				t.Fatal("CSRF failed to fence forensic action", w.Code)
			}
			w = request(path, body, csrf, cookie)
			if w.Code != 200 || lastPath != "/v1/app-modules/files-sync/"+action || lastBody != body {
				t.Fatal("fixed request changed during dispatch", w.Code, lastPath, lastBody)
			}
			revoke = true
			w = request(path, body, csrf, cookie)
			if w.Code != 403 || strings.Contains(w.Body.String(), "original-fragment-observation") {
				t.Fatal("withdrawn administrator received private original observation", w.Code, w.Body.String())
			}
			revoke = false
			if _, err := s.DB.Exec("DELETE FROM app_user_menus WHERE user_id=?", admin.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}
