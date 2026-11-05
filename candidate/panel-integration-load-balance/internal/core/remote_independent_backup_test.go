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

func TestRemoteIndependentBackupInputRejectsAmbiguousOrUnrelatedAuthority(t *testing.T) {
	id, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	base := `{"remote_target_id":"owned-target","expected_revision":7,"resource_id":"` + id + `","expected_sha":"` + sha + `","confirm":"COPY BACKUP ` + id + `"}`
	if in, err := DecodeRemoteIndependentInput("copy-remote-backup", []byte(base)); err != nil || in.ResourceID != id || in.ExpectedRevision != 7 || in.ExpectedSHA != sha {
		t.Fatal(in, err)
	}
	for name, body := range map[string]string{
		"duplicate target":     strings.Replace(base, `"remote_target_id":"owned-target"`, `"remote_target_id":"other-target","remote_target_id":"owned-target"`, 1),
		"escaped key":          strings.Replace(base, `remote_target_id`, `remote\u005ftarget_id`, 1),
		"alias key":            strings.Replace(base, `remote_target_id`, `Remote_Target_Id`, 1),
		"null":                 strings.Replace(base, `"expected_revision":7`, `"expected_revision":null`, 1),
		"coerced integer":      strings.Replace(base, `"expected_revision":7`, `"expected_revision":7.0`, 1),
		"missing confirmation": strings.Replace(base, `COPY BACKUP `, ``, 1),
		"extra source path":    strings.TrimSuffix(base, "}") + `,"path":"/root/secret"}`,
		"credentials":          strings.TrimSuffix(base, "}") + `,"password":"never-authorized"}`,
		"duplicate object":     base + base,
		"partial":              strings.TrimSuffix(base, "}"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRemoteIndependentInput("copy-remote-backup", []byte(body)); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	read := `{"remote_target_id":"owned-target","expected_revision":7,"resource_id":"` + id + `"}`
	if _, err := DecodeRemoteIndependentInput("verify-remote-copy", []byte(read)); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRemoteIndependentInput("verify-remote-copy", []byte(base)); err == nil {
		t.Fatal("read borrowed mutation authority")
	}
	for _, v := range []string{"2.0.0-compat1", "2.0.1", "bad"} {
		if ValidateSoftwareUpdate("files-sync", v) == nil {
			t.Fatal("unimplemented version", v)
		}
	}
	for _, v := range []string{"1.9.0", appcatalog.FilesSyncIndependentBackupVersion} {
		if err := ValidateSoftwareUpdate("files-sync", v); err != nil {
			t.Fatal(err)
		}
	}
}
func TestRemoteIndependentBackupChunkBindsTheWholeFileAndSelectedPart(t *testing.T) {
	id, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	v := RemoteIndependentChunk{Target: "owned-target", Transaction: id, Name: "staged", IntentSHA: sha, FileSHA: Hash("old"), FileBytes: 3, Part: 0, Bytes: []byte("old"), ChunkSHA: Hash("old")}
	if err := ValidateRemoteIndependentChunk(v, v.Target, id, v.Name, 0, sha); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*RemoteIndependentChunk){
		"other target":    func(v *RemoteIndependentChunk) { v.Target = "other-target" },
		"other file":      func(v *RemoteIndependentChunk) { v.Name = "previous" },
		"other intent":    func(v *RemoteIndependentChunk) { v.IntentSHA = strings.Repeat("c", 64) },
		"wrong part":      func(v *RemoteIndependentChunk) { v.Part = 1 },
		"short data":      func(v *RemoteIndependentChunk) { v.Bytes = []byte("ol") },
		"wrong content":   func(v *RemoteIndependentChunk) { v.Bytes = []byte("bad") },
		"covert mutation": func(v *RemoteIndependentChunk) { v.FilesChanged = true },
		"unbounded":       func(v *RemoteIndependentChunk) { v.FileBytes = RemoteCopyFileBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := v
			change(&bad)
			if ValidateRemoteIndependentChunk(bad, v.Target, id, v.Name, 0, sha) == nil {
				t.Fatal("unbound bytes accepted")
			}
		})
	}
	for _, part := range []string{"-1", "00", "32", "1.0", ""} {
		if _, err := RemoteIndependentReadPath(v.Target, id, v.Name, part, sha); err == nil {
			t.Fatal("unbounded path", part)
		}
	}
}
func TestRemoteIndependentBackupHTTPFullAdministratorAndExactForwarding(t *testing.T) {
	s := testStore(t)
	admin := accessUser(t, s, "copy-master", "", nil)
	limited := accessUser(t, s, "copy-limited", "admin", []string{"overview", "system-tools"})
	viewer := accessUser(t, s, "copy-viewer", "viewer", nil)
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	id, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	copyBody := `{"remote_target_id":"owned-target","expected_revision":7,"resource_id":"` + id + `","expected_sha":"` + sha + `","confirm":"COPY BACKUP ` + id + `"}`
	readPath := "/api/app-modules/files-sync/independent-backups/owned-target/" + id + "/staged/chunks/0?sha=" + sha
	calls := 0
	lastPath, lastBody := "", ""
	installedVersion := appcatalog.FilesSyncIndependentBackupVersion
	revoke := false
	revokePost := false
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		lastPath = r.URL.RequestURI()
		body := `{}`
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			lastBody = string(raw)
		}
		if r.URL.Path == "/v1/app-modules/files-sync" {
			raw, _ := json.Marshal(map[string]any{"status": SoftwareAppStatus{ID: "files-sync", Installed: true, Version: installedVersion}})
			body = string(raw)
		}
		if strings.Contains(r.URL.Path, "/chunks/") {
			if revoke {
				if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?, '[]', 1)", admin.ID); err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := json.Marshal(RemoteIndependentChunk{Target: "owned-target", Transaction: id, Name: "staged", IntentSHA: sha, FileSHA: Hash("old"), FileBytes: 3, Part: 0, Bytes: []byte("old"), ChunkSHA: Hash("old")})
			body = string(raw)
		}
		if revokePost && r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/copy-remote-backup") {
			if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?, '[]', 1)", admin.ID); err != nil {
				t.Fatal(err)
			}
			body = `{"independent_backup":{"private_result":"must-not-be-returned"}}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
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
	login := func(username string) (*http.Cookie, string) {
		w := request("POST", "/api/login", `{"username":"`+username+`","password":"access-test-password-long"}`, "", nil)
		var out accountSession
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return w.Result().Cookies()[0], out.CSRF
	}
	for _, user := range []identity{limited, viewer} {
		cookie, csrf := login(user.Username)
		before := calls
		for _, op := range []struct{ method, path, body string }{{"GET", readPath, ""}, {"POST", "/api/app-modules/files-sync/copy-remote-backup", copyBody}} {
			w := request(op.method, op.path, op.body, csrf, cookie)
			if w.Code != 403 || calls != before {
				t.Fatal("private request forwarded for partial authorization", w.Code, calls, before)
			}
		}
	}
	cookie, csrf := login(admin.Username)
	w := request("POST", "/api/app-modules/files-sync/copy-remote-backup", copyBody, csrf, cookie)
	if w.Code != 200 || lastPath != "/v1/app-modules/files-sync/copy-remote-backup" || lastBody != copyBody {
		t.Fatal("closed input changed during forwarding", w.Code, lastPath, lastBody)
	}
	w = request("GET", readPath, "", csrf, cookie)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), `"data":"b2xk"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	before := calls
	w = request("POST", "/api/app-modules/files-sync/copy-remote-backup", copyBody, "wrong", cookie)
	if w.Code != 403 || calls != before {
		t.Fatal("CSRF failed to fence copy", w.Code)
	}
	installedVersion = "1.9.0"
	before = calls
	w = request("POST", "/api/app-modules/files-sync/copy-remote-backup", copyBody, csrf, cookie)
	if w.Code != 409 || calls != before+1 {
		t.Fatal("old installation borrowed new operation", w.Code)
	}
	installedVersion = appcatalog.FilesSyncIndependentBackupVersion
	revoke = true
	w = request("GET", readPath, "", csrf, cookie)
	if w.Code != 403 || strings.Contains(w.Body.String(), `"data"`) {
		t.Fatal("revoked administrator received private data", w.Code, w.Body.String())
	}
	if _, err := s.DB.Exec("DELETE FROM app_user_menus WHERE user_id=?", admin.ID); err != nil {
		t.Fatal(err)
	}
	revoke = false
	revokePost = true
	w = request("POST", "/api/app-modules/files-sync/copy-remote-backup", copyBody, csrf, cookie)
	if w.Code != 403 || strings.Contains(w.Body.String(), "must-not-be-returned") {
		t.Fatal("revoked administrator received private mutation result", w.Code, w.Body.String())
	}
}
