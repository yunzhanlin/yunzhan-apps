package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFileSharedInfrastructureCurrentAuthorityAndCancellation(t *testing.T) {
	s := testStore(t)
	a := &Server{Store: s}
	admin := accessUser(t, s, "file-global-admin", "admin", nil)
	limited := accessUser(t, s, "file-limited-admin", "admin", []string{"files", "system-tools"})
	operator := accessUser(t, s, "file-site-operator", "operator", []string{"files"})
	for _, actor := range []identity{limited, operator, {ID: ID()}} {
		if a.fileSharedInfrastructureAllowed(context.Background(), actor) {
			t.Fatal("shared credentials conferred by ordinary file permissions", actor.Username)
		}
	}
	if !a.fileSharedInfrastructureAllowed(context.Background(), admin) {
		t.Fatal("current complete admin denied")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if a.fileSharedInfrastructureAllowed(ctx, admin) {
		t.Fatal("cancelled authority read accepted")
	}
	if _, err := s.DB.Exec(`INSERT INTO app_user_menus VALUES(?, '["files"]', 2)`, admin.ID); err != nil {
		t.Fatal(err)
	}
	if a.fileSharedInfrastructureAllowed(context.Background(), admin) {
		t.Fatal("revoked menus retained global credential authority")
	}
	if _, err := s.DB.Exec(`DELETE FROM users WHERE id=?`, limited.ID); err != nil {
		t.Fatal(err)
	}
	if a.fileSharedInfrastructureAllowed(context.Background(), limited) {
		t.Fatal("deleted account accepted")
	}
}

func TestFileSharedInfrastructureHTTPDoesNotBorrowSitePermissionOrCallerCredentials(t *testing.T) {
	s := testStore(t)
	admin := accessUser(t, s, "file-http-admin", "admin", nil)
	operator := accessUser(t, s, "file-http-operator", "operator", []string{"files"})
	limited := accessUser(t, s, "file-http-limited", "admin", []string{"files"})
	job, err := s.CreateSite("shared profile", "shared-profile", ID(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	var site string
	if err = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, job).Scan(&site); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`UPDATE app_user_roles SET site_ids=? WHERE user_id=?`, `["`+site+`"]`, operator.ID); err != nil {
		t.Fatal(err)
	}
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	// Initialize the ordinary fixture server key before storing its profile;
	// never replace an encryption key after writing credential ciphertext.
	remote, err := s.SaveBackupRemote("", BackupRemoteInput{Name: "file profile", BaseURL: "https://storage.example.test/dav", Username: "stored-owner", Password: "stored-fixture-secret", PathPrefix: "files", Enabled: true}, admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/v1/sites/"+site+"/files/cloud-upload" {
			t.Fatal("unexpected root operation", r.Method, r.URL.Path)
		}
		var in FileCloudUpload
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatal(err)
		}
		if in.Remote.ID != remote.ID || in.Remote.Username != "stored-owner" || in.Password != "stored-fixture-secret" || in.RemoteID != "" || in.Path != "note.txt" {
			t.Fatal("private payload is not exact saved profile")
		}
		return &http.Response{StatusCode: 201, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"remote_path":"https://storage.example.test/dav/files/note.txt","bytes":4,"sha256":"` + Hash("note") + `"}`))}, nil
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
	login := func(actor identity) (*http.Cookie, string) {
		w := request("POST", "/api/login", `{"username":"`+actor.Username+`","password":"access-test-password-long"}`, "", nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var v accountSession
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return w.Result().Cookies()[0], v.CSRF
	}
	cloud := `{"path":"note.txt","remote_id":"` + remote.ID + `"}`
	for _, actor := range []identity{operator, limited} {
		cookie, csrf := login(actor)
		for _, target := range []struct{ method, path, body string }{
			{"POST", "/api/sites/" + site + "/files/cloud-upload", cloud},
			{"POST", "/api/sites/" + site + "/files/shares/send", `{"url_path":"/share/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","recipient":"recipient@example.test"}`},
			{"GET", "/api/mail/smtp", ""}, {"PUT", "/api/mail/smtp", "{}"},
		} {
			w := request(target.method, target.path, target.body, csrf, cookie)
			if w.Code != 403 || calls != 0 {
				t.Fatal("site permission borrowed global credentials", actor.Username, target.path, w.Code, calls)
			}
		}
	}
	cookie, csrf := login(admin)
	for _, field := range []string{`,"password":"caller-secret"`, `,"remote":{"base_url":"https://caller.example.test/"}`} {
		w := request("POST", "/api/sites/"+site+"/files/cloud-upload", strings.TrimSuffix(cloud, "}")+field+"}", csrf, cookie)
		if w.Code != 400 || calls != 0 {
			t.Fatal("caller private fields accepted", w.Code, calls)
		}
	}
	w := request("POST", "/api/sites/"+site+"/files/cloud-upload", cloud, csrf, cookie)
	if w.Code != 201 || calls != 1 || strings.Contains(w.Body.String(), "stored-fixture-secret") || strings.Contains(w.Body.String(), "stored-owner") {
		t.Fatal("ordinary saved-profile handoff or public projection failed", w.Code, calls, w.Body.String())
	}
	if _, err = s.DB.Exec(`INSERT INTO app_user_menus VALUES(?, '["files"]', 2)`, admin.ID); err != nil {
		t.Fatal(err)
	}
	w = request("POST", "/api/sites/"+site+"/files/cloud-upload", cloud, csrf, cookie)
	if w.Code != 403 || calls != 1 {
		t.Fatal("old login retained revoked global authority", w.Code, calls)
	}
}
