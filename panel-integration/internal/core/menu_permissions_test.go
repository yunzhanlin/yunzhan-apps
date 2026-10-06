package core

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func accessUser(t *testing.T, s *Store, name, role string, menus []string) identity {
	t.Helper()
	id := ID()
	hash, err := bcrypt.GenerateFromPassword([]byte("access-test-password-long"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("INSERT INTO users VALUES(?,?,?,?)", id, name, hash, Now()); err != nil {
		t.Fatal(err)
	}
	if role != "" {
		if _, err = s.DB.Exec("INSERT INTO app_user_roles VALUES(?,?,'[]')", id, role); err != nil {
			t.Fatal(err)
		}
	}
	if menus != nil {
		raw, _ := json.Marshal(menus)
		if _, err = s.DB.Exec("INSERT INTO app_user_menus VALUES(?,?,1)", id, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	return identity{ID: id, Username: name}
}

func TestMenuDefaultsValidationAndFailClosed(t *testing.T) {
	for _, role := range []string{"admin", "operator", "viewer"} {
		ids, err := normalizeMenuIDs(role, nil)
		want := 4
		if role == "admin" {
			want = 12
		}
		if err != nil || len(ids) != want {
			t.Fatal(role, ids, err)
		}
		empty, err := normalizeMenuIDs(role, []string{})
		if err != nil || empty == nil || len(empty) != 0 {
			t.Fatal("explicit empty is not default", empty, err)
		}
	}
	for _, input := range []struct{ role, raw string }{
		{"root", "null"}, {"admin", `["files","files"]`}, {"admin", `["future"]`},
		{"viewer", `["terminal"]`}, {"operator", `["panel-access"]`},
		{"admin", `{"files":true}`}, {"admin", "["}, {"admin", strings.Repeat(" ", 1025)},
	} {
		if _, err := parseMenuIDs(input.role, input.raw); err == nil {
			t.Fatal("invalid authorization accepted", input)
		}
	}
	s := testStore(t)
	legacy := accessUser(t, s, "legacy", "", nil)
	if got, err := s.UserAccess(legacy.ID); err != nil || !fullAdministrator(got) || got.Revision != 1 {
		t.Fatal("legacy default", got, err)
	}
	if _, err := s.UserAccess(ID()); err == nil {
		t.Fatal("nonexistent user became an administrator")
	}
	if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'invalid',1)", legacy.ID); err != nil {
		t.Fatal(err)
	}
	if (&Server{Store: s}).appRoleAllowed(legacy, httptest.NewRequest("GET", "/api/me", nil)) {
		t.Fatal("corrupt ACL accepted")
	}
	for _, d := range AppModules() {
		if ModuleMenu(d.ID) == "" {
			t.Fatal("unmapped compiled module", d.ID)
		}
	}
}

func TestMenuRouteCeilingAndWebsiteScope(t *testing.T) {
	s := testStore(t)
	a := &Server{Store: s}
	admin := accessUser(t, s, "limited", "admin", []string{"files", "runtimes"})
	viewer := accessUser(t, s, "reader", "viewer", []string{"files"})
	operator := accessUser(t, s, "operator", "operator", []string{"files"})
	site := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, u := range []identity{viewer, operator} {
		if _, err := s.DB.Exec("UPDATE app_user_roles SET site_ids=? WHERE user_id=?", `["`+site+`"]`, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		u            identity
		method, path string
		allow        bool
	}{
		{admin, "GET", "/api/sites", true}, {admin, "POST", "/api/sites", false},
		{admin, "GET", "/api/sites/" + site + "/files", true}, {admin, "GET", "/api/sites/" + site + "/config", false},
		{admin, "GET", "/api/system/files", true}, {admin, "GET", "/api/system/inventory", false},
		{admin, "GET", "/api/software", true}, {admin, "POST", "/api/app-registry/nginx-waf/install", false},
		{admin, "GET", "/api/software/nginx-waf", false}, {admin, "GET", "/api/app-modules/user-manager", false},
		{admin, "GET", "/api/terminal", false}, {admin, "GET", "/api/account", true},
		{admin, "GET", "/api/future-route", false}, {admin, "GET", "/api/sites//" + site + "/files", false},
		{viewer, "GET", "/api/sites", true}, {viewer, "GET", "/api/sites/" + site + "/files", true},
		{viewer, "POST", "/api/sites/" + site + "/files/action", false},
		{viewer, "GET", "/api/sites/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/files", false},
		{viewer, "GET", "/api/overview", false}, {viewer, "GET", "/api/system/files", false},
		{viewer, "POST", "/api/session/activity", true},
		{operator, "POST", "/api/sites/" + site + "/files/action", true},
		{operator, "DELETE", "/api/sites/" + site, false},
		{operator, "POST", "/api/sites/" + site + "/stop", false},
	} {
		if got := a.appRoleAllowed(tc.u, httptest.NewRequest(tc.method, tc.path, nil)); got != tc.allow {
			t.Fatalf("%s %s %s: %v", tc.u.Username, tc.method, tc.path, got)
		}
	}
}

func TestMenuMutationPreservesLegacyAndProtectsLastFullAdmin(t *testing.T) {
	s := testStore(t)
	a := &Server{Store: s}
	master := accessUser(t, s, "master", "", nil)
	limited := accessUser(t, s, "limited", "admin", []string{"panel-access"})
	target := accessUser(t, s, "reader", "viewer", []string{"files"})
	for _, in := range []AppModuleInput{
		{Username: "master", Role: "admin", MenuIDs: []string{"files"}, ExpectedRevision: 1},
		{Username: "master", Role: "viewer", MenuIDs: []string{"files"}, ExpectedRevision: 1},
	} {
		if _, err := a.manageAppUsers(master, "update", in); err == nil {
			t.Fatal("last full administrator restricted")
		}
	}
	if _, err := a.manageAppUsers(limited, "update", AppModuleInput{Username: "master", Role: "admin", MenuIDs: []string{"panel-access"}, ExpectedRevision: 1}); err == nil {
		t.Fatal("limited administrator modified higher authority")
	}
	if _, err := a.manageAppUsers(limited, "create", AppModuleInput{Username: "elevated", Password: "access-test-password-long", Role: "admin", MenuIDs: []string{"terminal"}}); err == nil {
		t.Fatal("administrator granted outside own ceiling")
	}
	if _, err := a.manageAppUsers(master, "update", AppModuleInput{Username: "reader", Role: "viewer", MenuIDs: []string{"overview"}}); err == nil {
		t.Fatal("explicit grants without revision accepted")
	}
	// Existing client omitting menus must preserve a narrowed grant.
	if _, err := a.manageAppUsers(master, "update", AppModuleInput{Username: "reader", Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.UserAccess(target.ID)
	if err != nil || got.Revision != 2 || !reflect.DeepEqual(got.MenuIDs, []string{"files"}) {
		t.Fatal(got, err)
	}
	if _, err := a.manageAppUsers(master, "update", AppModuleInput{Username: "reader", Role: "viewer", MenuIDs: []string{}, ExpectedRevision: 1}); err == nil {
		t.Fatal("stale revision accepted")
	}
	if _, err := a.manageAppUsers(master, "update", AppModuleInput{Username: "reader", Role: "viewer", MenuIDs: []string{}, ExpectedRevision: 2}); err != nil {
		t.Fatal(err)
	}
	got, err = s.UserAccess(target.ID)
	if err != nil || len(got.MenuIDs) != 0 || got.Revision != 3 {
		t.Fatal(got, err)
	}
	// A second valid full administrator permits reduction of the first.
	accessUser(t, s, "rescue", "admin", nil)
	if _, err := a.manageAppUsers(master, "update", AppModuleInput{Username: "master", Role: "admin", MenuIDs: []string{"panel-access"}, ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.manageAppUsers(limited, "delete", AppModuleInput{Username: "rescue"}); err == nil {
		t.Fatal("limited administrator deleted rescue")
	}
}

func TestMenuHTTPChecksEveryRequestAndRevokesLogin(t *testing.T) {
	s := testStore(t)
	master := accessUser(t, s, "master", "", nil)
	target := accessUser(t, s, "reader", "viewer", []string{"files"})
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"status":{"installed":true}}`))}, nil
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
	login := func(name string) (*http.Cookie, string) {
		w := request("POST", "/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var v accountSession
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return w.Result().Cookies()[0], v.CSRF
	}
	cookie, token := login(target.Username)
	if w := request("GET", "/api/me", "", "", cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"menu_ids":["files"]`) {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/software", "/api/overview", "/api/terminal/sessions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "/api/filesystem?path=/", "/api/app-modules/user-manager"} {
		before := calls
		if w := request("GET", path, "", "", cookie); w.Code != 403 || calls != before {
			t.Fatal("unauthorized executor call", path, w.Code, calls-before)
		}
	}
	if w := request("POST", "/api/session/activity", "{}", token, cookie); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	masterCookie, masterToken := login(master.Username)
	update := `{"username":"reader","role":"viewer","menu_ids":[],"expected_revision":1}`
	if w := request("POST", "/api/app-modules/user-manager/update", update, "wrong", masterCookie); w.Code != 403 {
		t.Fatal("CSRF bypass", w.Code)
	}
	if w := request("POST", "/api/app-modules/user-manager/update", update, masterToken, masterCookie); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("GET", "/api/me", "", "", cookie); w.Code != 401 {
		t.Fatal("old session survived menu update", w.Code)
	}
	if w := request("POST", "/api/app-modules/user-manager/update", update, masterToken, masterCookie); w.Code != 409 {
		t.Fatal("stale revision accepted", w.Code)
	}
	cookie, token = login(target.Username)
	if w := request("GET", "/api/sites", "", "", cookie); w.Code != 403 {
		t.Fatal("empty grants accepted", w.Code)
	}
	if w := request("GET", "/api/account", "", "", cookie); w.Code != 200 {
		t.Fatal("self recovery denied", w.Code)
	}
	if w := request("POST", "/api/logout", "{}", token, cookie); w.Code != 200 {
		t.Fatal("self logout denied", w.Code)
	}
}
