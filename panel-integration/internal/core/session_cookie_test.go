package core

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestSessionCookieSharedHostPortIsolationAndLogout(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	servers := []*Server{}
	urls := []string{}
	sessions := []accountSession{}
	for _, name := range []string{"cookie-first", "cookie-second"} {
		s := testStore(t)
		accessUser(t, s, name, "admin", nil)
		a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Socket: "/missing"})
		if err != nil {
			t.Fatal(err)
		}
		httpServer := httptest.NewServer(a)
		t.Cleanup(httpServer.Close)
		a.Config.Origin = httpServer.URL
		servers = append(servers, a)
		urls = append(urls, httpServer.URL)
	}
	call := func(base, path, method string, body []byte, csrf string) (int, []byte, []*http.Cookie) {
		r, _ := http.NewRequest(method, base+path, bytes.NewReader(body))
		r.Header.Set("Origin", base)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, data, response.Cookies()
	}
	for i, base := range urls {
		name := []string{"cookie-first", "cookie-second"}[i]
		status, body, cookies := call(base, "/api/login", "POST", []byte(`{"username":"`+name+`","password":"access-test-password-long"}`), "")
		if status != 200 || len(cookies) != 1 || cookies[0].Name != servers[i].sessionCookieName() || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Domain != "" || cookies[0].Path != "/" {
			t.Fatal("unsafe login cookie", status)
		}
		var session accountSession
		if json.Unmarshal(body, &session) != nil {
			t.Fatal("login decode")
		}
		sessions = append(sessions, session)
	}
	if servers[0].sessionCookieName() == servers[1].sessionCookieName() {
		t.Fatal("different installations share a cookie name")
	}
	for _, base := range urls {
		parsed, _ := url.Parse(base)
		if len(jar.Cookies(parsed)) != 2 {
			t.Fatal("test jar must reproduce cross-port sharing")
		}
		if status, _, _ := call(base, "/api/me", "GET", nil, ""); status != 200 {
			t.Fatal("parallel login invalidated", status)
		}
	}
	if status, _, _ := call(urls[1], "/api/logout", "POST", []byte(`{}`), "wrong"); status != 403 {
		t.Fatal("namespace change bypassed CSRF", status)
	}
	if status, _, cookies := call(urls[0], "/api/logout", "POST", []byte(`{}`), sessions[0].CSRF); status != 200 || len(cookies) != 1 || cookies[0].Name != servers[0].sessionCookieName() || cookies[0].MaxAge != -1 {
		t.Fatal("wrong cookie cleared", status)
	}
	if status, _, _ := call(urls[0], "/api/me", "GET", nil, ""); status != 401 {
		t.Fatal("logged-out cookie authorized", status)
	}
	if status, _, _ := call(urls[1], "/api/me", "GET", nil, ""); status != 200 {
		t.Fatal("logout changed the other installation", status)
	}
}

func TestSessionCookieLegacyMigrationExpiryAndFailClosed(t *testing.T) {
	s := testStore(t)
	user := accessUser(t, s, "cookie-migrate", "admin", nil)
	config := Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"}
	a, err := NewServer(s, config)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewServer(s, Config{DataDir: config.DataDir, WebDir: config.WebDir, Origin: "https://new-origin.example", Socket: "/missing"})
	if err != nil || a.sessionCookieName() != b.sessionCookieName() {
		t.Fatal("namespace changed on restart/origin change", err)
	}
	token, csrf := Token(), Token()
	expires := time.Now().Add(5 * time.Minute).Unix()
	if _, err = s.DB.Exec(`INSERT INTO sessions VALUES(?,?,?,?,?)`, Hash(token), user.ID, csrf, expires, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	request := func(cookies []*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/me", nil)
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	legacy := &http.Cookie{Name: "panel_session", Value: token}
	current := &http.Cookie{Name: a.sessionCookieName(), Value: token}
	w := request([]*http.Cookie{legacy})
	cookies := w.Result().Cookies()
	if w.Code != 200 || len(cookies) != 1 || cookies[0].Name != current.Name || cookies[0].Value != token || cookies[0].MaxAge < 295 || cookies[0].MaxAge > 300 {
		t.Fatal("legacy migration changed token/lifetime", w.Code)
	}
	var after int64
	_ = s.DB.QueryRow(`SELECT expires_at FROM sessions WHERE token_hash=?`, Hash(token)).Scan(&after)
	if after != expires {
		t.Fatal("migration renewed server absolute expiry")
	}
	for _, input := range [][]*http.Cookie{{legacy, {Name: current.Name, Value: "invalid"}}, {legacy, {Name: current.Name, Value: ""}}, {current, current}, {legacy, legacy}} {
		if w = request(input); w.Code != 401 || len(w.Result().Cookies()) != 0 {
			t.Fatal("ambiguous/new-invalid fallback accepted", w.Code)
		}
	}
	if w = request([]*http.Cookie{current, legacy, legacy}); w.Code != 200 || len(w.Result().Cookies()) != 0 {
		t.Fatal("unrelated old cookie blocked current authenticated session", w.Code)
	}
	if w = request([]*http.Cookie{{Name: "panel_session", Value: Token()}}); w.Code != 401 || len(w.Result().Cookies()) != 0 {
		t.Fatal("foreign legacy token migrated", w.Code)
	}
	_, _ = s.DB.Exec(`UPDATE sessions SET expires_at=? WHERE token_hash=?`, time.Now().Add(-time.Second).Unix(), Hash(token))
	if w = request([]*http.Cookie{legacy}); w.Code != 401 || len(w.Result().Cookies()) != 0 {
		t.Fatal("expired legacy session migrated", w.Code)
	}
	secure := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://example.test", nil)
	a.cookie(secure, r, token, 300)
	if cookies := secure.Result().Cookies(); len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatal("HTTPS cookie protection lost")
	}
}
