package core

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionIdleExpiryAndPolicyRevision(t *testing.T) {
	s := testStore(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password-long"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO users VALUES(?,?,?,?)`, ID(), "admin", hash, Now()); err != nil {
		t.Fatal(err)
	}
	key, err := s.accountKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	session, err := s.authenticateAccount("admin", "test-password-long", "", key, now)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := s.GetSessionPolicy()
	if err != nil || policy.IdleMinutes != defaultSessionIdleMinutes {
		t.Fatal("default session idle policy", policy, err)
	}
	token := Hash(session.Token)
	if _, err = s.sessionIdentity(token, now.Add(29*time.Minute)); err != nil {
		t.Fatal("active session expired early", err)
	}
	if _, err = s.sessionIdentity(token, now.Add(30*time.Minute)); err == nil {
		t.Fatal("idle session survived configured timeout")
	}
	if err = s.touchSession(token, now.Add(29*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.sessionIdentity(token, now.Add(58*time.Minute)); err != nil {
		t.Fatal("real activity did not renew idle window", err)
	}
	if _, err = s.sessionIdentity(token, now.Add(12*time.Hour)); err == nil {
		t.Fatal("activity extended the absolute 12-hour limit")
	}
	for _, minutes := range []int{4, 241} {
		if _, err = s.UpdateSessionPolicy(minutes, policy.Revision, "admin"); err == nil {
			t.Fatalf("invalid idle minutes %d accepted", minutes)
		}
	}
	updated, err := s.UpdateSessionPolicy(5, policy.Revision, "admin")
	if err != nil || updated.Revision != policy.Revision+1 || updated.IdleMinutes != 5 {
		t.Fatal("policy did not persist", updated, err)
	}
	if _, err = s.UpdateSessionPolicy(60, policy.Revision, "admin"); err == nil {
		t.Fatal("stale policy revision accepted")
	}
	if _, err = s.sessionIdentity(token, now.Add(35*time.Minute)); err == nil {
		t.Fatal("new shorter policy did not apply to existing session")
	}
}

func TestSessionActivityEndpointIgnoresBackgroundReadsAndBadCSRF(t *testing.T) {
	s := testStore(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password-long"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO users VALUES(?,?,?,?)`, ID(), "admin", hash, Now()); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing.sock"})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:19100")
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		return w
	}
	login := request("POST", "/api/login", `{"username":"admin","password":"test-password-long"}`, "", nil)
	if login.Code != 200 {
		t.Fatal(login.Code, login.Body.String())
	}
	var session accountSession
	if err = json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	cookie := login.Result().Cookies()[0]
	old := time.Now().Unix() - 29*60
	if _, err = s.DB.Exec(`UPDATE sessions SET last_activity_at=? WHERE token_hash=?`, old, Hash(cookie.Value)); err != nil {
		t.Fatal(err)
	}
	if got := request("GET", "/api/me", "", "", cookie); got.Code != 200 {
		t.Fatal("recent session rejected", got.Code)
	}
	var touched int64
	if err = s.DB.QueryRow(`SELECT last_activity_at FROM sessions WHERE token_hash=?`, Hash(cookie.Value)).Scan(&touched); err != nil || touched != old {
		t.Fatal("background GET renewed idle timeout", touched, err)
	}
	if got := request("POST", "/api/session/activity", `{}`, "wrong", cookie); got.Code != 403 {
		t.Fatal("bad CSRF renewed session", got.Code)
	}
	if err = s.DB.QueryRow(`SELECT last_activity_at FROM sessions WHERE token_hash=?`, Hash(cookie.Value)).Scan(&touched); err != nil || touched != old {
		t.Fatal("bad CSRF changed last activity", touched, err)
	}
	if got := request("POST", "/api/session/activity", `{}`, session.CSRF, cookie); got.Code != 200 {
		t.Fatal("real activity rejected", got.Code, got.Body.String())
	}
	if err = s.DB.QueryRow(`SELECT last_activity_at FROM sessions WHERE token_hash=?`, Hash(cookie.Value)).Scan(&touched); err != nil || touched <= old {
		t.Fatal("real activity failed to renew session", touched, err)
	}
	policyResponse := request("GET", "/api/session-policy", "", "", cookie)
	if policyResponse.Code != 200 {
		t.Fatal("policy read failed", policyResponse.Code)
	}
	var policy SessionPolicy
	if err = json.Unmarshal(policyResponse.Body.Bytes(), &policy); err != nil {
		t.Fatal(err)
	}
	if got := request("PUT", "/api/session-policy", `{"idle_minutes":5,"revision":1}`, "wrong", cookie); got.Code != 403 {
		t.Fatal("policy accepted wrong CSRF", got.Code)
	}
	if got := request("PUT", "/api/session-policy", `{"idle_minutes":5,"revision":1}`, session.CSRF, cookie); got.Code != 200 {
		t.Fatal("policy save failed", got.Code, got.Body.String())
	}
	if got := request("PUT", "/api/session-policy", `{"idle_minutes":10,"revision":1}`, session.CSRF, cookie); got.Code != 409 {
		t.Fatal("policy accepted stale revision", got.Code)
	}
	policyResponse = request("GET", "/api/session-policy", "", "", cookie)
	if err = json.Unmarshal(policyResponse.Body.Bytes(), &policy); err != nil || policy.IdleMinutes != 5 || policy.Revision != 2 {
		t.Fatal("saved policy not returned", policy, err)
	}
	if _, err = s.DB.Exec(`UPDATE sessions SET last_activity_at=? WHERE token_hash=?`, time.Now().Unix()-31*60, Hash(cookie.Value)); err != nil {
		t.Fatal(err)
	}
	if got := request("GET", "/api/me", "", "", cookie); got.Code != 401 {
		t.Fatal("idle session remained authorized", got.Code)
	}
	if got := request("POST", "/api/session/activity", `{}`, session.CSRF, cookie); got.Code != 401 {
		t.Fatal("expired session revived through activity ping", got.Code)
	}
}

func TestSessionPolicyMigrationPreservesActiveLogin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password-long"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO users VALUES(?,?,?,?)`, ID(), "admin", hash, Now()); err != nil {
		t.Fatal(err)
	}
	key, err := s.accountKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.authenticateAccount("admin", "test-password-long", "", key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`DELETE FROM schema_migrations WHERE version=37; DROP TABLE session_policy; ALTER TABLE sessions DROP COLUMN last_activity_at;`); err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	s, err = OpenStore(path)
	if err != nil {
		t.Fatal("migration failed", err)
	}
	defer s.DB.Close()
	if _, err = s.sessionIdentity(Hash(session.Token), time.Now()); err != nil {
		t.Fatal("existing login lost during migration", err)
	}
}
