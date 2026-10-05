package core

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, e := OpenStore(filepath.Join(t.TempDir(), "panel.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	return s
}
func TestSiteIdempotencyAndPersistentRecovery(t *testing.T) {
	s := testStore(t)
	j, e := s.CreateSite("测试站点", "test-site", "one-key", "admin")
	if e != nil {
		t.Fatal(e)
	}
	same, e := s.CreateSite("测试站点", "test-site", "one-key", "admin")
	if e != nil || j != same {
		t.Fatalf("idempotency: %q %v", same, e)
	}
	if _, e = s.CreateSite("另一站点", "other-site", "one-key", "admin"); e == nil {
		t.Fatal("key reused for a different payload")
	}
	sites, e := s.Sites()
	if e != nil || len(sites) != 1 {
		t.Fatal("duplicate site", e)
	}
	taken, e := s.NextJob()
	if e != nil {
		t.Fatal(e)
	}
	if taken.ID != j {
		t.Fatal("incorrect job")
	}
	if e = s.Recover(); e != nil {
		t.Fatal(e)
	}
	jobs, e := s.Jobs()
	if e != nil || jobs[0].State != "needs_attention" {
		t.Fatal("interrupted job silently restarted", e)
	}
	if e = s.Retry(j, "admin"); e != nil {
		t.Fatal(e)
	}
	taken, e = s.NextJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Finish(taken, "running", "", []Step{{Now(), "validated"}}); e != nil {
		t.Fatal(e)
	}
	if e = s.Retry(j, "admin"); e == nil {
		t.Fatal("successful job replayed")
	}
	site, e := s.Site(sites[0].ID)
	if e != nil || site.Status != "running" {
		t.Fatal("site state not persisted", e)
	}
}
func TestSiteValidationAndConcurrentAction(t *testing.T) {
	s := testStore(t)
	for _, slug := range []string{"../escape", "ok;id", "ok\nserver{}", "two words", "UPPER", "ab", "-bad", "a/../../etc"} {
		if _, e := s.CreateSite("test", slug, "", "admin"); e == nil {
			t.Fatalf("accepted unsafe slug %q", slug)
		}
	}
	_, e := s.CreateSite("test", "valid-site", "", "admin")
	if e != nil {
		t.Fatal(e)
	}
	j, _ := s.NextJob()
	if e = s.Finish(j, "running", "", nil); e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueSiteAction(j.SiteID, "disable_site", "admin"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueSiteAction(j.SiteID, "enable_site", "admin"); e == nil {
		t.Fatal("conflicting tasks not serialized")
	}
}
func TestHTTPAuthenticationCSRFFlow(t *testing.T) {
	s := testStore(t)
	h, _ := bcrypt.GenerateFromPassword([]byte("test-password-long"), bcrypt.MinCost)
	_, e := s.DB.Exec(`INSERT INTO users VALUES(?,?,?,?)`, ID(), "admin", h, Now())
	if e != nil {
		t.Fatal(e)
	}
	a, e := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing.sock"})
	if e != nil {
		t.Fatal(e)
	}
	request := func(method, path, body, token, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("X-CSRF-Token", token)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/sites", "", "", "", nil); w.Code != 401 {
		t.Fatal("anonymous sites access", w.Code)
	}
	w := request("POST", "/api/login", `{"username":"admin","password":"test-password-long"}`, "", "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var me map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &me)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("cookie not protected")
	}
	cookie := cookies[0]
	body := `{"name":"测试","slug":"http-test"}`
	if w = request("POST", "/api/sites", body, "", "", cookie); w.Code != 403 {
		t.Fatal("missing CSRF accepted", w.Code)
	}
	if w = request("POST", "/api/sites", body, me["csrf"], "https://attacker.invalid", cookie); w.Code != 403 {
		t.Fatal("foreign origin accepted", w.Code)
	}
	if w = request("POST", "/api/sites", body, me["csrf"], "http://127.0.0.1:19100", cookie); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request("POST", "/api/sites", `{"name":"x","slug":"xxx","command":"id"}`, me["csrf"], "", cookie); w.Code != 400 {
		t.Fatal("unknown command field accepted", w.Code)
	}
	if w = request("POST", "/api/logout", `{}`, me["csrf"], "", cookie); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = request("GET", "/api/me", "", "", "", cookie); w.Code != 401 {
		t.Fatal("revoked session still valid", w.Code)
	}
}

func TestRuntimeJobsAndBindingCommitBoundary(t *testing.T) {
	s := testStore(t)
	r := runtimecatalog.PHP[2]
	if _, e := s.CreateSite("PHP", "php-test", "p1", "admin", r.ID); e == nil {
		t.Fatal("allowed missing runtime")
	}
	if e := s.RecordInstallation(r, "arm64"); e != nil {
		t.Fatal(e)
	}
	install, e := s.QueueInstall(r.ID, "install-1", "admin")
	if e != nil {
		t.Fatal(e)
	}
	same, e := s.QueueInstall(r.ID, "install-1", "admin")
	if e != nil || same != install {
		t.Fatal("install idempotency failed")
	}
	if _, e = s.QueueInstall(runtimecatalog.PHP[0].ID, "install-1", "admin"); e == nil {
		t.Fatal("accepted changed idempotency payload")
	}
	job, e := s.CreateSite("PHP", "php-test", "p1", "admin", r.ID)
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.NextJob()
	if e != nil || j.ID != job {
		t.Fatal(e)
	}
	if e = s.Finish(j, "running", "", []Step{}); e != nil {
		t.Fatal(e)
	}
	site, e := s.Site(j.SiteID)
	if e != nil || site.PHPVersionID != r.ID || site.RuntimeInstanceID == "static" {
		t.Fatal("binding missing", site, e)
	}
	var socket string
	if e = s.DB.QueryRow(`SELECT socket_path FROM runtime_instances WHERE id=?`, site.RuntimeInstanceID).Scan(&socket); e != nil || !strings.Contains(socket, r.ID) {
		t.Fatal("socket not version isolated", socket, e)
	}
	if _, e = s.QueuePHP(site.ID, "", "admin"); e != nil {
		t.Fatal(e)
	}
	switchJob, _ := s.NextJob()
	if e = s.Finish(switchJob, "needs_attention", "candidate probe failed", []Step{}); e != nil {
		t.Fatal(e)
	}
	site, _ = s.Site(site.ID)
	if site.PHPVersionID != r.ID {
		t.Fatal("failed switch changed binding")
	}
	runtimeJob, e := s.NextRuntimeJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Recover(); e != nil {
		t.Fatal(e)
	}
	recovered, e := s.NextRuntimeJob()
	if e != nil || recovered.ID != runtimeJob.ID {
		t.Fatal("runtime job not resumed")
	}
	if e = s.FinishRuntime(recovered, "", []Step{{Time: Now(), Message: "verified"}}); e != nil {
		t.Fatal(e)
	}
	all, e := s.Jobs()
	if e != nil || len(all) != 3 {
		t.Fatal("combined job listing", len(all), e)
	}
}
