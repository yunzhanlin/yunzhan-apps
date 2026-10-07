package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSiteArchiveNativePreflightBeforeQueueAndArchivedReplay(t *testing.T) {
	s := testStore(t)
	accessUser(t, s, "admin", "admin", nil)
	site := settingsSite(t, s, "archive-preflight")
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, csrf, key string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := request("POST", "/api/login", `{"username":"admin","password":"access-test-password-long"}`, "", "", nil)
	if login.Code != 200 {
		t.Fatal(login.Body.String())
	}
	var auth accountSession
	json.Unmarshal(login.Body.Bytes(), &auth)
	cookie := login.Result().Cookies()[0]
	response := `{"error":"网站仍被防火墙策略引用"}`
	code := 409
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/v1/sites/"+site.ID+"/archive-check" || r.URL.RawQuery != "" {
			t.Fatal("unsafe preflight", r.URL)
		}
		return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response))}, nil
	})}}
	path := "/api/sites/" + site.ID
	body := `{"confirm_domain":"` + site.Domain + `"}`
	assertNoJob := func() {
		t.Helper()
		var count int
		s.DB.QueryRow("SELECT count(*) FROM jobs WHERE kind='archive_site'").Scan(&count)
		current, _ := s.Site(site.ID)
		if count != 0 || current.Status != "running" {
			t.Fatal("known preflight rejection mutated site/queue", count, current.Status)
		}
	}
	if w := request("DELETE", path, body, "", "archive-key", cookie); w.Code != 403 || calls != 0 {
		t.Fatal("CSRF bypass", w.Code)
	}
	if w := request("DELETE", path, `{"confirm_domain":"wrong.example.test"}`, auth.CSRF, "archive-key", cookie); w.Code != 409 || calls != 0 {
		t.Fatal("wrong domain invoked root", w.Code)
	}
	if w := request("DELETE", path, body, auth.CSRF, "archive-key", cookie); w.Code != 409 || calls != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	assertNoJob()
	code = 200
	for _, bad := range []string{`{}`, `{"site_id":"` + ID() + `","waf_reference_clear":true,"no_site_files_changed":true}`, `{"site_id":"` + site.ID + `","waf_reference_clear":false,"no_site_files_changed":true}`} {
		response = bad
		if w := request("DELETE", path, body, auth.CSRF, "archive-key", cookie); w.Code != 409 {
			t.Fatal("unconfirmed preflight accepted", w.Code)
		}
		assertNoJob()
	}
	response = `{"site_id":"` + site.ID + `","waf_reference_clear":true,"no_site_files_changed":true}`
	w := request("DELETE", path, body, auth.CSRF, "archive-key", cookie)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var queued map[string]string
	json.Unmarshal(w.Body.Bytes(), &queued)
	job, err := s.NextJob()
	if err != nil || job.ID != queued["job_id"] {
		t.Fatal(job, err)
	}
	if err := s.Finish(job, "archived", "", nil); err != nil {
		t.Fatal(err)
	}
	before := calls
	replay := request("DELETE", path, body, auth.CSRF, "archive-key", cookie)
	var again map[string]string
	json.Unmarshal(replay.Body.Bytes(), &again)
	if replay.Code != 202 || again["job_id"] != job.ID || calls != before {
		t.Fatal("archived exact request replay broken", replay.Code, replay.Body.String())
	}
}

func TestSiteArchiveReleasesAppBindingAndDomainButKeepsAudit(t *testing.T) {
	s := testStore(t)
	project := ID()
	_, e := s.CreateAppProxySite("博客", "archive-blog", "archive.example.test", project, 18480, "create-archive", "admin")
	if e != nil {
		t.Fatal(e)
	}
	create, e := s.NextJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Finish(create, "running", "", nil); e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueSiteArchive(create.SiteID, "wrong.example.test", "archive-one", "admin"); e == nil {
		t.Fatal("wrong confirmation accepted")
	}
	jobID, e := s.QueueSiteArchive(create.SiteID, "archive.example.test", "archive-one", "admin")
	if e != nil {
		t.Fatal(e)
	}
	same, e := s.QueueSiteArchive(create.SiteID, "archive.example.test", "archive-one", "admin")
	if e != nil || same != jobID {
		t.Fatal("archive idempotency failed", e)
	}
	if _, e = s.QueueSiteArchive(create.SiteID, "other.example.test", "archive-one", "admin"); e == nil {
		t.Fatal("changed archive reused key")
	}
	archive, e := s.NextJob()
	if e != nil || archive.ID != jobID {
		t.Fatal("wrong archive job", e)
	}
	if e = s.Finish(archive, "archived", "", nil); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Site(create.SiteID); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("archived site still directly accessible", e)
	}
	visible, e := s.Sites()
	if e != nil || len(visible) != 0 {
		t.Fatal("archived site remained in list", e)
	}
	if name, e := s.ProjectSiteReference(project); e != nil || name != "" {
		t.Fatal("project binding was not released", name, e)
	}
	var original string
	if e = s.DB.QueryRow(`SELECT original_domain FROM site_archives WHERE site_id=?`, create.SiteID).Scan(&original); e != nil || original != "archive.example.test" {
		t.Fatal("original domain not preserved", e)
	}
	if _, e = s.Job(jobID); e != nil {
		t.Fatal("archive job history lost", e)
	}
	if _, e = s.CreateSiteAtDomain("新博客", "archive-blog", "archive.example.test", "reuse-domain", "admin"); e != nil {
		t.Fatal("domain or slug remained reserved", e)
	}
}

func TestSiteArchiveBlocksDependentBackup(t *testing.T) {
	s := testStore(t)
	_, e := s.CreateSite("备份站", "backup-site", "create-backup", "admin")
	if e != nil {
		t.Fatal(e)
	}
	job, e := s.NextJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Finish(job, "running", "", nil); e != nil {
		t.Fatal(e)
	}
	_, e = s.DB.Exec(`INSERT INTO site_backups(id,site_id,format,files,source_bytes,bytes,sha256,created_at) VALUES(?,?,?,?,?,?,?,?)`, ID(), job.SiteID, "zip", 1, 100, 90, Hash("test"), Now())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueSiteArchive(job.SiteID, "backup-site.localhost", "archive-backup", "admin"); e == nil {
		t.Fatal("dependent backup was ignored")
	}
}
