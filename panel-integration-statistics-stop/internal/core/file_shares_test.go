package core

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fileShareTransport func(*http.Request) (*http.Response, error)

func (f fileShareTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPublicShareStreamsSnapshotWithoutSession(t *testing.T) {
	s := testStore(t)
	job, e := s.CreateSite("public share", "public-share", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	var siteID string
	if e = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, job).Scan(&siteID); e != nil {
		t.Fatal(e)
	}
	share := FileShare{ID: ID(), SiteID: siteID, Path: "note.txt", Name: "note.txt", Bytes: 8, SHA256: Hash("snapshot"), ExpiresAt: time.Now().Add(time.Hour).Unix(), CreatedAt: Now()}
	token, e := s.createFileShare(share)
	if e != nil {
		t.Fatal(e)
	}
	called := 0
	m := http.NewServeMux()
	a := &Server{Store: s, Executor: &ExecutorClient{Client: &http.Client{Transport: fileShareTransport(func(r *http.Request) (*http.Response, error) {
		called++
		if r.URL.Path != "/v1/sites/"+siteID+"/files/shares/"+share.ID {
			t.Errorf("wrong executor path: %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Length": []string{"8"}}, Body: io.NopCloser(strings.NewReader("snapshot"))}, nil
	})}}, mux: m}
	a.fileShareRoutes(m)
	request := func(token string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", "/share/"+token, nil))
		return w
	}
	w := request(token)
	if w.Code != 200 || w.Body.String() != "snapshot" || w.Header().Get("Content-Disposition") == "" || called != 1 {
		t.Fatal(w.Code, w.Body.String(), called)
	}
	altered := token[:42] + "A"
	if token[42] == 'A' {
		altered = token[:42] + "B"
	}
	if w = request(altered); w.Code != 404 {
		t.Fatal("altered token accepted", w.Code)
	}
	if _, e = s.revokeFileShare(siteID, share.ID); e != nil {
		t.Fatal(e)
	}
	if w = request(token); w.Code != 404 || called != 1 {
		t.Fatal("revoked token streamed", w.Code, called)
	}
}

func TestFileShareTokenExpiryAndRevocation(t *testing.T) {
	s := testStore(t)
	job, e := s.CreateSite("sharing", "sharing-site", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	var siteID string
	if e = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, job).Scan(&siteID); e != nil {
		t.Fatal(e)
	}
	share := FileShare{ID: ID(), SiteID: siteID, Path: "docs/report.txt", Name: "report.txt", Bytes: 9, SHA256: Hash("file"), ExpiresAt: time.Now().Add(time.Hour).Unix(), CreatedAt: Now()}
	token, e := s.createFileShare(share)
	if e != nil || !shareTokenPattern.MatchString(token) {
		t.Fatal("share token creation", e)
	}
	if rows, e := s.listFileShares(siteID); e != nil || len(rows) != 1 || rows[0].Path != share.Path {
		t.Fatal("share list", rows, e)
	}
	got, e := s.fileShareByToken(token)
	if e != nil || got.ID != share.ID {
		t.Fatal("valid share unavailable", e)
	}
	if _, e := s.fileShareByToken("short"); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("invalid token accepted", e)
	}
	altered := token[:42] + "A"
	if token[42] == 'A' {
		altered = token[:42] + "B"
	}
	if _, e := s.fileShareByToken(altered); e == nil {
		t.Fatal("altered token accepted")
	}
	changed, e := s.revokeFileShare(siteID, share.ID)
	if e != nil || !changed {
		t.Fatal("share revoke", e)
	}
	if _, e := s.fileShareByToken(token); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("revoked token remained usable", e)
	}
	if changed, e = s.revokeFileShare(siteID, share.ID); e != nil || !changed {
		t.Fatal("duplicate revoke must permit snapshot cleanup retry", e)
	}
	share.ID = ID()
	share.ExpiresAt = time.Now().Add(time.Hour).Unix()
	token, e = s.createFileShare(share)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE file_shares SET expires_at=? WHERE id=?`, time.Now().Add(-time.Minute).Unix(), share.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.fileShareByToken(token); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("expired token remained usable", e)
	}
}

func TestFileShareActiveLimit(t *testing.T) {
	s := testStore(t)
	job, e := s.CreateSite("limited sharing", "limited-sharing", ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	var siteID string
	if e = s.DB.QueryRow(`SELECT site_id FROM jobs WHERE id=?`, job).Scan(&siteID); e != nil {
		t.Fatal(e)
	}
	item := FileShare{SiteID: siteID, Path: "file.txt", Name: "file.txt", Bytes: 1, SHA256: Hash("x"), ExpiresAt: time.Now().Add(time.Hour).Unix(), CreatedAt: Now()}
	var first string
	for i := 0; i < 20; i++ {
		item.ID = ID()
		if i == 0 {
			first = item.ID
		}
		if _, e = s.createFileShare(item); e != nil {
			t.Fatal(i, e)
		}
	}
	item.ID = ID()
	if _, e = s.createFileShare(item); e == nil {
		t.Fatal("21st active share accepted")
	}
	if _, e = s.revokeFileShare(siteID, first); e != nil {
		t.Fatal(e)
	}
	if _, e = s.createFileShare(item); e != nil {
		t.Fatal("revoke did not free slot", e)
	}
}
