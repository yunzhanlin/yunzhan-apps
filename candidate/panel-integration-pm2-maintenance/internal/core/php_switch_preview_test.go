package core

import (
	"context"
	"encoding/json"
	"io"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func phpSwitchSite(t *testing.T, s *Store) Site {
	t.Helper()
	for _, id := range []string{"php-8.4.25", "php-8.4.27"} {
		r, ok := runtimecatalog.Find(id)
		if !ok {
			t.Fatal(id)
		}
		if err := s.RecordInstallation(r, "amd64"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateSite("PHP switch", "php-switch", ID(), "admin", "php-8.4.25"); err != nil {
		t.Fatal(err)
	}
	j, err := s.NextJob()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Finish(j, "running", "", nil); err != nil {
		t.Fatal(err)
	}
	site, err := s.Site(j.SiteID)
	if err != nil {
		t.Fatal(err)
	}
	return site
}

func TestPHPSwitchDurableConfigPreconditionAndWorkerPreservation(t *testing.T) {
	s := testStore(t)
	site := phpSwitchSite(t, s)
	expected := Hash("original operator configuration")
	for _, digest := range []string{"not-a-digest", strings.Repeat("A", 64), strings.Repeat("f", 65)} {
		if _, err := s.QueuePHPWithConfig(site.ID, "php-8.4.27", "admin", digest); err == nil {
			t.Fatal("invalid digest queued")
		}
	}
	jobID, err := s.QueuePHPWithConfig(site.ID, "php-8.4.27", "admin", expected)
	if err != nil {
		t.Fatal(err)
	}
	var payload string
	s.DB.QueryRow("SELECT payload FROM jobs WHERE id=?", jobID).Scan(&payload)
	var p JobPayload
	if json.Unmarshal([]byte(payload), &p) != nil || p.ExpectedConfigSHA != expected || p.PreviousStatus != "running" {
		t.Fatal("precondition not durable", payload)
	}
	captured := make(chan ApplyRequest, 1)
	client := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/sites/apply" {
			var in ApplyRequest
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				return nil, err
			}
			captured <- in
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":"running"}`)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(`{"error":"outside fixture"}`)), Header: make(http.Header)}, nil
	})}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { RunWorker(ctx, s, client); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case in := <-captured:
		if in.JobID != jobID || !in.PreserveNginx || in.PreviousSite == nil || in.PreviousSite.ID != site.ID || in.PreviousSite.PHPVersionID != site.PHPVersionID || in.PreviousSite.RuntimeInstanceID != site.RuntimeInstanceID || in.Site.PHPVersionID != "php-8.4.27" || in.ExpectedConfigSHA != expected || len(in.Sites) != 1 {
			t.Fatal("worker dropped preservation identity", in)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PHP worker did not reach executor")
	}
}

func TestPHPSwitchPreviewRoleScopeAndNoQueuedMutation(t *testing.T) {
	s := testStore(t)
	site := phpSwitchSite(t, s)
	admin := accessUser(t, s, "php-admin", "admin", []string{"sites"})
	operator := accessUser(t, s, "php-operator", "operator", []string{"sites"})
	viewer := accessUser(t, s, "php-viewer", "viewer", []string{"sites"})
	limited := accessUser(t, s, "php-files", "admin", []string{"files"})
	s.DB.Exec("UPDATE app_user_roles SET site_ids=? WHERE user_id IN (?,?)", `["`+site.ID+`"]`, operator.ID, viewer.ID)
	a := &Server{Store: s}
	for _, tc := range []struct {
		user  identity
		id    string
		allow bool
	}{{admin, site.ID, true}, {operator, site.ID, true}, {viewer, site.ID, false}, {limited, site.ID, false}, {operator, ID(), false}} {
		req := httptest.NewRequest("POST", "/api/sites/"+tc.id+"/php/preview", nil)
		if a.appRoleAllowed(tc.user, req) != tc.allow {
			t.Fatal("incorrect preview role or website scope", tc.user.Username)
		}
	}
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var in ApplyRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatal(err)
		}
		if r.URL.Path != "/v1/sites/php-preview" || !in.PreserveNginx || in.PreviousSite == nil || in.PreviousSite.PHPVersionID != site.PHPVersionID || in.Site.PHPVersionID != "php-8.4.27" || in.JobID != "" {
			t.Fatal("preview requested mutation", in)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"protocol":"php-vhost-switch-v1"}`)), Header: make(http.Header)}, nil
	})}}
	var before int
	s.DB.QueryRow("SELECT count(*) FROM jobs").Scan(&before)
	req := httptest.NewRequest("POST", "/api/sites/"+site.ID+"/php/preview", strings.NewReader(`{"release_id":"php-8.4.27"}`))
	req.SetPathValue("id", site.ID)
	w := httptest.NewRecorder()
	a.previewPHP(w, req, admin)
	var after int
	s.DB.QueryRow("SELECT count(*) FROM jobs").Scan(&after)
	if w.Code != 200 || before != after || calls != 1 {
		t.Fatal("preview queued or failed", w.Code, w.Body.String())
	}
	retained, _ := s.Site(site.ID)
	if retained.PHPVersionID != site.PHPVersionID || retained.RuntimeInstanceID != site.RuntimeInstanceID || retained.SettingsRevision != site.SettingsRevision {
		t.Fatal("preview changed site binding")
	}
}
