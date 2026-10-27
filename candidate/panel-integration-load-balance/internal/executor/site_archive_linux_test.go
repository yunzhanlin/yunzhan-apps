//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func archiveFixture(t *testing.T, run Command) (*Service, core.Site) {
	t.Helper()
	s := testService(t, run)
	site := core.Site{ID: core.ID(), Name: "archive", Slug: "archive-site", Domain: "archive.example.test", Settings: core.DefaultSiteSettings(core.SiteSettings{})}
	dir := filepath.Join(s.Config.SitesDir, site.ID)
	if e := os.Mkdir(dir, 0755); e != nil {
		t.Fatal(e)
	}
	marker, _ := json.Marshal(map[string]string{"id": site.ID, "domain": site.Domain})
	if e := os.WriteFile(filepath.Join(dir, ".panel-site.json"), marker, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(s.Config.ConfDir, site.ID+".conf"), []byte("server { listen 19101; }\n"), 0644); e != nil {
		t.Fatal(e)
	}
	return s, site
}

func TestArchiveSiteMovesOwnedFilesAndCanReplay(t *testing.T) {
	calls := 0
	s, site := archiveFixture(t, func(_ context.Context, _ string, _ ...string) (string, error) { calls++; return "", nil })
	request := core.SiteArchiveRequest{Site: site, JobID: core.ID()}
	result, e := s.ArchiveSite(context.Background(), request)
	if e != nil || result.Status != "archived" {
		t.Fatal("archive failed", e)
	}
	for _, file := range []string{filepath.Join(filepath.Dir(s.Config.ConfDir), "sites-archive", site.ID+".conf"), filepath.Join(s.Config.SitesDir, ".archives", site.ID, ".panel-site.json")} {
		if _, e := os.Stat(file); e != nil {
			t.Fatal("archive missing", file, e)
		}
	}
	if _, e := os.Stat(filepath.Join(s.Config.ConfDir, site.ID+".conf")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("active config remained")
	}
	if _, e := s.ArchiveSite(context.Background(), request); e != nil {
		t.Fatal("archive replay failed", e)
	}
	if calls != 4 {
		t.Fatal("nginx validate/reload sequence incomplete", calls)
	}
}

func TestArchiveSiteRestoresConfigWhenNginxRejects(t *testing.T) {
	s, site := archiveFixture(t, func(_ context.Context, _ string, _ ...string) (string, error) { return "", errors.New("nginx invalid") })
	if _, e := s.ArchiveSite(context.Background(), core.SiteArchiveRequest{Site: site, JobID: core.ID()}); e == nil {
		t.Fatal("failed Nginx config accepted")
	}
	if _, e := os.Stat(filepath.Join(s.Config.ConfDir, site.ID+".conf")); e != nil {
		t.Fatal("original config not restored", e)
	}
	if _, e := os.Stat(filepath.Join(s.Config.SitesDir, site.ID, ".panel-site.json")); e != nil {
		t.Fatal("site directory moved on failure", e)
	}
}
