//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWAFSiteArchiveRejectsReferencesBeforeMovingAnything(t *testing.T) {
	for _, kind := range []string{"site", "body-off", "list", "rule", "cc"} {
		t.Run(kind, func(t *testing.T) {
			s, site := archiveFixture(t, func(context.Context, string, ...string) (string, error) {
				t.Fatal("referenced archive invoked a native command")
				return "", nil
			})
			cfg := core.DefaultWAFConfig()
			switch kind {
			case "site":
				cfg.Policy.Sites = append(cfg.Policy.Sites, core.WAFSitePolicy{SiteID: site.ID, Mode: "off"})
			case "body-off":
				policy := core.DefaultWAFBodyPolicy()
				policy.Mode = "off"
				cfg.Body = &core.WAFBodyConfig{EngineJobID: core.ID(), Sites: []core.WAFBodySitePolicy{{SiteID: site.ID, Policy: policy}}}
			case "list":
				cfg.Policy.Lists["url_deny"] = []core.WAFEntry{{ID: core.ID(), SiteID: site.ID, Value: "/private"}}
			case "rule":
				cfg.Policy.Rules = []core.WAFRule{{ID: core.ID(), SiteID: site.ID, Name: "owned", Field: "uri", Operator: "exact", Value: "/private", Action: "observe", Enabled: false}}
			case "cc":
				cfg.Policy.CCRules = []core.WAFCCRule{{ID: core.ID(), SiteID: site.ID, Path: "/private", Rate: 5, Burst: 5, Enabled: false}}
			}
			path := s.softwareManifestPath("nginx-waf")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := moduleWrite(path, softwareManifest{ID: "nginx-waf", Version: core.WAFVersion, Settings: core.WAFSettings(cfg)}); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(s.Config.ConfDir, site.ID+".conf")
			before, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/sites/"+site.ID+"/archive-check", nil))
			if w.Code != 409 || !strings.Contains(w.Body.String(), "防火墙") {
				t.Fatal("reference preflight trusted", w.Code, w.Body.String())
			}
			for _, path := range []string{"/v1/sites/not-id/archive-check", "/v1/sites/" + site.ID + "/archive-check?path=/private"} {
				w = httptest.NewRecorder()
				s.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
				if w.Code != 400 {
					t.Fatal("unclosed preflight", w.Code)
				}
			}
			if _, err := s.ArchiveSite(context.Background(), core.SiteArchiveRequest{Site: site, JobID: core.ID()}); err == nil || !strings.Contains(err.Error(), "防火墙") {
				t.Fatal("referenced website archived", err)
			}
			after, err := os.ReadFile(configPath)
			if err != nil || string(after) != string(before) {
				t.Fatal("website was moved/modified", err)
			}
			if err := s.wafSiteArchiveReference(core.ID()); err != nil {
				t.Fatal("unrelated site rejected", err)
			}
		})
	}
}
