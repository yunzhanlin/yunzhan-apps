package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func testService(t *testing.T, run Command) *Service {
	t.Helper()
	base := t.TempDir()
	c := Config{SystemRoot: base, SecurityDir: filepath.Join(base, "security"), SitesDir: filepath.Join(base, "sites"), ConfDir: filepath.Join(base, "config"), StateDir: filepath.Join(base, "state"), ApacheSiteConfig: filepath.Join(base, "apache.conf"), NginxConf: filepath.Join(base, "nginx.conf"), NginxBin: "/usr/sbin/nginx", Run: run}
	for _, p := range []string{c.SitesDir, c.ConfDir, c.StateDir, c.SecurityDir} {
		if e := os.Mkdir(p, 0755); e != nil {
			t.Fatal(e)
		}
	}
	return New(c)
}

func TestServiceFixtureNeverInheritsLiveSystemPaths(t *testing.T) {
	s := testService(t, func(context.Context, string, ...string) (string, error) { return "", nil })
	for _, path := range []string{s.Config.SecurityDir, s.Config.SitesDir, s.Config.ConfDir, s.Config.StateDir, s.Config.NginxConf, s.Config.ApacheSiteConfig} {
		relative, err := filepath.Rel(s.Config.SystemRoot, path)
		if err != nil || relative == ".." || filepath.IsAbs(relative) {
			t.Fatal("fixture inherited a live system path", path)
		}
	}
	if s.Config.SystemRoot == "/" || s.Config.SecurityDir == "/etc/panel/security-apps" {
		t.Fatal("fixture inherited production defaults")
	}
}
func TestConfigurationFailureRestoresPreviousFile(t *testing.T) {
	nginxChecks := 0
	s := testService(t, func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "/usr/bin/systemctl" {
			return "inactive", errors.New("inactive")
		}
		if name != "/usr/sbin/nginx" || len(args) != 1 || args[0] != "-t" {
			t.Fatal("unexpected command", name, args)
		}
		nginxChecks++
		return "", errors.New("invalid config")
	})
	site := core.Site{ID: core.ID(), Name: "safe <title>", Slug: "safe-site", Domain: "safe-site.localhost"}
	path := filepath.Join(s.Config.ConfDir, site.ID+".conf")
	old := []byte("# previous known configuration\n")
	if e := os.WriteFile(path, old, 0644); e != nil {
		t.Fatal(e)
	}
	_, e := s.Apply(context.Background(), core.ApplyRequest{Site: site, JobID: core.ID(), Enabled: true})
	if e == nil {
		t.Fatal("invalid config reported success")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(old) {
		t.Fatal("old configuration was lost")
	}
	if nginxChecks != 1 {
		t.Fatalf("unexpected Nginx validation count after failure: %d, apply error: %v", nginxChecks, e)
	}
}
func TestExecutorRejectsTraversalAndForeignDirectory(t *testing.T) {
	s := testService(t, func(context.Context, string, ...string) (string, error) {
		t.Fatal("must reject before executing")
		return "", nil
	})
	site := core.Site{ID: "../../escape", Name: "test", Slug: "safe-site", Domain: "safe-site.localhost"}
	if _, e := s.Apply(context.Background(), core.ApplyRequest{Site: site, JobID: core.ID(), Enabled: true}); e == nil {
		t.Fatal("path traversal accepted")
	}
	site.ID = core.ID()
	outside := t.TempDir()
	if e := os.Symlink(outside, filepath.Join(s.Config.SitesDir, site.ID)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Apply(context.Background(), core.ApplyRequest{Site: site, JobID: core.ID(), Enabled: true}); e == nil {
		t.Fatal("foreign symlink accepted")
	}
	files, _ := os.ReadDir(outside)
	if len(files) > 0 {
		t.Fatal("wrote outside site root")
	}
}
