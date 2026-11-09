//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetworkBaselineDiffAndPublicExposure(t *testing.T) {
	current := []string{"tcp LISTEN 0 4096 127.0.0.1:19100 0.0.0.0:* users:((\"panel\",pid=4,fd=5))", "tcp LISTEN 0 128 [::1]:9000 [::]:*", "tcp LISTEN 0 128 [::ffff:127.0.0.1]:9001 [::]:*", "udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*"}
	old := []string{current[0], "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*"}
	out := buildNetworkThreatReport(current, nil, old, true)
	if out["public_listener_count"] != 1 || out["new_public_listeners"] != 1 || len(out["alerts"].([]map[string]any)) != 4 {
		t.Fatal(out)
	}
	if len(buildNetworkThreatReport(current, nil, nil, false)["alerts"].([]map[string]any)) != 0 {
		t.Fatal("first inventory falsely reported threat")
	}
	if rows, partial := networkLines("\n\n"); len(rows) != 0 || partial {
		t.Fatal(rows, partial)
	}
	if rows, partial := networkLines(strings.Repeat("tcp LISTEN 0 0 *:80 *:*\n", 2500)); len(rows) != 2000 || !partial {
		t.Fatal(len(rows), partial)
	}
}

func TestPHPScanFiltersExcludesAndDeterministicOrder(t *testing.T) {
	f, site := fileFixture(t)
	for path, data := range map[string]string{"b.php": "<?php system('id'); base64_decode('abc');", "a.phtml": "<?php eval($x);", "skip.inc": "<?php exec('id');"} {
		if err := os.WriteFile(filepath.Join(site, "public", path), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	s := New(Config{SitesDir: filepath.Dir(site)})
	in := core.AppModuleInput{SiteID: filepath.Base(site), Excludes: []string{"skip.inc"}, Severity: "high"}
	out, err := s.modulePHPScanFiltered(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	report := out.(map[string]any)
	findings := report["findings"].([]map[string]any)
	if len(findings) != 2 || findings[0]["path"] != "a.phtml" || findings[1]["path"] != "b.php" || report["scanned_php"] != 2 {
		t.Fatal(out)
	}
	in.Search = "command-execution"
	out, err = s.modulePHPScanFiltered(context.Background(), in)
	if err != nil || out.(map[string]any)["findings_count"] != 1 {
		t.Fatal(out, err)
	}
	in.Excludes = []string{"../escape"}
	if _, err = s.modulePHPScanFiltered(context.Background(), in); err == nil {
		t.Fatal("unsafe exclude accepted")
	}
	_ = f
}

func TestModuleHistoryRedactsInputSecrets(t *testing.T) {
	s := New(Config{SecurityDir: t.TempDir()})
	err := s.appendModuleEvent("pure-ftpd", "password", "manual", core.AppModuleInput{Password: "secret-password", Token: "secret-token"}, nil, &networkTestError{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.moduleHistory("pure-ftpd", core.AppModuleInput{})
	b, _ := json.Marshal(out)
	if err != nil || strings.Contains(string(b), "secret-password") || strings.Contains(string(b), "secret-token") {
		t.Fatal(out, err)
	}
}

type networkTestError struct{}

func (*networkTestError) Error() string { return "secret-password secret-token command failed" }
