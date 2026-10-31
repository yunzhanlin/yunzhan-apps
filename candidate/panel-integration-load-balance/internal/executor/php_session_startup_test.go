package executor

import (
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"strings"
	"testing"
)

func TestPHPProbeRequiresStartupSessionProgressProtection(t *testing.T) {
	for _, release := range runtimecatalog.PHPReleases() {
		if !phpSessionProgressGuarded(release) {
			t.Fatalf("reviewed PHP release lacks startup protection: %s", release.ID)
		}
		for _, configured := range []bool{false, true} {
			site := core.Site{ID: "49c8086ba9b1aa3724d4d9ab94f65078", PHPVersionID: release.ID}
			if configured {
				settings := core.DefaultPHPSettings()
				settings.MemoryMB = 256
				settings.Extensions = []string{"redis-6.3.0"}
				site.Settings.PHP = &settings
			}
			script := phpProbeScript(site)
			if strings.Count(script, "ini_get('session.upload_progress.enabled')") != 1 || !strings.Contains(script, "FILTER_VALIDATE_BOOL") {
				t.Fatalf("FPM probe does not read actual upload progress flag: %s", script)
			}
			wantSuffix := "|0"
			if configured {
				wantSuffix += "|6.3.0"
			}
			if !strings.HasSuffix(phpProbeExpected(site), wantSuffix) {
				t.Fatalf("probe does not require protection before extension version: %s", phpProbeExpected(site))
			}
			// Startup policy must not rewrite old pool files, settings hashes or
			// instance IDs, which normal upgrade and rollback still validate.
			if strings.Contains(phpPoolConfiguration(site, "/srv/panel/sites/"+site.ID), "session.upload_progress") {
				t.Fatal("startup policy changed persistent legacy pool format")
			}
		}
	}
	for _, r := range []runtimecatalog.Release{{Family: "php", Version: "5.2.17"}, {Family: "php", Version: "7.4.33"}, {Family: "nginx", Version: "8.4.27"}, {Family: "php", Version: ""}} {
		if phpSessionProgressGuarded(r) {
			t.Fatalf("unsupported runtime received a PHP8 protection claim: %#v", r)
		}
	}
}
