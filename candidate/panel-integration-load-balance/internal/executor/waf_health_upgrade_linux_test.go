//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"local/panel/internal/core"
)

func TestWAFVerified251HealthUpgradePreservesCompletePolicyAndInstallTime(t *testing.T) {
	s, cfg := wafLegacyVersionFixture(t, "2.5.1", func(c *core.WAFConfig) {
		r := core.DefaultWAFBodyLogRotation()
		r.Enabled = false
		r.RotateMiB = 7
		r.MaxAgeMinutes = 23
		c.BodyLogRotation = &r
	})
	before, err := s.readSoftwareManifest("nginx-waf")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.updateSoftware(context.Background(), "nginx-waf", core.WAFVersion, func(string) {}); err != nil {
		t.Fatal(err)
	}
	after, err := s.readSoftwareManifest("nginx-waf")
	if err != nil || after.Version != core.WAFVersion || after.InstalledAt != before.InstalledAt {
		t.Fatal("original identity lost", err)
	}
	actual, err := core.DecodeWAFConfig(after.Settings)
	cfg.Policy.Revision++
	want, _ := json.Marshal(cfg)
	got, _ := json.Marshal(actual)
	if err != nil || !bytes.Equal(want, got) {
		t.Fatal("health upgrade changed unrelated policy", err)
	}
	h, _ := wafFiles(s)
	data, err := os.ReadFile(h)
	if err != nil || !bytes.Contains(data, []byte(`map "$panel_waf_site:$uri" $pw_health`)) || bytes.Contains(data, []byte(`map "$uri" $pw_health`)) {
		t.Fatal("new rules not installed", err)
	}
}
