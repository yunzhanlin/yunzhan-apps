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

func TestWAFVerified252CountryUpgradePreservesPolicyAndCreatesTransactionalInstanceOnly(t *testing.T) {
	s, cfg := wafLegacyVersionFixture(t, "2.5.2", func(c *core.WAFConfig) {
		rotation := core.DefaultWAFBodyLogRotation()
		rotation.Enabled, rotation.RotateMiB, rotation.MaxAgeMinutes = false, 7, 23
		c.BodyLogRotation = &rotation
	})
	before, err := s.readSoftwareManifest("nginx-waf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(s.wafCountryInstancePath()); !os.IsNotExist(err) {
		t.Fatal("legacy fixture invented a country instance", err)
	}
	if err := s.updateSoftware(context.Background(), "nginx-waf", core.WAFCountryDataVersion, func(string) {}); err != nil {
		t.Fatal(err)
	}
	after, err := s.readSoftwareManifest("nginx-waf")
	if err != nil || after.Version != core.WAFCountryDataVersion || after.InstalledAt != before.InstalledAt {
		t.Fatal("upgrade identity lost", err)
	}
	actual, err := core.DecodeWAFConfig(after.Settings)
	cfg.Policy.Revision++
	want, _ := json.Marshal(cfg)
	got, _ := json.Marshal(actual)
	if err != nil || !bytes.Equal(want, got) || actual.Country != nil {
		t.Fatal("upgrade changed policy or enabled country rules", err)
	}
	raw, err := os.ReadFile(s.wafCountryInstancePath())
	if err != nil {
		t.Fatal(err)
	}
	instance, err := decodeWAFCountryInstance(raw)
	if err != nil || instance.App != "nginx-waf" || !core.ValidID(instance.ID) {
		t.Fatal("transactional country installation identity missing", err)
	}
	changes, err := s.planWAFConfiguration(actual, false)
	if err != nil || len(changes) != 0 {
		t.Fatal("committed version cannot be independently re-planned", changes, err)
	}
	if _, err := os.Lstat(s.systemPath(wafCountryDataRoot)); !os.IsNotExist(err) {
		t.Fatal("version upgrade downloaded or adopted country data", err)
	}
	if _, err := os.Lstat(s.moduleDir("nginx-waf")); !os.IsNotExist(err) {
		t.Fatal("version upgrade prepared a network account implicitly", err)
	}
}
