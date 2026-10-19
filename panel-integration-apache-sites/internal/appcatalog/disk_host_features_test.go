package appcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func diskHostRequirementFixture() Manifest {
	m := diskUsageRequirementFixture()
	m.Version = "1.4.0"
	m.RequiredPanelFeatures = []string{DiskInodeUsageFeature, DiskHostJobsFeature}
	return m
}

func TestDiskHostManifestCannotBorrowLegacyInodeOrAnotherApplicationAuthority(t *testing.T) {
	if err := validatePanelRequirements(diskHostRequirementFixture(), func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if err := validatePanelRequirements(diskHostRequirementFixture(), func(f string) bool { return f == DiskInodeUsageFeature }); err == nil || !strings.Contains(err.Error(), "请先升级面板") {
		t.Fatal("old inode handler authorized full host", err)
	}
	for _, kind := range []string{"missing", "inode-only", "host-only", "duplicate", "extra", "legacy", "alias", "future", "another-app", "another-target", "another-route", "runtime", "compose"} {
		t.Run(kind, func(t *testing.T) {
			m := diskHostRequirementFixture()
			switch kind {
			case "missing":
				m.RequiredPanelFeatures = nil
			case "inode-only":
				m.RequiredPanelFeatures = []string{DiskInodeUsageFeature}
			case "host-only":
				m.RequiredPanelFeatures = []string{DiskHostJobsFeature}
			case "duplicate":
				m.RequiredPanelFeatures = []string{DiskHostJobsFeature, DiskHostJobsFeature}
			case "extra":
				m.RequiredPanelFeatures = append(m.RequiredPanelFeatures, StatisticsGeographyFeature)
			case "legacy":
				m.Version = "1.3.0"
			case "alias":
				m.Version = "1.4.0-rc1"
			case "future":
				m.Version = "1.5.0"
			case "another-app":
				m.ID = "daily-report"
				m.Delivery.Target = m.ID
			case "another-target":
				m.Delivery.Target = "daily-report"
			case "another-route":
				m.Delivery.ManageRoute = "software"
			case "runtime", "compose":
				m.Delivery.Provider = kind
			}
			if validatePanelRequirements(m, func(string) bool { return true }) == nil {
				t.Fatal("unbound full host claim accepted", kind)
			}
		})
	}
}

func TestDiskHostManifestHashCannotDropHostFeatureEvenAfterRehash(t *testing.T) {
	m := diskHostRequirementFixture()
	raw, _ := json.Marshal(m)
	sum := sha256.Sum256(raw)
	i := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: "https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/main/dist/apps/disk-analysis/1.4.0/manifest.json", SHA256: hex.EncodeToString(sum[:])}
	c := Default()
	if _, err := c.verifyManifestData(i, raw); (err == nil) != (runtime.GOOS == "linux") {
		t.Fatal(runtime.GOOS, err)
	}
	m.RequiredPanelFeatures = []string{DiskInodeUsageFeature}
	changed, _ := json.Marshal(m)
	if _, err := c.verifyManifestData(i, changed); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatal("host feature mutation borrowed old hash", err)
	}
	sum = sha256.Sum256(changed)
	i.SHA256 = hex.EncodeToString(sum[:])
	if _, err := c.verifyManifestData(i, changed); err == nil {
		t.Fatal("rehash authorized host without matching implementation")
	}
	if panelFeatureAvailable(DiskHostJobsFeature) != (runtime.GOOS == "linux") || panelFeatureAvailable("disk-host-jobs-v0") || panelFeatureAvailable("disk-host-jobs-v2") {
		t.Fatal("compiled host feature boundary changed")
	}
}
