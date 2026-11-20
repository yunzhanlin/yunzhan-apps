package appcatalog

import (
	"runtime"
	"testing"
)

func TestPM2JournalArchiveManifestRequiresAllThreeExactCompiledHandlers(t *testing.T) {
	m := pm2RootVendorManifestFixture()
	m.Version = PM2ConfigurationArchiveVersion
	m.RequiredPanelFeatures = []string{PM2ConfigurationArchiveFeature}
	available := func(f string) bool {
		return f == PM2ConfigurationArchiveFeature || f == PM2RootVendorFeature || f == PM2EvidencePreservingStopFeature
	}
	if err := validatePanelRequirements(m, available); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{PM2ConfigurationArchiveFeature, PM2RootVendorFeature, PM2EvidencePreservingStopFeature} {
		if err := validatePanelRequirements(m, func(f string) bool { return available(f) && f != missing }); err == nil {
			t.Fatal("missing compiled handler accepted", missing)
		}
	}
	for _, version := range []string{PM2RootVendorVersion, "7.0.4-compat12.0", "7.0.4-compat13"} {
		bad := m
		bad.Version = version
		if err := validatePanelRequirements(bad, available); err == nil {
			t.Fatal("old or aliased application borrowed archive handler", version)
		}
	}
	want := runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
	if panelFeatureAvailable(PM2ConfigurationArchiveFeature) != want || panelFeatureAvailable("pm2-configuration-archive-v2") {
		t.Fatal("archive platform scope drifted")
	}
	if err := validatePanelRequirements(pm2RootVendorManifestFixture(), pm2RootVendorAvailable); err != nil {
		t.Fatal("published compat11 authority was changed", err)
	}
}
