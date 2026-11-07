package appcatalog

import "testing"

func TestDiskHostCancelSealVersionRequiresExactCompiledCapability(t *testing.T) {
	features := []string{DiskInodeUsageFeature, DiskHostJobsFeature, DiskHostCancelSealFeature}
	manifest := diskHostRequirementFixture()
	manifest.Version, manifest.RequiredPanelFeatures = "1.4.1", features
	all := func(string) bool { return true }
	if err := validatePanelRequirements(manifest, all); err != nil {
		t.Fatal("complete fixed capability refused", err)
	}
	old := func(feature string) bool { return feature != DiskHostCancelSealFeature }
	if err := validatePanelRequirements(manifest, old); err == nil {
		t.Fatal("old compiled handler accepted cancellation-seal package")
	}
	for _, required := range [][]string{nil, features[:2], {DiskInodeUsageFeature, DiskHostJobsFeature, DiskHostJobsFeature}, append(append([]string{}, features...), "future")} {
		bad := manifest
		bad.RequiredPanelFeatures = required
		if err := validatePanelRequirements(bad, all); err == nil {
			t.Fatal("missing, duplicate or arbitrary capability accepted", required)
		}
	}
	for _, version := range []string{"1.4.1-rc1", "1.4.1-compat1", "1.4.2", "1.5.0"} {
		bad := manifest
		bad.Version = version
		if err := validatePanelRequirements(bad, all); err == nil {
			t.Fatal("unimplemented or aliased host revision accepted", version)
		}
	}
	legacy := manifest
	legacy.Version = "1.4.0"
	legacy.RequiredPanelFeatures = features[:2]
	if err := validatePanelRequirements(legacy, old); err != nil {
		t.Fatal("original1.4.0 fixed contract changed", err)
	}
}
