package core

import "testing"

func TestDiskUsageImplementedVersionAuthorizesExactNewPackageAndRejectsAliases(t *testing.T) {
	if DiskAnalysisAppVersion != "1.3.0" {
		t.Fatal("the audited inode-handler version changed without a new fixed-version test contract")
	}
	if got := SoftwareImplementationVersion("disk-analysis"); got != DiskAnalysisAppVersion {
		t.Fatalf("actual native inode handler must not remain advertised as logical-only1.2: %q", got)
	}
	for _, version := range []string{"1.0", "1.2.0", "1.3.0"} {
		if err := ValidateSoftwareUpdate("disk-analysis", version); err != nil {
			t.Errorf("implemented exact/legacy version %q refused: %v", version, err)
		}
	}
	for _, version := range []string{"", "invalid", "1.3", "1.3.0.0", "1.3.0-compat1", "1.3.0-rc1", "1.4.0", "2.0.0"} {
		if err := ValidateSoftwareUpdate("disk-analysis", version); err == nil {
			t.Errorf("unsupported or alias version %q accepted", version)
		}
	}
}

func TestDiskUsageVersionGateDoesNotWidenOtherApplicationImplementations(t *testing.T) {
	for _, app := range SoftwareAppCatalog() {
		if app.ID == "disk-analysis" {
			continue
		}
		if err := ValidateSoftwareUpdate(app.ID, app.Version); err != nil {
			t.Errorf("unchanged implemented %s@%s refused: %v", app.ID, app.Version, err)
		}
		if err := ValidateSoftwareUpdate(app.ID, "999.0.0"); err == nil {
			t.Errorf("unimplemented %s revision accepted", app.ID)
		}
	}
}
