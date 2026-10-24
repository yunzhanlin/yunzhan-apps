package core

import "testing"

func TestHardeningUpdateCapabilityIsFixedAndCannotBeInventedByCatalog(t *testing.T) {
	if SoftwareImplementationVersion("system-hardening") != HardeningAppVersion || ValidateSoftwareUpdate("system-hardening", HardeningAppVersion) != nil {
		t.Fatal("missing compiled fixed capability")
	}
	for _, version := range []string{"1.1.0-unreviewed", "1.1.1", "2.0.0"} {
		t.Run(version, func(t *testing.T) {
			if ValidateSoftwareUpdate("system-hardening", version) == nil {
				t.Fatal("catalog invented capability")
			}
		})
	}
}
