package core

import "testing"

func TestNFSPrivateClientVersionFenceKeepsLegacyAndRejectsAliases(t *testing.T) {
	if SoftwareImplementationVersion("nfs-manager") != NFSPrivateClientAppVersion {
		t.Fatal("current NFS implementation version not advertised")
	}
	for _, version := range []string{"1.2.0", "1.3.0", NFSPrivateClientAppVersion} {
		if err := ValidateSoftwareInstallVersion("nfs-manager", version); err != nil {
			t.Fatal("supported version refused", version, err)
		}
	}
	for _, version := range []string{"1.3.0-preview", "1.3.1-preview", "1.3.1-compat1", "1.3.2", "2.0.0", "unknown"} {
		if err := ValidateSoftwareInstallVersion("nfs-manager", version); err == nil {
			t.Fatal("unreviewed NFS version accepted", version)
		}
	}
}
