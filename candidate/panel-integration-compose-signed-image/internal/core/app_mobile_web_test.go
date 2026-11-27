package core

import (
	"reflect"
	"testing"
)

func TestMobileWeb140KeepsNativeArtifactsAndOldInstallations(t *testing.T) {
	r, e := NativeMobileDeliveryForVersion("1.4.0")
	if e != nil || r["version"] != "1.4.0" || r["native_package_version"] != "1.3.3" || r["web_management"] != true {
		t.Fatal(r, e)
	}
	old, _ := NativeMobileDeliveryForVersion("1.3.3")
	if old["version"] != "1.3.3" || old["native_package_version"] != nil || !reflect.DeepEqual(old["mobile_downloads"], r["mobile_downloads"]) {
		t.Fatal("web update changed or relabelled native outputs")
	}
	if NativeMobileSignedVersion("1.4.0") || !MobileSignedApplicationVersion("1.4.0") || ValidateSoftwareUpdate("mobile-pwa", "1.4.0") != nil {
		t.Fatal("web application identity confused with native build")
	}
}

func TestMobileWeb140SignedQueueBindingCannotBeBorrowed(t *testing.T) {
	nativeMobileQueueBindingChecks(t, MobileWebAppVersion)
}
