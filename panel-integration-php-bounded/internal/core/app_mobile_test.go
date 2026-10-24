package core

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestNativeMobileDeliveryFixedArtifacts(t *testing.T) {
	report := NativeMobileDelivery()
	downloads := report["mobile_downloads"].([]map[string]string)
	expected := map[string]string{
		"yunzhan-mobile-1.3.2-android.apk":         "a76d4a9a04b4d46c35332b36e04590078a27e25885fd5abe6ede611be55b09e3",
		"yunzhan-mobile-1.3.2-ios-unsigned.tar.gz": "ef86e336b7334bb29cad8570cc29eea0af0f9f26217b77bd914a94c429d4f365",
		"yunzhan-mobile-1.3.2-source.tar.gz":       "6fcbbaa8d18ba1cb22aa050b849dd8d3e1488e8f845b32c1930cb0eea2cc313f",
	}
	if len(downloads) != 3 {
		t.Fatal("missing native deliveries")
	}
	for _, d := range downloads {
		if !strings.HasPrefix(d["url"], "https://github.com/yunzhanlin/yunzhan-apps/releases/download/mobile-v1.3.2/") || !strings.HasSuffix(d["url"], d["filename"]) || expected[d["filename"]] != d["sha256"] || expected[d["filename"]] == "" {
			t.Fatal("untrusted delivery")
		}
		b, e := hex.DecodeString(d["sha256"])
		if e != nil || len(b) != 32 {
			t.Fatal("invalid checksum")
		}
		delete(expected, d["filename"])
	}
	if len(expected) != 0 || report["version"] != NativeMobileAppVersion || report["physical_device_acceptance"] != false || report["android_target_sdk"] != 37 {
		t.Fatal("delivery artifact, version or acceptance boundary drift")
	}
	if !strings.Contains(report["scope"].(string), "尚不代表") {
		t.Fatal("acceptance scope must remain explicit")
	}
	if report["native_source_inputs_sha256"] != "2b963086f95fdc30787c7d27ad5680b9fb5802e1dec28f5d824e3670f211a052" || report["android_emulator_session_acceptance"] != true || report["android_emulator_api"] != 37 || report["ios_accessibility_ui_acceptance"] != false {
		t.Fatal("emulator evidence must not silently claim iOS or physical-device acceptance")
	}
}

func TestNativeMobileUpdateVersionCannotBorrowOtherClientBuilds(t *testing.T) {
	if SoftwareImplementationVersion("mobile-pwa") != NativeMobileAppVersion || NativeMobileAppVersion != "1.3.2" {
		t.Fatal("compiled mobile application version drift")
	}
	for _, version := range []string{"1.0", "1.0-compat1", "1.1.0", "1.2.0", "1.3.0", "1.3.2"} {
		if err := ValidateSoftwareUpdate("mobile-pwa", version); err != nil {
			t.Fatal(version, err)
		}
	}
	for _, version := range []string{"1.0.0", "1.0-compat2", "1.2.1", "01.3.0", "1.3.1", "1.3.2-compat1", "1.3.3", "1.4.0", "18446744073709551616.0.0", "unknown"} {
		if err := ValidateSoftwareUpdate("mobile-pwa", version); err == nil {
			t.Fatal("unreviewed native version accepted", version)
		}
	}
	if SoftwareImplementationVersion("php-code-security") != "1.3.0" {
		t.Fatal("mobile update changed unrelated PHP security module")
	}
}
