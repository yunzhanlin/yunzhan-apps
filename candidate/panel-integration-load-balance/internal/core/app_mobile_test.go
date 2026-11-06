package core

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestNativeMobileDeliveryFixedArtifacts(t *testing.T) {
	report, err := NativeMobileDeliveryForVersion("1.3.2")
	if err != nil {
		t.Fatal(err)
	}
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
	if len(expected) != 0 || report["version"] != "1.3.2" || report["physical_device_acceptance"] != false || report["android_target_sdk"] != 37 {
		t.Fatal("delivery artifact, version or acceptance boundary drift")
	}
	if !strings.Contains(report["scope"].(string), "尚不代表") {
		t.Fatal("acceptance scope must remain explicit")
	}
	if report["native_source_inputs_sha256"] != "2b963086f95fdc30787c7d27ad5680b9fb5802e1dec28f5d824e3670f211a052" || report["android_emulator_session_acceptance"] != true || report["android_emulator_api"] != 37 || report["ios_accessibility_ui_acceptance"] != false {
		t.Fatal("emulator evidence must not silently claim iOS or physical-device acceptance")
	}
}

func TestNativeMobile133ReportsIndependentFixedArtifacts(t *testing.T) {
	report := NativeMobileDelivery()
	if report["version"] != "1.3.3" || report["native_source_inputs_sha256"] != "895c674a1c3475f934df1b2289fa3b01e613b16c5cad46f60f8bdc36739e680e" || report["physical_device_acceptance"] != false || report["android_emulator_api"] != 37 || report["ios_accessibility_ui_acceptance"] != false || report["ios_emulator_file_export_and_background_privacy_acceptance"] != true {
		t.Fatal("native133 source identity or exact platform evidence scope drift")
	}
	expected := map[string]string{
		"yunzhan-mobile-1.3.3-android.apk":         "a60a6d022fe932be837807ad27745cc362bb85bd2bf85af89ad2082b6ed9db74",
		"yunzhan-mobile-1.3.3-ios-unsigned.tar.gz": "7398fc9cd319232d5983dcffebddc2a53a6d6f3705925b1f0d56c5698bb9f882",
		"yunzhan-mobile-1.3.3-source.tar.gz":       "ee40e9c48470a6d1e6f16d895a28be61f2ae045cfd4e5c4dd4e5fe8458f38567",
	}
	downloads := report["mobile_downloads"].([]map[string]string)
	if len(downloads) != len(expected) {
		t.Fatal("native133 artifacts missing")
	}
	for _, file := range downloads {
		if expected[file["filename"]] == "" || file["sha256"] != expected[file["filename"]] || file["url"] != "https://github.com/yunzhanlin/yunzhan-apps/releases/download/mobile-v1.3.3/"+file["filename"] {
			t.Fatal("native133 borrowed another delivery cohort", file)
		}
		delete(expected, file["filename"])
	}
	if len(expected) != 0 {
		t.Fatal("native133 artifact duplicated")
	}
	downloads[0]["url"] = "https://unrelated.invalid/changed"
	again, err := NativeMobileDeliveryForVersion("1.3.3")
	if err != nil || !strings.Contains(again["mobile_downloads"].([]map[string]string)[0]["url"], "/mobile-v1.3.3/") {
		t.Fatal("native133 report mutation escaped its own report", err)
	}
}

func TestNativeMobileUpdateVersionCannotBorrowOtherClientBuilds(t *testing.T) {
	if SoftwareImplementationVersion("mobile-pwa") != NativeMobileAppVersion || NativeMobileAppVersion != "1.3.3" {
		t.Fatal("compiled mobile application version drift")
	}
	for _, version := range []string{"1.0", "1.0-compat1", "1.1.0", "1.2.0", "1.3.0", "1.3.2", "1.3.3"} {
		if err := ValidateSoftwareUpdate("mobile-pwa", version); err != nil {
			t.Fatal(version, err)
		}
	}
	for _, version := range []string{"1.0.0", "1.0-compat2", "1.2.1", "01.3.0", "1.3.1", "1.3.2-compat1", "1.3.4", "1.4.0", "18446744073709551616.0.0", "unknown"} {
		if err := ValidateSoftwareUpdate("mobile-pwa", version); err == nil {
			t.Fatal("unreviewed native version accepted", version)
		}
	}
	if SoftwareImplementationVersion("php-code-security") != "1.3.0" {
		t.Fatal("mobile update changed unrelated PHP security module")
	}
}

func TestNativeMobileDeliveryRetainsEachOriginalInstallationIdentity(t *testing.T) {
	for _, version := range []string{"1.0", "1.0-compat1", "1.1.0", "1.2.0", "1.3.0", "1.3.2"} {
		report, err := NativeMobileDeliveryForVersion(version)
		if err != nil || report["version"] != version {
			t.Fatal("programme version replaced original module identity", version, err)
		}
		for _, download := range report["mobile_downloads"].([]map[string]string) {
			if !strings.HasPrefix(download["url"], "https://github.com/yunzhanlin/yunzhan-apps/releases/download/mobile-v1.3.2/") {
				t.Fatal("old installation borrowed a newer client", version, download)
			}
		}
	}
	for _, version := range []string{"", "1.3.1", "1.3.2-compat1", "01.3.2", "1.4.0", "unknown"} {
		if report, err := NativeMobileDeliveryForVersion(version); err == nil || report != nil {
			t.Fatal("unknown installation borrowed a compiled native delivery", version)
		}
	}
	original, _ := NativeMobileDeliveryForVersion("1.3.2")
	original["mobile_downloads"].([]map[string]string)[0]["url"] = "https://unrelated.invalid/changed"
	again, _ := NativeMobileDeliveryForVersion("1.3.2")
	if !strings.HasPrefix(again["mobile_downloads"].([]map[string]string)[0]["url"], "https://github.com/yunzhanlin/yunzhan-apps/") {
		t.Fatal("one report mutated another installation's fixed download metadata")
	}
}
