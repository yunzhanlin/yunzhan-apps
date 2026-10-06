package core

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestNativeMobileDeliveryFixedArtifacts(t *testing.T) {
	report := NativeMobileDelivery()
	downloads := report["mobile_downloads"].([]map[string]string)
	if len(downloads) != 3 {
		t.Fatal("missing native deliveries")
	}
	for _, d := range downloads {
		if !strings.HasPrefix(d["url"], "https://github.com/yunzhanlin/yunzhan-apps/releases/download/v0.1.0-dev.proapps11/") || !strings.HasSuffix(d["url"], d["filename"]) {
			t.Fatal("untrusted delivery")
		}
		b, e := hex.DecodeString(d["sha256"])
		if e != nil || len(b) != 32 {
			t.Fatal("invalid checksum")
		}
	}
	if !strings.Contains(report["scope"].(string), "尚不代表") {
		t.Fatal("acceptance scope must remain explicit")
	}
}
