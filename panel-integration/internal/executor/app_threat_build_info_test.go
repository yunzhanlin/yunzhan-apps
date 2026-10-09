package executor

import (
	"strings"
	"testing"
)

func TestThreatIDSBuildProbeBindsActualVersionAndCaptureFeatureToPackage(t *testing.T) {
	valid := "This is Suricata version 8.0.7 RELEASE\nFeatures: PCAP AF_PACKET RUST\n"
	if err := validateThreatIDSBuildInfo("1:8.0.7-1~bpo13+1", valid); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{"", strings.Replace(valid, "8.0.7", "7.0.10", 1), strings.Replace(valid, "8.0.7", "8.0.8", 1), strings.Replace(valid, "AF_PACKET", "no-AF_PACKET", 1), valid + valid, valid + "Features: AF_PACKET\n", valid + strings.Repeat("x", 128<<10)} {
		if err := validateThreatIDSBuildInfo("1:8.0.7-1~bpo13+1", output); err == nil {
			t.Fatal("unknown/mismatched native probe accepted")
		}
	}
}
