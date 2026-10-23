package executor

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestThreatIDSLegacyCaptureGoldenMatchesOriginalInstalledReceipt(t *testing.T) {
	// Actual F22 Core-created QA revision, captured before changing the
	// renderer. No signed receipt or installed YAML is re-labelled as v1.
	in := threatIDSConfig{Revision: 1, Interface: "yzids24gk", HomeNetworks: []string{"192.0.2.0/30"}}
	text, err := threatIDSYAML(in, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil || fmt.Sprintf("%x", sha256.Sum256([]byte(text))) != "8d4e899f7b68e64d84fe796da37a2f39bc70e70d88139c6b6ac2c94fd93f40d7" {
		t.Fatal("original installed YAML no longer readable byte-exactly", err)
	}
	raw, err := json.Marshal(in)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != "b97f3711a2a50ca8b3f5017ff45876978aab36d168782d23ae3e8d275f411ff4" {
		t.Fatal("original configuration record serialization changed", err)
	}
}

// Decodes an actual stored-record shape rather than assuming that an unknown
// format silently opts into today's renderer. The old handler ignores this
// field with ordinary Unmarshal and renders the single-block legacy profile.
func TestThreatIDSExplicitMultiBlockCaptureProfile(t *testing.T) {
	var in threatIDSConfig
	if err := json.Unmarshal([]byte("{\"revision\":1,\"interface\":\"test0\",\"home_networks\":[\"192.0.2.0/30\"],\"capture_format\":1,\"capture_mtu\":1500}"), &in); err != nil {
		t.Fatal(err)
	}
	text, err := threatIDSYAML(in, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"ring-size: 4776", "block-size: 1048576", "threads: 1", "tpacket-v3: yes", "buffer-size: 65536", "checksum-validation: yes"} {
		if !strings.Contains(text, marker) {
			t.Fatalf("current bounded capture profile missing %q", marker)
		}
	}
	// Suricata 8.0.7 AFPComputeRingParamsV3: frames_per_block=block_size/frame_size;
	// blocks=ring_size/frames_per_block+1. A single block has no spare while user
	// space consumes it. The stored native MTU keeps buffers bounded, including
	// standard, jumbo and loopback MTUs. This is not a throughput acceptance.
	for _, mtu := range []int{68, 576, 1500, 9000, 65536} {
		frame := (mtu + 80 + 15) &^ 15
		ring := 8 * (1048576 / (mtu + 256))
		blocks := ring/(1048576/frame) + 1
		if blocks < 3 || blocks*1048576 > 9*1048576 {
			t.Fatalf("invalid fixed ring budget for MTU %d: %d blocks", mtu, blocks)
		}
	}
}

func TestThreatIDSLegacyCaptureRecordPreservedButCannotAuthorizeStart(t *testing.T) {
	in := threatIDSConfig{Revision: 4, Interface: "eth0", HomeNetworks: []string{"192.0.2.0/30"}}
	if err := validateThreatIDSConfig(in); err != nil {
		t.Fatal("legacy identity unreadable", err)
	}
	text, err := threatIDSYAML(in, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil || !strings.Contains(text, "ring-size: 256") || strings.Contains(text, "ring-size: 4776") {
		t.Fatal("legacy native bytes silently changed", err)
	}
	raw, err := json.Marshal(in)
	if err != nil || strings.Contains(string(raw), "capture_") {
		t.Fatal("legacy record gained fields", string(raw), err)
	}
	if err := threatIDSRequireCurrentCapture(in); err == nil {
		t.Fatal("legacy single-block profile allowed to start")
	}
	for _, bad := range []threatIDSConfig{
		{CaptureFormat: -1}, {CaptureFormat: 2}, {CaptureFormat: 0, CaptureMTU: 1500},
		{CaptureFormat: 1, CaptureMTU: 0}, {CaptureFormat: 1, CaptureMTU: 67}, {CaptureFormat: 1, CaptureMTU: 65537},
	} {
		bad.Revision, bad.Interface, bad.HomeNetworks = 1, "eth0", []string{"192.0.2.0/30"}
		if validateThreatIDSConfig(bad) == nil {
			t.Fatal("unknown/missing native capacity accepted", bad)
		}
	}
}

func TestThreatIDSMultiBlockCaptureUsesStoredBoundedNativeMTU(t *testing.T) {
	for _, mtu := range []int{68, 576, 1280, 1500, 9000, 65536} {
		in := threatIDSConfig{Revision: 1, Interface: "test0", HomeNetworks: []string{"192.0.2.0/30"}, CaptureFormat: 1, CaptureMTU: mtu}
		text, err := threatIDSYAML(in, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
		if err != nil {
			t.Fatal(mtu, err)
		}
		wanted := fmt.Sprintf("ring-size: %d", 8*(1048576/(mtu+256)))
		if !strings.Contains(text, wanted) || threatIDSRequireCurrentCapture(in) != nil {
			t.Fatal(mtu, "wrong closed buffer geometry")
		}
		// This record controls only reviewed geometry, never client ring size.
		if strings.Contains(text, "mmap-locked: yes") || strings.Contains(text, "buffer-size: 8388608") {
			t.Fatal("capture privileges/socket budget widened")
		}
	}
}
