package core

import "testing"

func TestApacheWAFTrustedProxyStrictSemantics(t *testing.T) {
	for _, bad := range []string{"last-address", "real-ip", "no-ack", "empty-cidrs", "all-peers", "nginx-rotation", "nginx-retention"} {
		t.Run(bad, func(t *testing.T) {
			cfg := DefaultApacheWAFConfig()
			cfg.TrustedProxy = trustedProxyFixture()
			switch bad {
			case "last-address":
				cfg.TrustedProxy.Recursive = false
			case "real-ip":
				cfg.TrustedProxy.Header = "X-Real-IP"
				cfg.TrustedProxy.Recursive = false
			case "no-ack":
				cfg.TrustedProxy.AcknowledgeHeaderControl = false
			case "empty-cidrs":
				cfg.TrustedProxy.TrustedCIDRs = []string{}
			case "all-peers":
				cfg.TrustedProxy.TrustedCIDRs = []string{"0.0.0.0/0"}
			case "nginx-rotation":
				cfg.BodyLogRotation = &WAFBodyLogRotationConfig{}
			case "nginx-retention":
				cfg.BodyLogRetention = &WAFBodyLogRetentionConfig{}
			}
			if _, err := DecodeApacheWAFConfig(WAFSettings(cfg)); err == nil {
				t.Fatal("unsupported Apache semantics accepted")
			}
		})
	}
	for _, enabled := range []bool{false, true} {
		cfg := DefaultApacheWAFConfig()
		cfg.TrustedProxy = trustedProxyFixture()
		cfg.TrustedProxy.Enabled = enabled
		if _, err := DecodeApacheWAFConfig(WAFSettings(cfg)); err != nil {
			t.Fatal(err)
		}
	}
	if cfg, err := DecodeApacheWAFConfig(map[string]any{"profile": "strict", "rate_per_second": 30}); err != nil || cfg.Policy.CCEnabled {
		t.Fatal(cfg, err)
	}
	if _, err := DecodeApacheWAFConfig(map[string]any{"trusted_proxy": WAFSettings(WAFConfig{TrustedProxy: trustedProxyFixture()})["trusted_proxy"]}); err == nil {
		t.Fatal("unrevisioned trust accepted")
	}
}

func TestApacheWAFRejectsUnsupportedRateControls(t *testing.T) {
	cfg := DefaultApacheWAFConfig()
	if _, err := DecodeApacheWAFConfig(WAFSettings(cfg)); err != nil {
		t.Fatal(err)
	}
	cfg.Policy.CCEnabled = true
	if _, err := DecodeApacheWAFConfig(WAFSettings(cfg)); err == nil {
		t.Fatal("unsupported CC falsely accepted")
	}
}
