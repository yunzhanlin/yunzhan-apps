package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func trustedProxyFixture() *WAFTrustedProxyConfig {
	return &WAFTrustedProxyConfig{Enabled: true, Header: "X-Forwarded-For", Recursive: true, TrustedCIDRs: []string{"127.0.0.1/32", "2001:db8::/32"}, AcknowledgeHeaderControl: true}
}
func TestWAFTrustedProxyStrictExplicitRanges(t *testing.T) {
	if err := ValidateWAFTrustedProxy(nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWAFTrustedProxy(trustedProxyFixture()); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/7", "2001::/16", "127.0.0.1/24", "proxy.example.test", "unix:", "127.0.0.1:80", "::ffff:192.0.2.1/128", "224.0.0.0/8", "255.255.255.255/32", "2001:0db8::/32", "127.0.0.1/32; return 200;"} {
		t.Run(bad, func(t *testing.T) {
			v := trustedProxyFixture()
			v.TrustedCIDRs = []string{bad}
			if ValidateWAFTrustedProxy(v) == nil {
				t.Fatal("unsafe proxy range accepted")
			}
		})
	}
	for _, mutate := range []func(*WAFTrustedProxyConfig){func(v *WAFTrustedProxyConfig) { v.AcknowledgeHeaderControl = false }, func(v *WAFTrustedProxyConfig) { v.Header = "proxy_protocol" }, func(v *WAFTrustedProxyConfig) { v.Header = "X-Real-IP" }, func(v *WAFTrustedProxyConfig) { v.TrustedCIDRs = nil }, func(v *WAFTrustedProxyConfig) { v.TrustedCIDRs = []string{} }, func(v *WAFTrustedProxyConfig) { v.TrustedCIDRs = []string{"127.0.0.0/8", "127.0.0.1/32"} }, func(v *WAFTrustedProxyConfig) { v.TrustedCIDRs = make([]string, 33) }} {
		v := trustedProxyFixture()
		mutate(v)
		if ValidateWAFTrustedProxy(v) == nil {
			t.Fatal("unsafe or unacknowledged trust accepted", v)
		}
	}
	v := trustedProxyFixture()
	v.Header = "X-Real-IP"
	v.Recursive = false
	if ValidateWAFTrustedProxy(v) != nil {
		t.Fatal("single address header rejected")
	}
	v = &WAFTrustedProxyConfig{Header: "X-Forwarded-For", TrustedCIDRs: []string{}}
	if ValidateWAFTrustedProxy(v) != nil {
		t.Fatal("explicit disabled policy rejected")
	}
}
func TestWAFProxyOmissionPreservesHistoricalShapeAndApacheSemantics(t *testing.T) {
	legacy := DefaultWAFConfig()
	raw, err := json.Marshal(legacy)
	if err != nil || strings.Contains(string(raw), "trusted_proxy") {
		t.Fatal("legacy fingerprint shape changed", err)
	}
	decoded, err := DecodeWAFConfig(WAFSettings(legacy))
	if err != nil || decoded.TrustedProxy != nil {
		t.Fatal("legacy policy acquired proxy trust", err)
	}
	legacy.TrustedProxy = trustedProxyFixture()
	decoded, err = DecodeWAFConfig(WAFSettings(legacy))
	if err != nil || !decoded.TrustedProxy.Enabled {
		t.Fatal("explicit trust rejected", err)
	}
	legacy.Policy.CCEnabled = false
	if _, err := DecodeApacheWAFConfig(WAFSettings(legacy)); err != nil {
		t.Fatal("Apache rejected explicitly acknowledged recursive XFF trust", err)
	}
	legacy.TrustedProxy.Recursive = false
	if _, err := DecodeApacheWAFConfig(WAFSettings(legacy)); err == nil {
		t.Fatal("Apache accepted Nginx-only nonrecursive semantics")
	}
	rawSettings := WAFSettings(legacy)
	rawSettings["trusted_proxy"].(map[string]any)["bypass_verification"] = true
	if _, err := DecodeWAFConfig(rawSettings); err == nil {
		t.Fatal("unknown proxy field accepted")
	}
}
