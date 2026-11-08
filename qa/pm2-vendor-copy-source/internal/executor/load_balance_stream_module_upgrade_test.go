package executor

import (
	"strings"
	"testing"
)

func TestLoadBalanceStreamModuleUpgradeLegacyRecognitionGrantsNoNativeMigration(t *testing.T) {
	for _, version := range []string{"", "1.0", "1.0.0", "1.6.0", "1.8.3", "1.8.4", "1.8.5"} {
		raw := []byte(`{"id":"load-balance","version":"` + version + `","settings":{},"installed_at":"2026-10-24T00:00:00Z"}`)
		if _, err := decodeLoadBalanceStreamModuleVersion(raw, true); err != nil {
			t.Fatal("old original HTTP version obstructed read-only upgrade", version, err)
		}
		if _, err := decodeLoadBalanceStreamModule(raw); (err == nil) != (version == "1.8.4" || version == "1.8.5") {
			t.Fatal("read-only compatibility widened native effect migration", version)
		}
		if _, err := decodeLoadBalanceStreamModuleVersion([]byte(strings.Replace(string(raw), `"settings":{}`, `"settings":{},"installation_id":"`+strings.Repeat("a", 32)+`"`, 1)), true); err == nil {
			t.Fatal("old version acquired native epoch")
		}
	}
	for _, raw := range []string{
		`{"id":"load-balance","version":"1.9.0"}`,
		`{"id":"load-balance","version":"1.9.1"}`,
		`{"id":"load-balance","version":"2.0.0"}`,
		`{"id":"load-balance","version":"bad"}`,
		`{"id":"load-balance","version":"1.6.0","Version":"1.9.0"}`,
		`{"id":"load-balance","version":"1.6.0","unexpected":true}`,
	} {
		if _, err := decodeLoadBalanceStreamModuleVersion([]byte(raw), true); err == nil {
			t.Fatal("native, malformed or ambiguous history treated as old HTTP", raw)
		}
	}
}
