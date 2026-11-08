package core

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWAFCountryMasterPausePreservesSelectionAndOverrides(t *testing.T) {
	cfg := countryPolicyFixture()
	cfg.Sites = []WAFCountrySite{{SiteID: ID(), Rule: WAFCountryRule{Mode: "block", List: "allow", Countries: []string{"US"}}}}
	before, _ := json.Marshal(cfg)
	cfg.Enabled = false
	raw, _ := json.Marshal(cfg)
	got, err := DecodeWAFCountryConfig(raw)
	if err != nil || got.Enabled || ValidateWAFCountryConfig(&got) != nil {
		t.Fatal("pause lost valid intent", err)
	}
	for _, mode := range []string{"off", "observe", "block"} {
		rule, err := WAFCountryEffectiveRule(&got, cfg.Sites[0].SiteID, mode)
		if err != nil || rule.Mode != "off" {
			t.Fatal("paused country rules remained active", mode, rule, err)
		}
	}
	got.Enabled = true
	after, _ := json.Marshal(got)
	if !bytes.Equal(before, after) {
		t.Fatal("pause/resume changed data or selections")
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"enabled":false`), []byte(`"enabled":"false"`), 1),
		bytes.Replace(raw, []byte(`"enabled":false,`), nil, 1),
		bytes.Replace(raw, []byte(`"enabled":false`), []byte(`"enabled":false,"enabled":true`), 1),
	} {
		if _, err := DecodeWAFCountryConfig(bad); err == nil {
			t.Fatal("ambiguous master switch accepted")
		}
	}
}
