package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNetworkIDSRuleProfileChoiceIsClosedExplicitAndActionSpecific(t *testing.T) {
	selection := networkRuleFeedSelectionFixture()
	for _, choice := range []NetworkIDSRuleProfileSelection{{Source: "original"}, {Source: "verified-feed", Selection: &selection}} {
		request := NetworkIDSOperationRequest{Action: "ids-rules", Input: NetworkIDSOperationInput{ExpectedRevision: 7, RuleProfile: &choice}}
		raw, _ := json.Marshal(request)
		decoded, err := DecodeNetworkIDSOperationRequest(raw)
		if err != nil || decoded.Input.RuleProfile.Source != choice.Source {
			t.Fatal("closed choice roundtrip", err)
		}
		body, _ := json.Marshal(request.Input)
		if _, err := decodeNetworkIDSOperationInput("ids-rules", body); err != nil {
			t.Fatal(err)
		}
		if _, err := decodeNetworkIDSOperationInput("ids-config", body); err == nil {
			t.Fatal("interface save switched rule choice")
		}
	}
	good, _ := json.Marshal(NetworkIDSRuleProfileSelection{Source: "verified-feed", Selection: &selection})
	for _, raw := range []string{
		`null`, `{}`, `{"source":null}`, `{"source":""}`, `{"source":"inline"}`, `{"Source":"original"}`, `{"source":"original","source":"original"}`,
		`{"source":"original","sour\u0063e":"original"}`, `{"source":"original","selection":null}`, `{"source":"original","url":"https://evil.invalid"}`,
		`{"source":"verified-feed"}`, `{"source":"verified-feed","selection":{}}`, `{"source":"original"} {}`,
		strings.Replace(string(good), `"feed_id":`, `"FEED_ID":`, 1), strings.Replace(string(good), `"feed_id":`, `"feed_id":"et-open-web-20261009","feed_id":`, 1),
		strings.Replace(string(good), selection.RuleManifestSHA, "../rules", 1), strings.Replace(string(good), selection.AppVersion, "99.0.0", 1),
	} {
		if _, err := decodeNetworkIDSRuleProfile([]byte(raw)); err == nil {
			t.Fatal("unclosed or future rule choice accepted", raw)
		}
	}
	if _, err := decodeNetworkIDSOperationInput("ids-rules", []byte(`{"expected_revision":1}`)); err == nil {
		t.Fatal("omission silently selected original")
	}
	if _, err := decodeNetworkIDSOperationInput("ids-rules", []byte(`{"expected_revision":1,"rule_profile":{"source":"original"},"enabled":false}`)); err == nil {
		t.Fatal("rules changed boot selection")
	}
}

func TestNetworkIDSRuleProfileImplementationVersionNeverOverwritesPublicOldRelease(t *testing.T) {
	if SoftwareImplementationVersion("network-threat-detection") != "1.3.0" {
		t.Fatal("new rule profile handler reuses the old immutable application version")
	}
	for _, version := range []string{"1.2.0", "1.3.0"} {
		if err := ValidateSoftwareUpdate("network-threat-detection", version); err != nil {
			t.Fatal("reviewed old/new handler version rejected", version, err)
		}
	}
	if ValidateSoftwareUpdate("network-threat-detection", "1.4.0") == nil {
		t.Fatal("unimplemented future handler version advertised as usable")
	}
}
