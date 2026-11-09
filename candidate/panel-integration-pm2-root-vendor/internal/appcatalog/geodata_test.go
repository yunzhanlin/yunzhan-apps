package appcatalog

import (
	"encoding/json"
	"strings"
	"testing"

	"local/panel/internal/geodata"
)

func TestGeoDataChannelClosedApplicationABI(t *testing.T) {
	m := panelRequirementFixture()
	m.Version = "2.6.0"
	m.RequiredPanelFeatures = []string{StatisticsCursorRetirementFeature, StatisticsRequestIdentityFeature, StatisticsGeographyFeature}
	m.GeoDataChannel = &GeoDataChannel{ID: geodata.Channel, Format: 1}
	if err := validatePanelRequirements(m, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if err := validateGeoDataChannel(m); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"old-version", "alias", "future", "other-app", "provider", "target", "format", "channel", "missing", "handler"} {
		t.Run(kind, func(t *testing.T) {
			v := m
			channel := *m.GeoDataChannel
			v.GeoDataChannel = &channel
			v.RequiredPanelFeatures = append([]string(nil), m.RequiredPanelFeatures...)
			switch kind {
			case "old-version":
				v.Version = "2.5.0"
			case "alias":
				v.Version = "2.6.0-build"
			case "future":
				v.Version = "2.7.0"
			case "other-app":
				v.ID = "website-analytics"
			case "provider":
				v.Delivery.Provider = "compose"
			case "target":
				v.Delivery.Target = "website-analytics"
			case "format":
				v.GeoDataChannel.Format = 2
			case "channel":
				v.GeoDataChannel.ID = "https://evil.invalid"
			case "missing":
				v.GeoDataChannel = nil
			case "handler":
				v.RequiredPanelFeatures = v.RequiredPanelFeatures[:2]
			}
			if kind == "handler" {
				if validatePanelRequirements(v, func(string) bool { return true }) == nil {
					t.Fatal("missing implemented handler accepted")
				}
			} else if validateGeoDataChannel(v) == nil {
				t.Fatal("unsupported data ABI accepted")
			}
		})
	}
	m.Version = "2.5.0"
	m.GeoDataChannel = nil
	if validateGeoDataChannel(m) == nil {
		t.Fatal("old app can claim geography without the new data ABI")
	}
	m.RequiredPanelFeatures = m.RequiredPanelFeatures[:2]
	if err := validateGeoDataChannel(m); err != nil {
		t.Fatal("old application cannot be preserved", err)
	}
	if validatePanelRequirements(panelRequirementFixture(), func(string) bool { return false }) == nil {
		t.Fatal("unsupported panel accepted")
	}
}
func TestGeoDataEnvelopeRejectsKeysAliasesDuplicatesNullAndDataPayloads(t *testing.T) {
	in := GeoDataEnvelope{[]byte("catalog"), []byte("signature"), []byte("manifest"), []byte("data manifest"), []byte("data signature")}
	raw, _ := json.Marshal(in)
	if _, err := DecodeGeoDataEnvelope(raw); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"duplicate": append([]byte(`{"app_catalog":"",`), raw[1:]...), "alias": []byte(strings.Replace(string(raw), `"app_catalog"`, `"App_Catalog"`, 1)), "null": []byte(strings.Replace(string(raw), `"app_catalog":"Y2F0YWxvZw=="`, `"app_catalog":null`, 1)), "extra": append(append([]byte(nil), raw...), []byte(` {}`)...), "payload": append([]byte(`{"database":"attacker bytes",`), raw[1:]...), "key": append([]byte(`{"public_key":"caller-key",`), raw[1:]...), "url": append([]byte(`{"url":"http://127.0.0.1/",`), raw[1:]...), "oversized": []byte(strings.Repeat("x", MaxGeoDataEnvelopeBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeGeoDataEnvelope(data); err == nil {
				t.Fatal("untrusted handoff accepted")
			}
		})
	}
}
