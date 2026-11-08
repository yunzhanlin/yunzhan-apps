package core

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func countryPolicyFixture() WAFCountryConfig {
	in := countryDataSelectionFixture()
	data := WAFCountryDataset{DataManifestSHA: in.DataManifestSHA, Release: in.Release, Revision: in.Revision, Countries: append([]string{}, in.Countries...)}
	data.Dataset = WAFCountryDatasetID(data)
	return WAFCountryConfig{Enabled: true, Data: data, Global: WAFCountryRule{Mode: "block", List: "deny", Countries: []string{"CN"}}, Sites: []WAFCountrySite{}}
}

func TestWAFCountryPolicyClosedDatasetAndRuleShapeDoesNotGrantSourceOrInstallationAuthority(t *testing.T) {
	cfg := countryPolicyFixture()
	raw, _ := json.Marshal(cfg)
	got, err := DecodeWAFCountryConfig(raw)
	if err != nil || !reflect.DeepEqual(got, cfg) || cfg.Data.Dataset != WAFCountryCacheDataset(countryDataSelectionFixture()) {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"null", "{}", string(raw) + ` {}`, strings.Replace(string(raw), `"data":{`, `"Data":{`, 1), strings.Replace(string(raw), `"mode":"block"`, `"mode":"block","mode":"block"`, 1), strings.Replace(string(raw), `"data":{`, `"data":{"path":"/etc/nginx/nginx.conf",`, 1), strings.Replace(string(raw), `"global":{`, `"global":{"unknown_action":"allow",`, 1), strings.Replace(string(raw), `"sites":[]`, `"sites":null`, 1), strings.Replace(string(raw), `"countries":["CN","US"]`, `"countries":["US","CN"]`, 1), strings.Replace(string(raw), `"countries":["CN"]`, `"countries":["ZZ"]`, 1), strings.TrimSuffix(string(raw), "}") + `,"verified":true}`, strings.Repeat(" ", 32<<10+1)} {
		if value, err := DecodeWAFCountryConfig([]byte(bad)); err == nil || !reflect.DeepEqual(value, WAFCountryConfig{}) {
			t.Fatal("unqualified future country policy accepted", value, err)
		}
	}
	// Current2.5.1 MUST still reject this future field. Publishing a signed
	// app with a new name/version cannot make the old handler enforce it.
	settings := WAFSettings(DefaultWAFConfig())
	settings["country"] = cfg
	if WAFVersion != WAFCountryDataVersion {
		if _, err := DecodeWAFConfig(settings); err == nil {
			t.Fatal("unfinished current WAF handler borrowed future country policy")
		}
	}
}

func TestWAFCountryPolicyRejectsForeignDatasetUnselectedCountryAndAmbiguousSiteOverrides(t *testing.T) {
	for _, kind := range []string{"dataset", "release", "revision", "data-order", "global-inherit", "unknown-mode", "unknown-list", "unselected", "off-countries", "off-list", "sites-null", "sites-full", "site-duplicate", "site-order", "site-inherit-content", "site-off-content"} {
		t.Run(kind, func(t *testing.T) {
			cfg := countryPolicyFixture()
			switch kind {
			case "dataset":
				cfg.Data.Dataset = strings.Repeat("a", 64) + "-" + strings.Repeat("b", 64)
			case "release":
				cfg.Data.Release = "2026-13"
			case "revision":
				cfg.Data.Revision = 1001
			case "data-order":
				cfg.Data.Countries = []string{"US", "CN"}
			case "global-inherit":
				cfg.Global.Mode = "inherit"
			case "unknown-mode":
				cfg.Global.Mode = "simulate"
			case "unknown-list":
				cfg.Global.List = "unknown-allow"
			case "unselected":
				cfg.Global.Countries = []string{"DE"}
			case "off-countries":
				cfg.Global.Mode = "off"
			case "off-list":
				cfg.Global.Mode = "off"
				cfg.Global.Countries = []string{}
			case "sites-null":
				cfg.Sites = nil
			case "sites-full":
				cfg.Sites = make([]WAFCountrySite, 65)
			case "site-duplicate":
				s := WAFCountrySite{strings.Repeat("a", 32), WAFCountryRule{Mode: "inherit", Countries: []string{}}}
				cfg.Sites = []WAFCountrySite{s, s}
			case "site-order":
				cfg.Sites = []WAFCountrySite{{strings.Repeat("b", 32), WAFCountryRule{Mode: "inherit", Countries: []string{}}}, {strings.Repeat("a", 32), WAFCountryRule{Mode: "off", Countries: []string{}}}}
			case "site-inherit-content":
				cfg.Sites = []WAFCountrySite{{strings.Repeat("a", 32), WAFCountryRule{Mode: "inherit", List: "deny", Countries: []string{"CN"}}}}
			case "site-off-content":
				cfg.Sites = []WAFCountrySite{{strings.Repeat("a", 32), WAFCountryRule{Mode: "off", List: "allow", Countries: []string{"US"}}}}
			}
			if ValidateWAFCountryConfig(&cfg) == nil {
				t.Fatal("ambiguous country policy accepted", kind)
			}
		})
	}
}

func TestWAFCountryPolicyMasterOffAndObserveCannotBecomeBlockingThroughCountryOverride(t *testing.T) {
	cfg := countryPolicyFixture()
	site := strings.Repeat("a", 32)
	for _, override := range []WAFCountryRule{{Mode: "inherit", Countries: []string{}}, {Mode: "off", Countries: []string{}}, {Mode: "observe", List: "allow", Countries: []string{"US"}}, {Mode: "block", List: "allow", Countries: []string{"US"}}} {
		cfg.Sites = []WAFCountrySite{{site, override}}
		for _, master := range []string{"off", "observe", "block"} {
			got, err := WAFCountryEffectiveRule(&cfg, site, master)
			if err != nil {
				t.Fatal(err)
			}
			want := override.Mode
			if want == "inherit" {
				want = cfg.Global.Mode
			}
			if master == "off" {
				want = "off"
			} else if master == "observe" && want == "block" {
				want = "observe"
			}
			if got.Mode != want {
				t.Fatal(master, override, got, want)
			}
		}
	}
	cfg.Global = WAFCountryRule{Mode: "off", Countries: []string{}}
	cfg.Sites = []WAFCountrySite{{site, WAFCountryRule{Mode: "block", List: "deny", Countries: []string{"CN"}}}}
	if got, err := WAFCountryEffectiveRule(&cfg, site, "block"); err != nil || got.Mode != "block" {
		t.Fatal("explicit site override did not override inactive DEFAULT", got, err)
	}
	if got, err := WAFCountryEffectiveRule(&cfg, "", "block"); err != nil || got.Mode != "off" {
		t.Fatal("site override escaped into global scope", got, err)
	}
}

func TestWAFCountryPolicyNonMatchIsNotUnknownCountryAndAllowDenyHaveExplicitSemantics(t *testing.T) {
	for _, list := range []string{"allow", "deny"} {
		rule := WAFCountryRule{Mode: "block", List: list, Countries: []string{"CN"}}
		for _, country := range []string{"CN", "US", "--"} {
			got, err := WAFCountryRuleWouldReject(rule, country)
			want := country == "CN"
			if list == "allow" {
				want = !want
			}
			if err != nil || got != want {
				t.Fatal(list, country, got, want, err)
			}
		}
		for _, country := range []string{"ZZ", "us", "CN;", "", "$http_x_forwarded_for"} {
			if _, err := WAFCountryRuleWouldReject(rule, country); err == nil {
				t.Fatal("foreign country label accepted", country)
			}
		}
	}
	if reject, err := WAFCountryRuleWouldReject(WAFCountryRule{Mode: "off", Countries: []string{}}, "--"); err != nil || reject {
		t.Fatal(reject, err)
	}
}

func TestWAFCountryPolicyEffectiveRulesAreDetachedAndNeverAcceptCallerReadinessFlags(t *testing.T) {
	cfg := countryPolicyFixture()
	rule, err := WAFCountryEffectiveRule(&cfg, "", "block")
	if err != nil {
		t.Fatal(err)
	}
	rule.Countries[0] = "US"
	if cfg.Global.Countries[0] != "CN" {
		t.Fatal("effective rule aliases mutable input")
	}
	raw, _ := json.Marshal(cfg)
	for _, field := range []string{`"verified":true`, `"active":true`, `"source":"https://evil.invalid"`, `"public_key":"fake"`, `"path":"/tmp/fake"`} {
		if _, err := DecodeWAFCountryConfig([]byte(strings.TrimSuffix(string(raw), "}") + "," + field + "}")); err == nil {
			t.Fatal("caller readiness/source authority accepted", field)
		}
	}
}
