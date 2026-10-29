package executor

import (
	"encoding/json"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func countryRenderFixture() *core.WAFCountryConfig {
	data := core.WAFCountryDataset{DataManifestSHA: strings.Repeat("a", 64), Release: "2026-10", Revision: 1, Countries: []string{"CN", "US"}}
	data.Dataset = core.WAFCountryDatasetID(data)
	return &core.WAFCountryConfig{Enabled: true, Data: data, Global: core.WAFCountryRule{Mode: "block", List: "deny", Countries: []string{"CN"}}, Sites: []core.WAFCountrySite{}}
}

func TestCountryPolicyNativeMapsUseFixedSignedReferenceAndOnlyControlledRemoteAddress(t *testing.T) {
	cfg := countryRenderFixture()
	cfg.Sites = []core.WAFCountrySite{{SiteID: strings.Repeat("b", 32), Rule: core.WAFCountryRule{Mode: "observe", List: "allow", Countries: []string{"US"}}}, {SiteID: strings.Repeat("c", 32), Rule: core.WAFCountryRule{Mode: "off", Countries: []string{}}}, {SiteID: strings.Repeat("d", 32), Rule: core.WAFCountryRule{Mode: "inherit", Countries: []string{}}}}
	out, active, err := renderWAFCountryMaps(cfg, "block")
	if err != nil || !active {
		t.Fatal(active, err)
	}
	for _, part := range []string{"geo $remote_addr $pw_country_label", `default "--";`, wafCountryDataRoot + "/" + cfg.Data.Dataset + "/CN.cidr", wafCountryDataRoot + "/" + cfg.Data.Dataset + "/US.cidr", `map "$pw_country_label" $pw_country_reject_0`, "default 0;\n  \"CN\" 1;", `map "$pw_country_label" $pw_country_reject_1`, "default 1;\n  \"US\" 0;", `"` + strings.Repeat("b", 32) + `" "observe";`, `"` + strings.Repeat("c", 32) + `" 0;`, `"block:1" "country";`, `"observe:1" "country";`} {
		if !strings.Contains(out, part) {
			t.Fatal("missing closed country rule", part, out)
		}
	}
	for _, forbidden := range []string{"$http_", "geoip", "proxy_recursive", "volatile", "return 403", "return 200", "UNKNOWN", "default ZZ", "\"ZZ\"", strings.Repeat("d", 32)} {
		if strings.Contains(out, forbidden) {
			t.Fatal("caller header/newer-module/unknown/inherit or independent block escaped", forbidden)
		}
	}
	if strings.Count(out, "  include ") != 2 {
		t.Fatal("selected files not exact")
	}
}

func TestCountryPolicyStopRemovesEveryDataIncludeWithoutDeletingOrMutatingCacheReference(t *testing.T) {
	cfg := countryRenderFixture()
	before, _ := json.Marshal(cfg)
	for _, master := range []string{"off", "observe", "block"} {
		out, active, err := renderWAFCountryMaps(cfg, master)
		if err != nil || master == "off" && (active || out != "") || master != "off" && (!active || out == "") {
			t.Fatal(master, active, err, out)
		}
	}
	cfg.Global = core.WAFCountryRule{Mode: "off", Countries: []string{}}
	out, active, err := renderWAFCountryMaps(cfg, "block")
	if err != nil || active || out != "" {
		t.Fatal("disabled country policy kept native includes", out, err)
	}
	cfg.Global = core.WAFCountryRule{Mode: "block", List: "deny", Countries: []string{"CN"}}
	after, _ := json.Marshal(cfg)
	if string(before) != string(after) {
		t.Fatal("pure stop renderer changed immutable data reference")
	}
}

func TestCountryPolicyInvalidReferenceHasNoPartialConfigOrAutomaticFallback(t *testing.T) {
	for _, kind := range []string{"path", "unselected", "null-sites", "mode"} {
		cfg := countryRenderFixture()
		mode := "block"
		switch kind {
		case "path":
			cfg.Data.Dataset = "../../etc/nginx/nginx.conf"
		case "unselected":
			cfg.Global.Countries = []string{"DE"}
		case "null-sites":
			cfg.Sites = nil
		case "mode":
			mode = "enforce-anyway"
		}
		if out, active, err := renderWAFCountryMaps(cfg, mode); err == nil || active || out != "" {
			t.Fatal("invalid policy returned usable partial native config", out, active, err)
		}
	}
}

func TestCountryPolicyIntegratedReasonsStayBelowExistingListsAndDoNotRenumberCCScopes(t *testing.T) {
	base := core.DefaultWAFConfig()
	base.Policy.Sites = []core.WAFSitePolicy{{SiteID: strings.Repeat("b", 32), Mode: "observe", Rate: 30, Burst: 60}}
	beforeHTTP, beforeServer := renderWAFPolicyVersion(base, core.WAFCountryDataVersion)
	base.Country = countryRenderFixture()
	base.Country.Sites = []core.WAFCountrySite{{SiteID: strings.Repeat("a", 32), Rule: core.WAFCountryRule{Mode: "block", List: "allow", Countries: []string{"US"}}}}
	afterHTTP, afterServer := renderWAFPolicyVersion(base, core.WAFCountryDataVersion)
	if beforeServer != afterServer {
		t.Fatal("country-only scope changed established CC zones or server directives")
	}
	for _, part := range []string{`map "$panel_waf_site" $pw_scope`, `"` + strings.Repeat("b", 32) + `" "s1";`, `map "$pw_mode:$pw_health:$pw_has_block" $pw_block`, `"block:0:1" 1;`, `,"country":"$pw_country_label","country_data":"` + base.Country.Data.DataManifestSHA + `"`} {
		if !strings.Contains(afterHTTP, part) {
			t.Fatal("missing integrated country/control contract", part)
		}
	}
	if strings.Contains(afterHTTP, `"`+strings.Repeat("a", 32)+`" "s1";`) || !strings.Contains(beforeHTTP, `"`+strings.Repeat("b", 32)+`" "s1";`) {
		t.Fatal("country-only scope renumbered metadata/CC scope")
	}
	if strings.Index(afterHTTP, "$pw_country_block_reason") > strings.Index(afterHTTP, "$pw_reason_cookie") || strings.Index(afterHTTP, "$pw_reason_ip") < strings.Index(afterHTTP, "$pw_reason_cookie") {
		t.Fatal("country candidate bypassed list or metadata priorities")
	}
	legacyHTTP, legacyServer := renderWAFPolicyVersion(base, "2.5.1")
	if !strings.Contains(legacyHTTP, "invalid_country_policy_version;") || legacyHTTP != legacyServer {
		t.Fatal("old handler rendered future active country settings")
	}
	base.Policy.Mode = "off"
	offHTTP, _ := renderWAFPolicyVersion(base, core.WAFCountryDataVersion)
	if strings.Contains(offHTTP, "pw_country_label") || strings.Contains(offHTTP, ".cidr") {
		t.Fatal("master stop kept native country includes or variables")
	}
}
