package executor

import (
	"local/panel/internal/core"
	"strings"
	"testing"
)

func TestThreatIDSRuleDataCandidateUsesClosedSeparateRuleReferences(t *testing.T) {
	in := threatIDSConfig{Revision: 1, Interface: "lo", HomeNetworks: []string{"127.0.0.1/32", "::1/128"}}
	selection := core.NetworkIDSRuleFeedSelection{FeedID: "et-open-web-20261009", AppVersion: core.SoftwareImplementationVersion("network-threat-detection"), AppManifestSHA: strings.Repeat("a", 64), RuleManifestSHA: strings.Repeat("b", 64)}
	original, err := threatIDSYAML(in, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil {
		t.Fatal(err)
	}
	text, err := threatIDSRuleDataYAML(in, selection)
	if err != nil {
		t.Fatal(err)
	}
	dir := threatIDSRuleFeedRoot + "/" + selection.FeedID + "-" + selection.RuleManifestSHA
	for _, reference := range []string{`default-rule-path: "` + dir + `"`, `classification-file: "` + dir + `/classification.config"`, `reference-config-file: "` + dir + `/reference.config"`, `  - "et-open.rules"`, `threshold-file: "/opt/panel/app-modules/network-threat-detection/rules/threshold.config"`} {
		if !strings.Contains(text, reference) {
			t.Fatal("closed reference missing", reference)
		}
	}
	for _, marker := range []string{"include:", "lua:", "copy-mode", "nfqueue", `  - "cloudstack.rules"`} {
		if strings.Contains(text, marker) {
			t.Fatal("candidate widened capture or merged indicator rules", marker)
		}
	}
	for _, marker := range []string{"payload: no", "http-body: no", "packet: no", "metadata: no", "disable-promisc: yes", "threads: 1", "memcap: 64mb"} {
		if !strings.Contains(text, marker) {
			t.Fatal("privacy or resource policy removed", marker)
		}
	}
	unchanged, _ := threatIDSYAML(in, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if unchanged != original {
		t.Fatal("rendering candidate changed original profile")
	}
	for _, scenario := range []string{"path-id", "path-sha", "future-handler", "invalid-app-sha"} {
		t.Run(scenario, func(t *testing.T) {
			bad := selection
			switch scenario {
			case "path-id":
				bad.FeedID = "../../etc"
			case "path-sha":
				bad.RuleManifestSHA = "../bad"
			case "future-handler":
				bad.AppVersion = "99.0.0"
			case "invalid-app-sha":
				bad.AppManifestSHA = "caller-trust"
			}
			if _, err := threatIDSRuleDataYAML(in, bad); err == nil {
				t.Fatal("unclosed candidate accepted")
			}
		})
	}
}
