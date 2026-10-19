package executor

import (
	"errors"
	"local/panel/internal/core"
	"strings"
)

const threatIDSRuleFeedRoot = "/opt/panel/network-rule-feeds"

// Pure closed renderer, never signing authority or proof of native syntax.
// Root must independently verify the selected store before use, including at
// boot and recovery. An application version newer than this handler is denied.
func threatIDSRuleDataYAML(in threatIDSConfig, selection core.NetworkIDSRuleFeedSelection) (string, error) {
	if err := core.ValidateNetworkIDSRuleFeedSelection(selection); err != nil {
		return "", err
	}
	if err := core.ValidateSoftwareUpdate("network-threat-detection", selection.AppVersion); err != nil {
		return "", err
	}
	original := in
	original.RuleFeed = nil
	text, err := threatIDSYAML(original, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil {
		return "", err
	}
	dir := threatIDSRuleFeedRoot + "/" + selection.FeedID + "-" + selection.RuleManifestSHA
	// Closed names only. The original six-file indicator set and threshold are
	// preserved; the ET profile uses its own classification/reference data and
	// does NOT merge conflicting definitions with the original indicator rules.
	for _, pair := range [][2]string{
		{`default-rule-path: "/opt/panel/app-modules/network-threat-detection/rules"`, `default-rule-path: "` + dir + `"`},
		{`classification-file: "/opt/panel/app-modules/network-threat-detection/rules/classification.config"`, `classification-file: "` + dir + `/classification.config"`},
		{`reference-config-file: "/opt/panel/app-modules/network-threat-detection/rules/reference.config"`, `reference-config-file: "` + dir + `/reference.config"`},
		{`  - "cloudstack.rules"`, `  - "et-open.rules"`},
	} {
		if strings.Count(text, pair[0]) != 1 {
			return "", errors.New("IDS 原始受限配置的规则引用不唯一；未产生候选")
		}
		text = strings.Replace(text, pair[0], pair[1], 1)
	}
	return text, nil
}
