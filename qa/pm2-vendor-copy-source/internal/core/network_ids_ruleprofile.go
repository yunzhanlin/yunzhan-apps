package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Rule choice is separate from interface configuration. No filename, URL,
// executable or caller-supplied trust material is accepted. Returning to the
// original indicators requires an explicit choice, not an omitted feed field.
type NetworkIDSRuleProfileSelection struct {
	Source    string                       `json:"source"`
	Selection *NetworkIDSRuleFeedSelection `json:"selection,omitempty"`
}

func ValidateNetworkIDSRuleProfile(in NetworkIDSRuleProfileSelection) error {
	switch in.Source {
	case "original":
		if in.Selection == nil {
			return nil
		}
	case "verified-feed":
		if in.Selection != nil {
			if err := ValidateNetworkIDSRuleFeedSelection(*in.Selection); err != nil {
				return err
			}
			return ValidateSoftwareUpdate("network-threat-detection", in.Selection.AppVersion)
		}
	}
	return errors.New("IDS 规则选择必须明确为原创指标或完整绑定的已签名数据")
}

func decodeNetworkIDSRuleProfile(raw []byte) (NetworkIDSRuleProfileSelection, error) {
	var out NetworkIDSRuleProfileSelection
	if len(raw) < 1 || len(raw) > 1536 {
		return out, errors.New("IDS 规则选择超过容量")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return out, errors.New("IDS 规则选择必须为闭合对象")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] || name != "source" && name != "selection" {
			return out, errors.New("IDS 规则选择字段重复或未知")
		}
		seen[name] = true
		if name == "selection" {
			var selected json.RawMessage
			if err := d.Decode(&selected); err != nil {
				return out, err
			}
			selection, err := decodeNetworkIDSRuleFeedSelection(selected)
			if err != nil {
				return out, err
			}
			out.Selection = &selection
		} else if err := d.Decode(&out.Source); err != nil || out.Source == "" {
			return out, errors.New("IDS 规则来源必须为明确字符串")
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') || !seen["source"] {
		return out, errors.New("IDS 规则选择不完整")
	}
	if _, err := d.Token(); err != io.EOF {
		return out, errors.New("IDS 规则选择有多余内容")
	}
	return out, ValidateNetworkIDSRuleProfile(out)
}
