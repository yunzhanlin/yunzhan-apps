//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"local/panel/internal/core"
)

// A rule-only transaction must not turn a historical ban set into authority.
// Compare the complete typed policy while allowing positively identified plain
// IP set contents to evolve. Handles, chain hooks, every rule's order, matches,
// verdicts, table/chain/set metadata and unknown fields are never discarded.
// The supplied CURRENT scope must first agree with CURRENT Fail2ban bans.
func intrusionNftPolicyIdentity(raw []byte, current intrusionNftScope) (string, error) {
	return intrusionNftObservedPolicyIdentity(raw, current, false)
}

func intrusionNftObservedPolicyIdentity(raw []byte, current intrusionNftScope, deferred bool) (string, error) {
	return intrusionNftRetainedPolicyIdentity(raw, current, deferred, nil)
}

// A transaction that observed an absent address-family scope may later see it
// created by the daemon's real first ban. Only those newly verified OWNED
// objects can be omitted for comparison with the historical static baseline.
// nil retains every owned object; an empty map compares only unowned policy.
// Existing historical handles/metadata are always retained by the caller.
func intrusionNftRetainedPolicyIdentity(raw []byte, current intrusionNftScope, deferred bool, retained map[string]bool) (string, error) {
	for name, keep := range retained {
		if !keep || name != current.IPv4Set && name != current.IPv6Set {
			return "", errors.New("受管内核比较范围不是明确地址族集合")
		}
	}
	_, err := inspectIntrusionNftScope(raw, current)
	if err != nil && !(deferred && len(current.Banned) == 0 && errors.Is(err, errIntrusionNftScopeAbsent)) {
		return "", err
	}
	var doc map[string][]map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return "", errors.New("内核策略原文无法重新解析")
	}
	projection := []map[string]any{}
	for _, object := range doc["nftables"] {
		if _, ok := object["metainfo"]; ok {
			// nft's version/json-schema transport metadata is not kernel policy.
			continue
		}
		if set, ok := object["set"].(map[string]any); ok {
			name, _ := set["name"].(string)
			if retained != nil && (name == current.IPv4Set || name == current.IPv6Set) && !retained[name] {
				continue
			}
			if !intrusionNftObjectKeys(set, []string{"family", "table", "name", "handle", "type"}, "elem") || set["type"] != "ipv4_addr" && set["type"] != "ipv6_addr" {
				return "", errors.New("共享表集合格式未支持动态地址观察，未忽略未知字段")
			}
			name, named := set["name"].(string)
			handle, numbered := set["handle"].(float64)
			if !named || !intrusionNftName(name) || !numbered || handle < 1 || handle > 9007199254740991 || handle != float64(int64(handle)) {
				return "", errors.New("共享表动态集合身份或句柄无法核对")
			}
			if elems, present := set["elem"]; present {
				values, ok := elems.([]any)
				if !ok || len(values) > 512 {
					return "", errors.New("共享表动态集合容量或格式未知")
				}
				seen := map[netip.Addr]bool{}
				for _, value := range values {
					label, ok := value.(string)
					if !ok {
						return "", errors.New("共享表动态集合不是普通地址元素")
					}
					ip, err := netip.ParseAddr(label)
					if err != nil || ip.Zone() != "" || ip.Is4In6() || seen[ip] || (set["type"] == "ipv4_addr") != ip.Is4() {
						return "", errors.New("共享表动态集合地址无效或重复")
					}
					seen[ip] = true
				}
			}
			delete(set, "elem")
		}
		if rule, ok := object["rule"].(map[string]any); ok && rule["chain"] == current.Chain {
			set, _, ports, err := intrusionNftRejectingRule(rule)
			if err != nil {
				return "", err
			}
			if set == current.IPv4Set || set == current.IPv6Set {
				if retained != nil && !retained[set] {
					if _, manual := rule["comment"]; manual {
						return "", errors.New("新地址族规则含外部元数据，未自动接管")
					}
					continue
				}
				if !slices.Equal(ports, current.Ports) {
					return "", errors.New("受管规则端口不是本次完整观察范围")
				}
				match := rule["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)
				// This one positively typed numeric match is transaction-owned.
				// Future runtime preflight must separately require BEFORE or AFTER.
				match["right"] = map[string]any{"managed_ssh_ports": true}
			}
		}
		projection = append(projection, object)
	}
	data, err := json.Marshal(projection)
	if err != nil {
		return "", err
	}
	return core.Hash(string(data)), nil
}
