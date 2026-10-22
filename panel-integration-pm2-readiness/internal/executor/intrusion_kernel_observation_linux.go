//go:build linux

package executor

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
)

func intrusionBannedAddresses(raw string) ([]netip.Addr, error) {
	if len(raw) > 24<<10 || strings.ContainsAny(raw, "\x00\r") {
		return nil, errors.New("运行中封禁列表不完整或超限")
	}
	labels := strings.Fields(raw)
	if len(labels) > 512 {
		return nil, errors.New("运行中封禁列表超过本次完整核验上限")
	}
	ips := []netip.Addr{}
	seen := map[netip.Addr]bool{}
	for _, label := range labels {
		ip, err := netip.ParseAddr(label)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || seen[ip] {
			return nil, errors.New("运行中封禁地址格式未知或重复")
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
	return ips, nil
}

func intrusionNftProperty(raw string) (string, error) {
	if len(raw) < 2 || len(raw) > 128 || !strings.HasSuffix(raw, "\n") || strings.ContainsAny(strings.TrimSuffix(raw, "\n"), "\r\n\t\x00 ") {
		return "", errors.New("内核动作属性不是有界的单行规范值")
	}
	return strings.TrimSuffix(raw, "\n"), nil
}
func intrusionNftSetProperty(raw, name string) (string, error) {
	value, err := intrusionNftProperty(raw)
	if err != nil {
		return "", err
	}
	// Only this fixed upstream tag is resolved; never recursive interpolation,
	// other tag names, arbitrary expressions or commands.
	if strings.Count(value, "<name>") > 1 {
		return "", errors.New("内核动作集合标签重复")
	}
	value = strings.ReplaceAll(value, "<name>", name)
	if !intrusionNftName(value) {
		return "", errors.New("内核动作集合身份未知")
	}
	return value, nil
}

func intrusionNftObservedChain(raw []byte, scope intrusionNftScope) (string, error) {
	var document map[string][]map[string]any
	if len(raw) > 24<<10 || decodeApacheWAFPrivateJSON(raw, &document, map[string]bool{"nftables": true}, 8000) != nil {
		return "", errors.New("内核链定位输出不可核对")
	}
	chains := map[string]bool{}
	for _, object := range document["nftables"] {
		rule, ok := object["rule"].(map[string]any)
		if !ok || rule["table"] != scope.Table || rule["family"] != "inet" {
			continue
		}
		name, _, _, err := intrusionNftRejectingRule(rule)
		if err != nil {
			continue
		}
		if name != scope.IPv4Set && name != scope.IPv6Set {
			continue
		}
		chain, ok := rule["chain"].(string)
		if !ok || !intrusionNftName(chain) {
			return "", errors.New("内核实际拦截链身份无效")
		}
		chains[chain] = true
	}
	if len(chains) != 1 {
		return "", errors.New("内核实际拦截链缺失或存在多个不明确链")
	}
	for chain := range chains {
		return chain, nil
	}
	return "", errors.New("内核实际拦截链缺失")
}

// The caller supplies only the fixed read adapter bound to its single overall
// deadline. This cannot execute nft input, reload a Jail, ban or unban an IP.
func inspectIntrusionKernel(read func(string, ...string) (string, error), action string, ports []int, banned []netip.Addr) (intrusionNftObservation, error) {
	out := intrusionNftObservation{}
	if !intrusionNftName(action) {
		return out, errors.New("运行中动作身份未核验")
	}
	values := map[string]string{}
	for _, property := range []string{"name", "table", "table_family", "addr_set", "addr_set?family=inet6"} {
		raw, err := read("/usr/bin/fail2ban-client", "get", "sshd", "action", action, property)
		if err != nil {
			return out, errors.New("内核动作完整属性无法读取")
		}
		values[property] = raw
	}
	name, err := intrusionNftProperty(values["name"])
	if err != nil || !intrusionNftName(name) {
		return out, errors.New("内核动作名称无效")
	}
	table, err := intrusionNftProperty(values["table"])
	if err != nil || !intrusionNftName(table) || values["table_family"] != "inet\n" {
		return out, errors.New("内核动作表或地址族未支持核验")
	}
	set4, err := intrusionNftSetProperty(values["addr_set"], name)
	if err != nil {
		return out, err
	}
	set6, err := intrusionNftSetProperty(values["addr_set?family=inet6"], name)
	if err != nil {
		return out, err
	}
	raw, err := read("/usr/sbin/nft", "-j", "list", "table", "inet", table)
	if err != nil {
		if len(banned) == 0 {
			directory, directoryErr := read("/usr/sbin/nft", "-j", "list", "tables")
			if directoryErr == nil && intrusionNftTableKnownAbsent([]byte(directory), table) == nil {
				return intrusionNftObservation{Deferred: true}, nil
			}
		}
		return out, errors.New("实际内核拦截表无法读取；未将动作属性当作生效证明")
	}
	scope := intrusionNftScope{Table: table, IPv4Set: set4, IPv6Set: set6, Ports: slices.Clone(ports), Banned: slices.Clone(banned)}
	scope.Chain, err = intrusionNftObservedChain([]byte(raw), scope)
	if err != nil {
		if len(banned) == 0 {
			// A shared table can exist for another Jail while SSHD is lazy.
			// Only the fixed chain property is read, then the COMPLETE actual
			// chain is checked for bypasses and partial/orphaned own objects.
			chainRaw, chainErr := read("/usr/bin/fail2ban-client", "get", "sshd", "action", action, "chain")
			chain, decodeErr := intrusionNftProperty(chainRaw)
			if chainErr == nil && decodeErr == nil && chain == "<known/chain>" {
				resolved, readErr := read("/usr/bin/fail2ban-client", "get", "sshd", "action", action, "actionstart")
				if readErr != nil {
					return out, errors.New("延迟内核链的完整固定动作无法读取")
				}
				chain, decodeErr = intrusionNftLazyChain(resolved, table, ports)
			}
			if chainErr == nil && decodeErr == nil && intrusionNftName(chain) {
				scope.Chain = chain
				if _, check := inspectIntrusionNftScope([]byte(raw), scope); errors.Is(check, errIntrusionNftScopeAbsent) {
					return intrusionNftObservation{Deferred: true}, nil
				}
			}
		}
		return out, err
	}
	return inspectIntrusionNftScope([]byte(raw), scope)
}
