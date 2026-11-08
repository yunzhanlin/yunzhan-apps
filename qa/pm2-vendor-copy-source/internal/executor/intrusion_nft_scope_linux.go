//go:build linux

package executor

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
)

// Closed source-backed identities; never a user-supplied command or path.
type intrusionNftScope struct {
	Table, Chain, IPv4Set, IPv6Set string
	Ports                          []int
	Banned                         []netip.Addr
}
type intrusionNftObservation struct {
	Verified, IPv4, IPv6 bool
	Deferred             bool
	ActiveBans           int
}

var errIntrusionNftScopeAbsent = errors.New("尚无可核验的内核受管拦截作用域")

func intrusionNftName(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for i, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '-')) {
			return false
		}
	}
	return true
}
func intrusionNftNumber(raw any) (int, bool) {
	value, ok := raw.(float64)
	if !ok || value < 1 || value > 65535 || float64(int(value)) != value {
		return 0, false
	}
	return int(value), true
}
func intrusionNftPorts(raw any) ([]int, error) {
	if n, ok := intrusionNftNumber(raw); ok {
		return []int{n}, nil
	}
	value, ok := raw.(map[string]any)
	if !ok || len(value) != 1 {
		return nil, errors.New("内核端口表达式无法核验")
	}
	list, ok := value["set"].([]any)
	if !ok || len(list) < 1 || len(list) > intrusionMaxPorts {
		return nil, errors.New("内核端口集合不完整或超限")
	}
	ports := []int{}
	seen := map[int]bool{}
	for _, item := range list {
		n, ok := intrusionNftNumber(item)
		if !ok || seen[n] {
			return nil, errors.New("内核端口集合含非规范或重复值")
		}
		seen[n] = true
		ports = append(ports, n)
	}
	slices.Sort(ports)
	return ports, nil
}
func intrusionNftObjectKeys(value map[string]any, required []string, optional ...string) bool {
	allowed := map[string]bool{}
	for _, key := range append(slices.Clone(required), optional...) {
		allowed[key] = true
	}
	for key := range value {
		if !allowed[key] {
			return false
		}
	}
	for _, key := range required {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}

// Unknown verdicts, jumps, extra matches or counters are not assumed equivalent.
// An earlier accept in this shared chain must not bypass the claimed rule.
func intrusionNftRejectingRule(raw map[string]any) (string, string, []int, error) {
	fail := func() (string, string, []int, error) {
		return "", "", nil, errors.New("内核链含未知、旁路或不完整规则")
	}
	if !intrusionNftObjectKeys(raw, []string{"family", "table", "chain", "handle", "expr"}, "comment") {
		return fail()
	}
	expr, ok := raw["expr"].([]any)
	if !ok || len(expr) != 3 {
		return fail()
	}
	matches := []map[string]any{}
	for _, item := range expr[:2] {
		outer, ok := item.(map[string]any)
		if !ok || len(outer) != 1 {
			return fail()
		}
		match, ok := outer["match"].(map[string]any)
		if !ok || !intrusionNftObjectKeys(match, []string{"op", "left", "right"}) || match["op"] != "==" {
			return fail()
		}
		matches = append(matches, match)
	}
	if !reflect.DeepEqual(matches[0]["left"], map[string]any{"payload": map[string]any{"protocol": "tcp", "field": "dport"}}) {
		return fail()
	}
	ports, err := intrusionNftPorts(matches[0]["right"])
	if err != nil {
		return "", "", nil, err
	}
	family := ""
	for _, candidate := range []string{"ip", "ip6"} {
		if reflect.DeepEqual(matches[1]["left"], map[string]any{"payload": map[string]any{"protocol": candidate, "field": "saddr"}}) {
			family = candidate
		}
	}
	name, ok := matches[1]["right"].(string)
	if family == "" || !ok || !strings.HasPrefix(name, "@") || !intrusionNftName(strings.TrimPrefix(name, "@")) {
		return fail()
	}
	verdict, ok := expr[2].(map[string]any)
	if !ok || len(verdict) != 1 {
		return fail()
	}
	if drop, exists := verdict["drop"]; exists {
		if drop != nil {
			return fail()
		}
	} else {
		reject, ok := verdict["reject"].(map[string]any)
		if !ok || !intrusionNftObjectKeys(reject, []string{"type", "expr"}) || reject["expr"] != "port-unreachable" || reject["type"] != "icmp" && reject["type"] != "icmpv6" && reject["type"] != "icmpx" {
			return fail()
		}
		if family == "ip" && reject["type"] == "icmpv6" || family == "ip6" && reject["type"] == "icmp" {
			return fail()
		}
	}
	return strings.TrimPrefix(name, "@"), family, ports, nil
}

// Validate actual kernel rule ports and exact active IP sets, not configurable
// Fail2ban properties. No raw addresses or kernel rules escape this result.
func inspectIntrusionNftScope(raw []byte, scope intrusionNftScope) (intrusionNftObservation, error) {
	out := intrusionNftObservation{}
	fail := func(message string) (intrusionNftObservation, error) { return out, errors.New(message) }
	if len(raw) < 1 || len(raw) > 24<<10 || !intrusionNftName(scope.Table) || !intrusionNftName(scope.Chain) || !intrusionNftName(scope.IPv4Set) || !intrusionNftName(scope.IPv6Set) || scope.IPv4Set == scope.IPv6Set {
		return fail("内核核验输入范围无效")
	}
	if len(scope.Ports) < 1 || len(scope.Ports) > intrusionMaxPorts || len(scope.Banned) > 512 {
		return fail("内核核验端口或封禁数量超限")
	}
	for i, p := range scope.Ports {
		if p < 1 || p > 65535 || i > 0 && scope.Ports[i-1] >= p {
			return fail("内核核验目标端口不规范")
		}
	}
	expected := map[string]map[netip.Addr]bool{scope.IPv4Set: {}, scope.IPv6Set: {}}
	for _, ip := range scope.Banned {
		if !ip.IsValid() || ip.Zone() != "" || ip.Is4In6() {
			return fail("实际封禁地址格式未支持")
		}
		name := scope.IPv6Set
		if ip.Is4() {
			name = scope.IPv4Set
		}
		if expected[name][ip] {
			return fail("实际封禁地址重复")
		}
		expected[name][ip] = true
	}
	var document map[string][]map[string]any
	if decodeApacheWAFPrivateJSON(raw, &document, map[string]bool{"nftables": true}, 8000) != nil || len(document) != 1 || len(document["nftables"]) < 1 || len(document["nftables"]) > 1024 {
		return fail("内核 JSON 重复、未知、截断或超限")
	}
	tableOK, chainOK := false, false
	sets := map[string]bool{}
	rules := map[string]int{}
	handles := map[float64]bool{}
	for _, item := range document["nftables"] {
		if len(item) != 1 {
			return fail("内核记录字段不唯一")
		}
		if _, ok := item["metainfo"]; ok {
			continue
		}
		if object, ok := item["table"]; ok {
			value, ok := object.(map[string]any)
			if !ok || value["name"] != scope.Table || value["family"] != "inet" || tableOK {
				return fail("内核表身份无法核对")
			}
			tableOK = true
			continue
		}
		if object, ok := item["chain"]; ok {
			value, ok := object.(map[string]any)
			if !ok || value["family"] != "inet" || value["table"] != scope.Table {
				return fail("内核链所属表不明")
			}
			if value["name"] != scope.Chain {
				continue
			}
			if chainOK || value["hook"] != "input" || value["type"] != "filter" || value["prio"] != float64(-1) || value["policy"] != "accept" {
				return fail("内核基链钩子、顺序或策略不符")
			}
			chainOK = true
			continue
		}
		if object, ok := item["set"]; ok {
			value, ok := object.(map[string]any)
			if !ok || value["family"] != "inet" || value["table"] != scope.Table {
				return fail("内核集合所属表不明")
			}
			name, _ := value["name"].(string)
			if name != scope.IPv4Set && name != scope.IPv6Set {
				continue
			}
			if sets[name] || !intrusionNftObjectKeys(value, []string{"family", "table", "name", "handle", "type"}, "elem") {
				return fail("内核受管集合重复或格式未支持")
			}
			wantedType := "ipv4_addr"
			if name == scope.IPv6Set {
				wantedType = "ipv6_addr"
			}
			if value["type"] != wantedType {
				return fail("内核受管集合地址类型不符")
			}
			elems := []any{}
			if present, exists := value["elem"]; exists {
				var valid bool
				elems, valid = present.([]any)
				if !valid || len(elems) > 512 {
					return fail("内核受管集合元素超限或格式未知")
				}
			}
			actual := map[netip.Addr]bool{}
			for _, elem := range elems {
				label, ok := elem.(string)
				if !ok {
					return fail("内核受管集合元素未支持")
				}
				ip, err := netip.ParseAddr(label)
				if err != nil || actual[ip] || ip.Zone() != "" || ip.Is4In6() || (name == scope.IPv4Set) != ip.Is4() {
					return fail("内核集合地址重复或格式无效")
				}
				actual[ip] = true
			}
			if !reflect.DeepEqual(actual, expected[name]) {
				return fail("内核实际封禁集合与运行中 Jail 不一致")
			}
			sets[name] = true
			continue
		}
		if object, ok := item["rule"]; ok {
			value, ok := object.(map[string]any)
			if !ok || value["family"] != "inet" || value["table"] != scope.Table {
				return fail("内核规则所属表不明")
			}
			if value["chain"] != scope.Chain {
				continue
			}
			handle, ok := value["handle"].(float64)
			if !ok || handle < 1 || handle > 9007199254740991 || handle != float64(int64(handle)) || handles[handle] {
				return fail("内核规则身份无效或重复")
			}
			handles[handle] = true
			name, family, ports, err := intrusionNftRejectingRule(value)
			if err != nil {
				return fail(err.Error())
			}
			if name != scope.IPv4Set && name != scope.IPv6Set {
				continue
			}
			if (name == scope.IPv4Set) != (family == "ip") || !slices.Equal(ports, scope.Ports) {
				return fail("内核实际拦截端口或地址族与 SSH 目标不一致")
			}
			rules[name]++
			if rules[name] > 1 {
				return fail("受管内核拦截规则重复")
			}
			continue
		}
		return fail("内核 JSON 含尚未支持核验的对象")
	}
	if !tableOK || !chainOK {
		return fail("内核受管表或基链未核实")
	}
	for _, name := range []string{scope.IPv4Set, scope.IPv6Set} {
		if !sets[name] && len(expected[name]) == 0 && rules[name] == 0 {
			continue
		}
		if !sets[name] || rules[name] != 1 {
			return fail("内核受管集合与拦截规则不完整")
		}
		if name == scope.IPv4Set {
			out.IPv4 = true
		} else {
			out.IPv6 = true
		}
	}
	out.Verified = out.IPv4 || out.IPv6
	out.ActiveBans = len(scope.Banned)
	if !out.Verified {
		return out, errIntrusionNftScopeAbsent
	}
	return out, nil
}
