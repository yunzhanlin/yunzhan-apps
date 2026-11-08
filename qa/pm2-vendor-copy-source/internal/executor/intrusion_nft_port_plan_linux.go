//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"slices"
	"strconv"
	"strings"
)

type intrusionNftPortPlan struct {
	BeforeSHA256 string
	TargetPorts  []int
	Statements   []string
	RuleHandles  []uint64
}

// Older nft parsers reject quoted table/chain identifiers here. Accept only
// a closed ASCII identifier, never escaping or user-controlled expressions.
func intrusionNftWriteName(value string) bool {
	if !intrusionNftName(value) || !(value[0] >= 'a' && value[0] <= 'z' || value[0] >= 'A' && value[0] <= 'Z') {
		return false
	}
	for _, word := range []string{"inet", "ip", "ip6", "arp", "netdev", "bridge", "tcp", "udp", "table", "chain", "set", "map", "element", "add", "delete", "replace", "insert", "list", "flush", "reset", "destroy", "handle", "comment", "last", "include", "define", "type", "policy", "hook", "priority", "filter", "input", "output", "forward", "prerouting", "postrouting", "ingress", "egress", "dport", "saddr", "drop", "accept", "return", "reject", "jump", "goto", "counter"} {
		if strings.EqualFold(value, word) {
			return false
		}
	}
	return true
}

// Derive a bounded rule-only batch from a complete, verified original snapshot.
// No sets, IPs, timers, unrelated handles or arbitrary nft input are generated.
// This function never executes the plan. A persistent original-job transaction
// and a fresh authority comparison are required before any future application.
func planIntrusionNftPortChange(raw []byte, before intrusionNftScope, wanted []int) (plan intrusionNftPortPlan, planErr error) {
	defer func() {
		if planErr != nil {
			plan = intrusionNftPortPlan{}
		}
	}()
	plan = intrusionNftPortPlan{TargetPorts: slices.Clone(wanted), Statements: []string{}, RuleHandles: []uint64{}}
	for _, name := range []string{before.Table, before.Chain, before.IPv4Set, before.IPv6Set} {
		if !intrusionNftWriteName(name) {
			return plan, errors.New("受管内核对象标识符未满足固定安全语法，未生成指令")
		}
	}
	if _, err := inspectIntrusionNftScope(raw, before); err != nil {
		return plan, err
	}
	if len(wanted) < 1 || len(wanted) > intrusionMaxPorts {
		return plan, errors.New("新 SSH 端口范围缺失或超限")
	}
	labels := []string{}
	for i, port := range wanted {
		if port < 1 || port > 65535 || i > 0 && wanted[i-1] >= port {
			return plan, errors.New("新 SSH 端口范围不规范")
		}
		labels = append(labels, strconv.Itoa(port))
	}
	plan.BeforeSHA256 = core.Hash(string(raw))
	if slices.Equal(before.Ports, wanted) {
		return plan, nil
	}
	var document map[string][]map[string]any
	if json.Unmarshal(raw, &document) != nil {
		return plan, errors.New("原内核快照无法重新解析")
	}
	for _, object := range document["nftables"] {
		rule, ok := object["rule"].(map[string]any)
		if !ok || rule["family"] != "inet" || rule["table"] != before.Table || rule["chain"] != before.Chain {
			continue
		}
		set, family, _, err := intrusionNftRejectingRule(rule)
		if err != nil {
			return plan, err
		}
		if set != before.IPv4Set && set != before.IPv6Set {
			continue
		}
		if _, exists := rule["comment"]; exists {
			return plan, errors.New("受管规则含额外人工元数据；未自动替换")
		}
		// Full snapshot validation above already proved this integer, unique handle.
		handle := uint64(rule["handle"].(float64))
		verdict := "drop"
		last := rule["expr"].([]any)[2].(map[string]any)
		if value, exists := last["reject"]; exists {
			reject := value.(map[string]any)
			verdict = "reject with " + reject["type"].(string) + " type port-unreachable"
		}
		line := fmt.Sprintf("replace rule inet %s %s handle %d tcp dport { %s } %s saddr @%s %s\n", before.Table, before.Chain, handle, strings.Join(labels, ", "), family, set, verdict)
		plan.Statements = append(plan.Statements, line)
		plan.RuleHandles = append(plan.RuleHandles, handle)
	}
	if len(plan.Statements) < 1 || len(plan.Statements) > 2 || len(strings.Join(plan.Statements, "")) > 4096 {
		return intrusionNftPortPlan{}, errors.New("内核端口变更不属于已核验的一至两个固定规则")
	}
	return plan, nil
}
