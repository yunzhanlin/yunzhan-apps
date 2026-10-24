//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"local/panel/internal/core"
)

// Format ONLY an already positively typed owned rejecting rule. This is not
// an execution API: its caller must first qualify the full current kernel
// against the original transaction and CURRENT ban list. No IP/set/timer or
// arbitrary statement is generated, and manual metadata is never dropped.
func intrusionOwnedPortReplacement(rule map[string]any, policy intrusionManagedPolicy, wanted []int) (string, uint64, error) {
	if err := intrusionPolicyValidate(policy); err != nil {
		return "", 0, err
	}
	if err := intrusionJournalPorts(wanted); err != nil {
		return "", 0, err
	}
	for _, name := range []string{policy.Table, policy.Chain, policy.IPv4Set, policy.IPv6Set} {
		if !intrusionNftWriteName(name) {
			return "", 0, errors.New("受管规则标识符不能生成固定批次")
		}
	}
	set, family, _, err := intrusionNftRejectingRule(rule)
	if err != nil {
		return "", 0, err
	}
	handle, numbered := rule["handle"].(float64)
	_, manual := rule["comment"]
	if rule["family"] != "inet" || rule["table"] != policy.Table || rule["chain"] != policy.Chain || set != policy.IPv4Set && set != policy.IPv6Set || (set == policy.IPv4Set) != (family == "ip") || manual || !numbered || handle < 1 || handle > 9007199254740991 || handle != float64(uint64(handle)) {
		return "", 0, errors.New("规则句柄、地址族或人工元数据不属于固定受管替换范围")
	}
	labels := make([]string, len(wanted))
	for i, p := range wanted {
		labels[i] = strconv.Itoa(p)
	}
	verdict := "drop"
	last := rule["expr"].([]any)[2].(map[string]any)
	if value, exists := last["reject"]; exists {
		reject := value.(map[string]any)
		verdict = "reject with " + reject["type"].(string) + " type port-unreachable"
	}
	return fmt.Sprintf("replace rule inet %s %s handle %d tcp dport { %s } %s saddr @%s %s\n", policy.Table, policy.Chain, uint64(handle), strings.Join(labels, ", "), family, set, verdict), uint64(handle), nil
}

// PURE original-bound rule plan. Every family may currently be original
// BEFORE or target AFTER, but the full retained policy/directory/handles and
// actual bans must qualify first. Generate only the specific outdated owned
// handles. The comparison projection is NEVER used as nft input or raw-state
// authority; the observed SHA covers the byte-exact CURRENT original document.
func planIntrusionCurrentFamilyPorts(original intrusionJournalPlan, raw, directory []byte, bans []netip.Addr, state string) (out intrusionNftPortPlan, err error) {
	defer func() {
		if err != nil {
			out = intrusionNftPortPlan{}
		}
	}()
	if state != "committed" && state != "rolled_back" {
		return out, errors.New("入侵防护地址族批次目标不是固定原事务状态")
	}
	kernel := bytes.Clone(raw)
	observed, err := intrusionJournalKernelAccept(original, kernel, directory, bans)
	if err != nil {
		return out, err
	}
	wanted := original.TargetPorts
	if state == "rolled_back" {
		wanted = original.BeforePolicy.Ports
	}
	out = intrusionNftPortPlan{BeforeSHA256: core.Hash(string(kernel)), TargetPorts: slices.Clone(wanted), Statements: []string{}, RuleHandles: []uint64{}}
	if observed.State != "rules_observed" {
		return out, nil
	}
	if len(observed.PortsBySet) < 1 || len(observed.PortsBySet) > 2 {
		return out, errors.New("入侵防护受管地址族规则范围未完整核对")
	}
	// Strict duplicate-aware full validation occurred above on this private
	// byte-for-byte copy; this decode cannot hide duplicate or unknown input.
	var doc map[string][]map[string]any
	if err = json.Unmarshal(kernel, &doc); err != nil {
		return out, err
	}
	for _, object := range doc["nftables"] {
		rule, ok := object["rule"].(map[string]any)
		if !ok || rule["family"] != "inet" || rule["table"] != original.BeforePolicy.Table || rule["chain"] != original.BeforePolicy.Chain {
			continue
		}
		set, _, ports, parseErr := intrusionNftRejectingRule(rule)
		if parseErr != nil {
			return out, parseErr
		}
		if set != original.BeforePolicy.IPv4Set && set != original.BeforePolicy.IPv6Set {
			continue
		}
		if !slices.Equal(ports, observed.PortsBySet[set]) {
			return out, errors.New("当前地址族规则与完整观察映射不一致")
		}
		if slices.Equal(ports, wanted) {
			continue
		}
		line, handle, formatErr := intrusionOwnedPortReplacement(rule, original.BeforePolicy, wanted)
		if formatErr != nil {
			return out, formatErr
		}
		out.Statements = append(out.Statements, line)
		out.RuleHandles = append(out.RuleHandles, handle)
	}
	if len(out.Statements) > 2 || len(strings.Join(out.Statements, "")) > 4096 {
		return out, errors.New("当前地址族批次超过原固定一至两个规则范围")
	}
	return out, nil
}
