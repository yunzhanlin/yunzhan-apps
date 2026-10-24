//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"local/panel/internal/core"
)

type intrusionKernelPortProjection struct {
	ObservedSHA256 string
	Projected      []byte
	PortsBySet     map[string][]int
	Deferred       bool
}

func intrusionNftPortLiteral(ports []int) any {
	if len(ports) == 1 {
		return float64(ports[0])
	}
	values := make([]any, len(ports))
	for i, p := range ports {
		values[i] = float64(p)
	}
	return map[string]any{"set": values}
}

// PURE comparison projection for an already qualified original transaction.
// Genuine new-family bans can create a target-port rule while the other family
// still has its original port. Admit ONLY those two exact numeric scopes for
// EACH positively typed owned rule. All handles/metadata/order/other policy and
// CURRENT bans are retained and checked, not replaced from audit history.
// Projected bytes are NEVER kernel input or an executable. Before any future
// writer can use this, its caller must ALSO compare the full original static
// policy/directory, named pending record, lock/boot/PID and actual files/dump.
func intrusionProjectCurrentKernelPorts(original intrusionJournalPlan, raw []byte, bans []netip.Addr) (intrusionKernelPortProjection, error) {
	if err := intrusionJournalValidate(original); err != nil {
		return intrusionKernelPortProjection{}, err
	}
	return intrusionProjectKernelPortsForValidatedOriginal(original, raw, bans)
}

// Pure sharing ONLY within the caller's already validated unchanged plan.
// Original-bound kernel acceptance still separately checks retained handles,
// full shared policy/directory and the actual current family port map.
func intrusionProjectKernelPortsForValidatedOriginal(original intrusionJournalPlan, raw []byte, bans []netip.Addr) (out intrusionKernelPortProjection, err error) {
	defer func() {
		if err != nil {
			out = intrusionKernelPortProjection{}
		}
	}()
	var doc map[string][]map[string]any
	if len(raw) < 1 || len(raw) > 24<<10 || decodeApacheWAFPrivateJSON(raw, &doc, map[string]bool{"nftables": true}, 8000) != nil || len(doc) != 1 || len(doc["nftables"]) < 1 || len(doc["nftables"]) > 1024 {
		return out, errors.New("入侵防护地址族端口观察不是完整唯一的固定内核文档")
	}
	policy := original.BeforePolicy
	out = intrusionKernelPortProjection{ObservedSHA256: core.Hash(string(raw)), PortsBySet: map[string][]int{}}
	for _, object := range doc["nftables"] {
		rule, ok := object["rule"].(map[string]any)
		if !ok || rule["family"] != "inet" || rule["table"] != policy.Table || rule["chain"] != policy.Chain {
			continue
		}
		set, family, ports, parseErr := intrusionNftRejectingRule(rule)
		if parseErr != nil {
			return out, parseErr
		}
		if set != policy.IPv4Set && set != policy.IPv6Set {
			continue
		}
		if (set == policy.IPv4Set) != (family == "ip") || out.PortsBySet[set] != nil || !slices.Equal(ports, policy.Ports) && !slices.Equal(ports, original.TargetPorts) {
			return out, errors.New("入侵防护实际地址族规则重复、错配或具有原事务之外的第三种端口")
		}
		out.PortsBySet[set] = slices.Clone(ports)
		match := rule["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)
		match["right"] = intrusionNftPortLiteral(policy.Ports)
	}
	normalized, err := json.Marshal(doc)
	if err != nil {
		return out, err
	}
	_, err = inspectIntrusionNftScope(normalized, intrusionPolicyScope(policy, bans))
	if err != nil {
		if !errors.Is(err, errIntrusionNftScopeAbsent) || len(bans) != 0 || len(out.PortsBySet) != 0 {
			return out, err
		}
		out.Deferred = true
	}
	out.Projected = normalized
	return out, nil
}

// An empty result is not "all ports". It means either deferred absence or a
// genuinely mixed-family state, whose exact map must be separately retained
// and rechecked before any original-bound recovery can change a rule.
func intrusionKernelUniformPorts(bySet map[string][]int) []int {
	var first []int
	for _, ports := range bySet {
		if first == nil {
			first = slices.Clone(ports)
		} else if !slices.Equal(first, ports) {
			return nil
		}
	}
	return first
}
