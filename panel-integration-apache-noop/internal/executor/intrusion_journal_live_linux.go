//go:build linux

package executor

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
)

// Recovery derives a rule-only change from CURRENT verified rules and CURRENT
// Jail bans. The original snapshot proves policy identity, never permission to
// restore historical IPs, timers, whole tables, a server or another Jail.
// This remains a pure plan: its raw before hash must be re-observed by the
// durable writer immediately before nft syntax checking and atomic application.
func intrusionJournalLivePortPlan(original intrusionJournalPlan, raw []byte, bans []netip.Addr, state string) (intrusionNftPortPlan, error) {
	var empty intrusionNftPortPlan
	if err := intrusionJournalValidate(original); err != nil {
		return empty, err
	}
	wanted := original.TargetPorts
	if state == "rolled_back" {
		wanted = original.BeforePolicy.Ports
	} else if state != "committed" {
		return empty, errors.New("入侵防护内核目标不是固定提交或恢复状态")
	}
	originalBans, err := intrusionBannedAddresses(strings.Join(original.BansBefore, " "))
	if err != nil {
		return empty, err
	}
	identity, err := intrusionNftPolicyIdentity(original.KernelBefore, intrusionPolicyScope(original.BeforePolicy, originalBans))
	if err != nil {
		return empty, err
	}
	for _, ports := range [][]int{original.BeforePolicy.Ports, original.TargetPorts} {
		policy := original.BeforePolicy
		policy.Ports = slices.Clone(ports)
		current := intrusionPolicyScope(policy, bans)
		got, readErr := intrusionNftPolicyIdentity(raw, current)
		if readErr != nil {
			continue
		}
		if got != identity {
			return empty, errors.New("实际内核策略身份已偏离原事务，未覆盖或重建对象")
		}
		return planIntrusionNftPortChange(raw, current, wanted)
	}
	return empty, errors.New("实际内核端口或当前封禁不属于原事务完整前后状态，未恢复历史封禁")
}
