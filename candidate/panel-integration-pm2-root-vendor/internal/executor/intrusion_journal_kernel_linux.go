//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

type intrusionTransactionKernel struct {
	State          string
	Ports          []int
	PortsBySet     map[string][]int
	StaticIdentity string
}

// Compare the successful full directory while allowing ONLY the originally
// named inet table to appear after the daemon's genuine first ban. Other table
// names, families, handles, ordering and unknown fields are never discarded.
func intrusionDirectoryWithoutOwnedTable(raw []byte, wanted string) (string, bool, error) {
	if err := intrusionNftTableDirectoryValidate(raw, wanted, false); err != nil {
		return "", false, err
	}
	var doc map[string][]map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return "", false, errors.New("实际内核目录无法重新核对")
	}
	objects := []map[string]any{}
	present := false
	for _, object := range doc["nftables"] {
		if table, ok := object["table"].(map[string]any); ok && table["family"] == "inet" && table["name"] == wanted {
			present = true
			continue
		}
		objects = append(objects, object)
	}
	data, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		return "", false, err
	}
	id, err := intrusionDirectoryIdentity(data, wanted)
	return id, present, err
}

func intrusionOriginalOwnedSets(original intrusionJournalPlan) map[string]bool {
	out := map[string]bool{}
	var doc map[string][]map[string]any
	if json.Unmarshal(original.KernelBefore, &doc) != nil {
		return out
	}
	for _, object := range doc["nftables"] {
		if set, ok := object["set"].(map[string]any); ok {
			if name, ok := set["name"].(string); ok && (name == original.BeforePolicy.IPv4Set || name == original.BeforePolicy.IPv6Set) {
				out[name] = true
			}
		}
	}
	return out
}

// This accepts an observation, never a script or historical IP restoration.
// Daemon property ports and actual kernel ports may independently be BEFORE or
// AFTER while recovering an interrupted scalar+rule transaction. New-family
// sets created by CURRENT real bans are retained, not treated as old snapshots
// to delete. Every original handle/metadata and all unowned policy stay fixed.
func intrusionJournalKernelAccept(original intrusionJournalPlan, raw, directory []byte, bans []netip.Addr) (out intrusionTransactionKernel, probeErr error) {
	defer func() {
		if probeErr != nil {
			out = intrusionTransactionKernel{}
		}
	}()
	if err := intrusionJournalValidate(original); err != nil {
		return out, err
	}
	if original.KernelState == "table_absent" {
		before, err := intrusionDirectoryIdentity(original.KernelDirectory, original.BeforePolicy.Table)
		if err != nil {
			return out, err
		}
		now, present, err := intrusionDirectoryWithoutOwnedTable(directory, original.BeforePolicy.Table)
		if err != nil || now != before {
			return out, errors.New("原缺失表之外的实际内核目录已改变，未接管")
		}
		if (len(raw) > 0) != present {
			return out, errors.New("实际内核表与完整目录不是一致观察")
		}
		if present {
			var entries, table map[string][]map[string]any
			if json.Unmarshal(directory, &entries) != nil || json.Unmarshal(raw, &table) != nil {
				return out, errors.New("实际内核表和目录无法重新关联")
			}
			for _, object := range entries["nftables"] {
				if entry, ok := object["table"].(map[string]any); ok && entry["family"] == "inet" && entry["name"] == original.BeforePolicy.Table {
					if handle, exists := entry["handle"]; exists {
						matched := false
						for _, v := range table["nftables"] {
							if current, ok := v["table"].(map[string]any); ok && current["family"] == "inet" && current["name"] == original.BeforePolicy.Table && current["handle"] == handle {
								matched = true
							}
						}
						if !matched {
							return out, errors.New("实际内核表句柄与完整目录不一致")
						}
					}
				}
			}
		}
		if !present {
			if len(bans) != 0 {
				return out, errors.New("当前封禁存在但实际内核表仍缺失")
			}
			return intrusionTransactionKernel{State: "table_absent", StaticIdentity: now}, nil
		}
	} else if len(raw) == 0 || len(directory) != 0 {
		return out, errors.New("原既存内核表缺失或观察混入另一份目录，未重建")
	}
	retained := intrusionOriginalOwnedSets(original)
	var baseline string
	if original.KernelState != "table_absent" {
		oldBans, err := intrusionBannedAddresses(strings.Join(original.BansBefore, " "))
		if err != nil {
			return out, err
		}
		baseline, err = intrusionNftRetainedPolicyIdentity(original.KernelBefore, intrusionPolicyScope(original.BeforePolicy, oldBans), original.KernelState == "scope_absent", retained)
		if err != nil {
			return out, err
		}
	}
	projected, err := intrusionProjectKernelPortsForValidatedOriginal(original, raw, bans)
	if err != nil {
		return out, err
	}
	scope := intrusionPolicyScope(original.BeforePolicy, bans)
	comparison, err := intrusionNftRetainedPolicyIdentity(projected.Projected, scope, projected.Deferred, retained)
	if err != nil {
		return out, err
	}
	if original.KernelState != "table_absent" && comparison != baseline {
		return out, errors.New("实际原规则句柄、元数据或共享策略偏离原事务，未覆盖")
	}
	full, err := intrusionNftObservedPolicyIdentity(projected.Projected, scope, projected.Deferred)
	if err != nil {
		return out, err
	}
	if projected.Deferred {
		return intrusionTransactionKernel{State: "scope_absent", StaticIdentity: full}, nil
	}
	// Keep the exact CURRENT map alongside the comparison identity. Empty
	// uniform ports means mixed families, NEVER an unbounded/all-ports scope.
	return intrusionTransactionKernel{State: "rules_observed", Ports: intrusionKernelUniformPorts(projected.PortsBySet), PortsBySet: projected.PortsBySet, StaticIdentity: full}, nil
}
