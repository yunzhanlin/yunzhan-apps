//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"net/netip"
	"reflect"
	"slices"
)

func intrusionDirectoryIdentity(raw []byte, table string) (string, error) {
	if err := intrusionNftTableKnownAbsent(raw, table); err != nil {
		return "", err
	}
	var doc map[string][]map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return "", errors.New("内核完整目录无法重新核对")
	}
	objects := []map[string]any{}
	for _, object := range doc["nftables"] {
		if _, meta := object["metainfo"]; !meta {
			objects = append(objects, object)
		}
	}
	canonical, err := json.Marshal(objects)
	if err != nil {
		return "", err
	}
	return core.Hash(string(canonical)), nil
}

type intrusionRuntimeKernelObservation struct {
	Raw, Directory []byte
	Scope          intrusionTransactionKernel
}

func intrusionObserveRuntimeKernel(read func(string, ...string) (string, error), policy intrusionManagedPolicy, bans []netip.Addr, original *intrusionJournalPlan) (out intrusionRuntimeKernelObservation, probeErr error) {
	defer func() {
		if probeErr != nil {
			out = intrusionRuntimeKernelObservation{}
		}
	}()
	if err := intrusionPolicyValidate(policy); err != nil {
		return out, err
	}
	raw, readErr := read("/usr/sbin/nft", "-j", "list", "table", "inet", policy.Table)
	if readErr == nil {
		out.Raw = []byte(raw)
	}
	if readErr != nil || original != nil && original.KernelState == "table_absent" {
		directory, err := read("/usr/sbin/nft", "-j", "list", "tables")
		if err != nil {
			return out, err
		}
		out.Directory = []byte(directory)
	}
	if original != nil {
		observation, err := intrusionJournalKernelAccept(*original, out.Raw, out.Directory, bans)
		if err != nil {
			return out, err
		}
		out.Scope = observation
		return out, nil
	}
	if readErr != nil {
		if len(bans) != 0 {
			return out, errors.New("存在运行中封禁但无法读取实际内核表")
		}
		identity, err := intrusionDirectoryIdentity(out.Directory, policy.Table)
		if err != nil {
			return out, err
		}
		out.Scope = intrusionTransactionKernel{State: "table_absent", StaticIdentity: identity}
		return out, nil
	}
	scope := intrusionPolicyScope(policy, bans)
	_, err := inspectIntrusionNftScope(out.Raw, scope)
	deferred := len(bans) == 0 && errors.Is(err, errIntrusionNftScopeAbsent)
	if err != nil && !deferred {
		return out, err
	}
	identity, err := intrusionNftObservedPolicyIdentity(out.Raw, scope, deferred)
	if err != nil {
		return out, err
	}
	out.Scope = intrusionTransactionKernel{State: "rules_observed", Ports: slices.Clone(policy.Ports), StaticIdentity: identity}
	if deferred {
		out.Scope.State = "scope_absent"
		out.Scope.Ports = nil
	}
	return out, nil
}

func intrusionRuntimeKernelTransactionRecheck(read func(string, ...string) (string, error), before intrusionRuntimeState, original *intrusionJournalPlan) error {
	now, err := intrusionObserveRuntimeKernel(read, before.Policy, before.Bans, original)
	if err != nil {
		return err
	}
	if len(before.KernelIdentity) != 64 || now.Scope.StaticIdentity != before.KernelIdentity || now.Scope.State != before.KernelState || !slices.Equal(now.Scope.Ports, before.KernelScopePorts) || !reflect.DeepEqual(now.Scope.PortsBySet, before.KernelPortsBySet) {
		return errors.New("实际内核创建状态、规则、句柄或共享策略在观察期间改变；未覆盖")
	}
	return nil
}
