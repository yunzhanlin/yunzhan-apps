//go:build linux

package executor

import (
	"errors"
	"maps"
	"slices"
)

// Evidence from ONLY the executor's verified private replica. Retained literal
// declarations are parsed again after interruption; they are never executed,
// replayed or accepted as a request-supplied uninstall target. The immutable
// pending record, real named lock and fresh boundaries remain mandatory.
type intrusionRemovalEvidence struct {
	Dump     []byte `json:"dump"`
	SSHPorts []int  `json:"ssh_ports"`
}

func intrusionJournalRemovalValidate(plan intrusionJournalPlan) error {
	if plan.Action != "uninstall" {
		if plan.Removal != nil {
			return errors.New("非卸载事务不能携带底层卸载证据或额外 SSH 范围")
		}
		return nil
	}
	if plan.Removal == nil || intrusionJournalPorts(plan.Removal.SSHPorts) != nil {
		return errors.New("卸载事务缺少独立观察的原 SSH 监听范围")
	}
	current := intrusionRuntimeState{Policy: plan.BeforePolicy, Recipe: plan.ActionBefore, JournalMatch: plan.JournalMatchBefore}
	candidate, err := intrusionRemovalDerivations.derive(plan.Removal.Dump, current, plan.EffectiveBefore)
	if err != nil {
		return err
	}
	if !maps.Equal(candidate.Settings, plan.TargetSettings) || !slices.Equal(candidate.Ports, plan.TargetPorts) {
		return errors.New("卸载目标不是由完整原底层配置证据独立推导；未采用请求默认值")
	}
	return nil
}

// Restoring the underlying firewall action is NOT permission to move SSH's
// actual listeners. Other operations retain their original target-port rule.
func intrusionJournalObservedSSHPorts(plan intrusionJournalPlan) []int {
	if plan.Action == "uninstall" && plan.Removal != nil {
		return slices.Clone(plan.Removal.SSHPorts)
	}
	return slices.Clone(plan.TargetPorts)
}
