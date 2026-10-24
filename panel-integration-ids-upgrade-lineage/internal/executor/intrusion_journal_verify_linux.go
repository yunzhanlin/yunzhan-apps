//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
)

// The effective disk stream may be BEFORE while the daemon is AFTER (or vice
// versa). Derive ONLY its port/limit expectation from the actually observed
// original Jail file. The complete live recipe/backend is checked separately;
// no declaration from this comparison is ever sent to Fail2ban.
func (s *Service) intrusionJournalCheckEffective(ctx context.Context, plan intrusionJournalPlan, files []fileBackup, live intrusionRuntimeState) error {
	if err := s.intrusionJournalMatchFiles(plan, files, "mixed"); err != nil {
		return err
	}
	if _, err := intrusionJournalScalarPlan(plan, live, "committed"); err != nil {
		return err
	}
	settings := plan.TargetSettings
	ports := plan.TargetPorts
	if hardeningBackupSame(files[0], plan.Files[0].Before.backup(s.intrusionJournalPaths()[0])) {
		before, err := intrusionJournalBeforeSettings(plan)
		if err != nil {
			return err
		}
		settings = before
		ports = plan.BeforePolicy.Ports
	}
	expected := live
	expected.Policy.Ports = slices.Clone(ports)
	values, err := intrusionStockActionValues(expected.Policy, plan.ActionBefore.Values["nftables"], plan.ActionBefore.Values["chain"])
	if err != nil {
		return err
	}
	values["banEpoch"] = plan.ActionBefore.Values["banEpoch"]
	expected.Recipe.Values = values
	dump, err := s.readIntrusionEffectiveConfiguration(ctx, expected, settings)
	if err != nil {
		return err
	}
	if dump.Identity != plan.EffectiveBefore {
		return errors.New("入侵防护完整有效配置偏离原事务；过滤器、其他 Jail 或全局声明未获接管授权")
	}
	return nil
}

func intrusionJournalRuntimeAt(plan intrusionJournalPlan, live intrusionRuntimeState, state string) error {
	changes, err := intrusionJournalScalarPlan(plan, live, state)
	if err != nil {
		return err
	}
	if len(changes.Changes) != 0 {
		return errors.New("入侵防护实际运行参数尚未到达原事务目标，未发布成功")
	}
	recipe, err := intrusionPortRecipeChanges(plan, live.Recipe, state)
	if err != nil {
		return err
	}
	if len(recipe.Changes) != 0 {
		return errors.New("入侵防护实际端口和已解析动作模板尚未一起闭合，未发布成功")
	}
	ports := plan.TargetPorts
	if state == "rolled_back" {
		ports = plan.BeforePolicy.Ports
	}
	if live.KernelState == "rules_observed" {
		if !slices.Equal(live.KernelScopePorts, ports) {
			return errors.New("入侵防护实际内核端口尚未到达原事务目标，未将动作属性当作内核规则")
		}
		for _, actual := range live.KernelPortsBySet {
			if !slices.Equal(actual, ports) {
				return errors.New("入侵防护地址族端口仍处于原事务混合状态，未发布成功")
			}
		}
	} else if live.KernelState != "scope_absent" && live.KernelState != "table_absent" || len(live.Bans) != 0 {
		return errors.New("入侵防护延迟建表状态缺少当前无封禁的完整观察")
	}
	return nil
}

// Success requires independent real daemon/kernel samples around a complete
// physical-file/config-dump comparison. A changing ban list is NOT replayed or
// restored: each sample independently qualifies CURRENT bans; static policy
// and the original named authority must remain identical. This never mutates.
func (s *Service) intrusionJournalVerifyState(ctx context.Context, lock *os.File, plan intrusionJournalPlan, raw []byte, state string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.intrusionJournalRequireOriginal(lock, plan, raw); err != nil {
		return err
	}
	files, tree, err := s.intrusionJournalObserveFilesAndTree(ctx, plan, state)
	if err != nil {
		return err
	}
	live, err := s.readIntrusionTransactionRuntime(ctx, lock, plan, raw)
	if err != nil {
		return err
	}
	if err = intrusionJournalRuntimeAt(plan, live, state); err != nil {
		return err
	}
	if err = s.intrusionJournalCheckEffective(ctx, plan, files, live); err != nil {
		return err
	}
	again, err := s.readIntrusionTransactionRuntime(ctx, lock, plan, raw)
	if err != nil {
		return err
	}
	if err = intrusionJournalRuntimeAt(plan, again, state); err != nil {
		return err
	}
	if live.KernelState != again.KernelState || live.KernelIdentity != again.KernelIdentity || !slices.Equal(live.KernelScopePorts, again.KernelScopePorts) || !reflect.DeepEqual(live.KernelPortsBySet, again.KernelPortsBySet) {
		return errors.New("入侵防护内核静态范围在终态核验期间改变，未自动重试")
	}
	after, afterTree, err := s.intrusionJournalObserveFilesAndTree(ctx, plan, state)
	if err != nil {
		return err
	}
	for i := range files {
		if !hardeningBackupSame(files[i], after[i]) {
			return errors.New("入侵防护完整文件在终态核验期间改变")
		}
	}
	if !reflect.DeepEqual(tree, afterTree) {
		return errors.New("入侵防护磁盘配置树在终态核验期间改变")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.intrusionJournalRequireOriginal(lock, plan, raw)
}
