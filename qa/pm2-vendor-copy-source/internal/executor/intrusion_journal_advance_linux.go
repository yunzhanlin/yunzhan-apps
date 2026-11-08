//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"time"

	"local/panel/internal/core"
)

func (s *Service) intrusionJournalMutationBoundary(ctx context.Context, lock *os.File, plan intrusionJournalPlan, raw []byte) (intrusionRuntimeState, error) {
	var empty intrusionRuntimeState
	files, _, err := s.intrusionJournalObserveFilesAndTree(ctx, plan, "mixed")
	if err != nil {
		return empty, err
	}
	live, err := s.readIntrusionTransactionRuntime(ctx, lock, plan, raw)
	if err != nil {
		return empty, err
	}
	if err = s.intrusionJournalCheckEffective(ctx, plan, files, live); err != nil {
		return empty, err
	}
	if _, _, err = s.intrusionJournalObserveFilesAndTree(ctx, plan, "mixed"); err != nil {
		return empty, err
	}
	if err = ctx.Err(); err != nil {
		return empty, err
	}
	if err = s.intrusionJournalRequireOriginal(lock, plan, raw); err != nil {
		return empty, err
	}
	return live, nil
}

// Every fixed field is visited at most once in this invocation. Lost SET
// replies stop immediately; there is no retry, reload, reban or compensation
// from historical IPs. An explicit subsequent original-ID recovery observes
// the actual current state before deriving any remaining scalar operation.
func (s *Service) intrusionJournalWriteScalars(ctx context.Context, lock *os.File, plan intrusionJournalPlan, raw []byte, state string) error {
	live, err := s.intrusionJournalMutationBoundary(ctx, lock, plan, raw)
	if err != nil {
		return err
	}
	initial, err := intrusionJournalScalarPlan(plan, live, state)
	if err != nil {
		return err
	}
	needed := map[string]bool{}
	for _, change := range initial.Changes {
		needed[change.Key] = true
	}
	first := true
	for _, key := range []string{"maxretry", "findtime", "bantime"} {
		if !needed[key] {
			continue
		}
		// Skip no-write fields, not write gates. The first actual operation
		// uses the immediately preceding complete boundary; subsequent ones
		// independently re-observe it. Final verification checks every field.
		if !first {
			live, err = s.intrusionJournalMutationBoundary(ctx, lock, plan, raw)
			if err != nil {
				return err
			}
		}
		first = false
		next, err := intrusionJournalScalarPlan(plan, live, state)
		if err != nil {
			return err
		}
		for _, change := range next.Changes {
			if change.Key != key {
				continue
			}
			args, err := intrusionScalarMutationArgs(next.Process, next.ProcessStart, next.Action, change)
			if err != nil {
				return err
			}
			if err = s.intrusionJournalRequireOriginal(lock, plan, raw); err != nil {
				return err
			}
			if err = ctx.Err(); err != nil {
				return err
			}
			bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
			result, runErr := s.Config.Run(bounded, "/usr/bin/python3", args...)
			deadlineErr := bounded.Err()
			cancel()
			if runErr != nil || deadlineErr != nil {
				return errors.New("入侵防护标量结果未知；保留原事务，未重试、重启或恢复历史封禁")
			}
			if _, err = intrusionScalarMutationDecode([]byte(result), next.Process, next.ProcessStart, next.Action, change); err != nil {
				return err
			}
		}
	}
	if first {
		// No numeric operation or external call occurred since this complete
		// boundary. Carry it directly into the first port-template step rather
		// than immediately repeating the same read-only tree/dump/runtime
		// sequence. Every actual SET still has its original/boot check and
		// helper-side fresh peer+GET CAS. After ANY numeric step, re-observe.
		return s.intrusionJournalWritePortRecipeFromBoundary(ctx, lock, plan, raw, state, live)
	}
	return s.intrusionJournalWritePortRecipe(ctx, lock, plan, raw, state)
}

// The two resolved templates must be changed explicitly before the port
// property. Every field is visited at most once; source-derived typed helper
// arguments contain no action body. Independent original literal and kernel
// family states remain observable only under this exact pending record.
func (s *Service) intrusionJournalWritePortRecipe(ctx context.Context, lock *os.File, plan intrusionJournalPlan, raw []byte, state string) error {
	live, err := s.intrusionJournalMutationBoundary(ctx, lock, plan, raw)
	if err != nil {
		return err
	}
	return s.intrusionJournalWritePortRecipeFromBoundary(ctx, lock, plan, raw, state, live)
}

// Only the two immediately preceding controller paths may supply this fresh
// complete observation; it is never persisted, reused after a mutation or
// accepted from a request. The standalone entry point above always observes.
func (s *Service) intrusionJournalWritePortRecipeFromBoundary(ctx context.Context, lock *os.File, plan intrusionJournalPlan, raw []byte, state string, live intrusionRuntimeState) error {
	initial, err := intrusionPortRecipeChanges(plan, live.Recipe, state)
	if err != nil {
		return err
	}
	needed := map[string]bool{}
	for _, change := range initial.Changes {
		needed[change.Field] = true
	}
	first := true
	for _, field := range []string{"actionstart", "actionflush", "port"} {
		if !needed[field] {
			continue
		}
		if !first {
			live, err = s.intrusionJournalMutationBoundary(ctx, lock, plan, raw)
			if err != nil {
				return err
			}
		}
		first = false
		next, err := intrusionPortRecipeChanges(plan, live.Recipe, state)
		if err != nil {
			return err
		}
		for _, change := range next.Changes {
			if change.Field != field {
				continue
			}
			var args []string
			if field == "port" {
				args, err = intrusionScalarMutationArgs(plan.ProcessBefore, plan.ProcessStartBefore, plan.BeforePolicy.Action, intrusionScalarChange{Key: "port", From: change.From, To: change.To})
			} else {
				args, err = intrusionPortTemplateMutationArgs(plan, change)
			}
			if err != nil {
				return err
			}
			if err = s.intrusionJournalRequireOriginal(lock, plan, raw); err != nil {
				return err
			}
			if err = ctx.Err(); err != nil {
				return err
			}
			bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
			result, runErr := s.Config.Run(bounded, "/usr/bin/python3", args...)
			deadlineErr := bounded.Err()
			cancel()
			if runErr != nil || deadlineErr != nil {
				return errors.New("入侵防护端口或模板写入结果未知；保留原事务，未重试、重载或执行历史动作")
			}
			if field == "port" {
				_, err = intrusionScalarMutationDecode([]byte(result), plan.ProcessBefore, plan.ProcessStartBefore, plan.BeforePolicy.Action, intrusionScalarChange{Key: "port", From: change.From, To: change.To})
			} else {
				_, err = intrusionPortTemplateMutationDecode([]byte(result), plan, change)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func intrusionJournalCurrentNftPlan(plan intrusionJournalPlan, live intrusionRuntimeState, state string) (intrusionNftPortPlan, error) {
	var out intrusionNftPortPlan
	changes, err := intrusionJournalScalarPlan(plan, live, state)
	if err != nil {
		return out, err
	}
	if len(changes.Changes) != 0 {
		return out, errors.New("入侵防护动作端口和限额未闭合；未先改内核或删除封禁")
	}
	recipe, err := intrusionPortRecipeChanges(plan, live.Recipe, state)
	if err != nil {
		return out, err
	}
	if len(recipe.Changes) != 0 {
		return out, errors.New("入侵防护端口动作模板未闭合，未先改内核或假定新地址族已经安全")
	}
	return planIntrusionCurrentFamilyPorts(plan, live.Kernel, live.KernelDirectory, live.Bans, state)
}

func (s *Service) intrusionJournalWriteKernel(ctx context.Context, lock *os.File, plan intrusionJournalPlan, raw []byte, state string) error {
	live, err := s.intrusionJournalMutationBoundary(ctx, lock, plan, raw)
	if err != nil {
		return err
	}
	next, err := intrusionJournalCurrentNftPlan(plan, live, state)
	if err != nil || len(next.Statements) == 0 {
		return err
	}
	if s.Config.RunInput == nil {
		return errors.New("入侵防护缺少固定内核输入执行器，未执行宿主命令")
	}
	input := []byte(strings.Join(next.Statements, ""))
	run := func(check bool) error {
		args := []string{"-f", "-"}
		if check {
			args = []string{"-c", "-f", "-"}
		}
		bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		out, err := s.Config.RunInput(bounded, input, "/usr/sbin/nft", args...)
		if err != nil || bounded.Err() != nil || strings.TrimSpace(out) != "" {
			return errors.New("入侵防护固定内核批次未取得完整无歧义回执；保留原任务，未隐式重试")
		}
		return nil
	}
	if err = run(true); err != nil {
		return err
	}
	current, err := s.intrusionJournalMutationBoundary(ctx, lock, plan, raw)
	if err != nil {
		return err
	}
	again, err := intrusionJournalCurrentNftPlan(plan, current, state)
	if err != nil {
		return err
	}
	if live.KernelState != current.KernelState || live.KernelIdentity != current.KernelIdentity || !slices.Equal(next.Statements, again.Statements) || !slices.Equal(next.RuleHandles, again.RuleHandles) {
		return errors.New("入侵防护内核批次检查后静态规则或句柄变化；未应用或重试旧批次")
	}
	// The byte-exact script was freshly re-derived from CURRENT bans/handles.
	// Natural ban expiry does not authorize restoring an old set or timer.
	if err = s.intrusionJournalRequireOriginal(lock, plan, raw); err != nil {
		return err
	}
	if err = run(false); err != nil {
		return err
	}
	after, err := s.readIntrusionTransactionRuntime(ctx, lock, plan, raw)
	if err != nil {
		return err
	}
	return intrusionJournalRuntimeAt(plan, after, state)
}

// Only this bounded existing-install transition coordinates the individual
// fixed-slot writers. On ANY error it retains the immutable pending record;
// it never automatically retries a lost outcome or globally restarts Fail2ban.
// It is not wired to an HTTP handler until lifetime/version/UI gates are ready.
func (s *Service) intrusionJournalAdvance(ctx context.Context, lock *os.File, plan intrusionJournalPlan, raw []byte, state, recoveryJob string) error {
	job, err := intrusionOriginalJob(ctx)
	if err != nil {
		return err
	}
	if state != "committed" && state != "rolled_back" || state == "committed" && (recoveryJob != "" || job != plan.ID) || state == "rolled_back" && (!core.ValidID(recoveryJob) || recoveryJob == plan.ID || job != recoveryJob) {
		return errors.New("入侵防护事务目标或恢复身份范围无效")
	}
	if err := s.intrusionJournalRequireOriginal(lock, plan, raw); err != nil {
		return err
	}
	inventory, err := s.intrusionJournalInventoryRead()
	if err != nil {
		return err
	}
	if previous, exists := inventory.Records[plan.ID]; exists {
		if !intrusionTerminalMatches(previous, plan, raw, state, recoveryJob) {
			return errors.New("入侵防护原任务已有不同终态；未回滚已提交事务或重放历史变更")
		}
		return s.intrusionJournalCloseTerminal(ctx, lock, plan, raw, state, recoveryJob)
	}
	if _, err = s.intrusionJournalMutationBoundary(ctx, lock, plan, raw); err != nil {
		return err
	}
	if err = s.intrusionJournalWriteFile(ctx, lock, plan, raw, 0, state); err != nil {
		return err
	}
	if err = s.intrusionJournalWriteScalars(ctx, lock, plan, raw, state); err != nil {
		return err
	}
	if err = s.intrusionJournalWriteKernel(ctx, lock, plan, raw, state); err != nil {
		return err
	}
	// The manifest is last: it cannot announce the target version before the
	// actual runtime and kernel steps, and no API success precedes terminal QA.
	for _, slot := range []int{2, 1} {
		if err = s.intrusionJournalWriteFile(ctx, lock, plan, raw, slot, state); err != nil {
			return err
		}
	}
	if err = s.intrusionJournalWriteTerminal(ctx, lock, plan, raw, state, recoveryJob); err != nil {
		return err
	}
	return s.intrusionJournalCloseTerminal(ctx, lock, plan, raw, state, recoveryJob)
}
