//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

type intrusionTransactionObservation struct {
	ID                          string         `json:"id"`
	SHA256                      string         `json:"sha256"`
	Action                      string         `json:"action"`
	StartedAt                   string         `json:"started_at"`
	FinishedAt                  string         `json:"finished_at"`
	State                       string         `json:"state"`
	BeforeSettings              map[string]int `json:"before_settings"`
	TargetSettings              map[string]int `json:"target_settings"`
	BeforePorts                 []int          `json:"before_ports"`
	TargetPorts                 []int          `json:"target_ports"`
	SSHObservedPorts            []int          `json:"ssh_observed_ports"`
	DurationChangesExistingBans bool           `json:"duration_changes_existing_bans"`
	RecoveryPermitted           bool           `json:"recovery_permitted"`
	Detail                      string         `json:"detail"`
}

// A pending lifetime deliberately has no current installed/healthy object.
// File absence half-way through removal is not an accepted uninstallation.
type intrusionWorkspaceInspection struct {
	Format               int                               `json:"format"`
	CheckedAt            string                            `json:"checked_at"`
	StateKnown           bool                              `json:"state_known"`
	Current              *intrusionInspection              `json:"current"`
	Pending              *intrusionTransactionObservation  `json:"pending"`
	History              []intrusionTransactionObservation `json:"history"`
	RetainedTemporaries  int                               `json:"retained_temporaries"`
	BanDurationSemantics string                            `json:"ban_duration_semantics"`
	Detail               string                            `json:"detail"`
}

func (s *Service) intrusionObservationLockCurrent(file *os.File) error {
	root, err := s.intrusionJournalRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	visible, err := root.Lstat(intrusionMutationLockName)
	if file == nil {
		if !errors.Is(err, os.ErrNotExist) {
			return errors.New("入侵防护观察期间出现锁或未知对象；未采用旧状态")
		}
		if !s.softwareManifestAnchorCurrent(root) {
			return errors.New("入侵防护观察根目录改变")
		}
		return nil
	}
	opened, openErr := file.Stat()
	flags, flagErr := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if flagErr != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return errors.New("入侵防护观察必须使用原只读描述符")
	}
	if err != nil || openErr != nil || !softwareManifestRecordInfo(visible) || !softwareManifestRecordInfo(opened) || visible.Mode().Perm() != 0600 || opened.Mode().Perm() != 0600 || !os.SameFile(opened, visible) || !s.softwareManifestAnchorCurrent(root) {
		return errors.New("入侵防护原观察锁的命名身份、权限或父级改变")
	}
	return nil
}

// Existing SH lock only: no O_CREATE, chmod, exclusive upgrade or repair.
func (s *Service) intrusionObservationLock() (*os.File, error) {
	root, err := s.intrusionJournalRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(intrusionMutationLockName)
	if errors.Is(err, os.ErrNotExist) {
		return nil, s.intrusionObservationLockCurrent(nil)
	}
	if err != nil {
		return nil, err
	}
	if !softwareManifestRecordInfo(info) || info.Mode().Perm() != 0600 {
		return nil, errors.New("入侵防护观察锁不可信；未修复")
	}
	file, err := root.OpenFile(intrusionMutationLockName, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		file.Close()
		return nil, errors.New("入侵防护观察锁在打开期间改变")
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("入侵防护原变更尚在执行；只读检查未创建新任务")
	}
	if err = s.intrusionObservationLockCurrent(file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

// Separate READ authority. This never calls the writer's RequireLock (which
// would convert SH to EX), and cannot authorize a scalar/file/kernel action.
func (s *Service) intrusionObservationOriginal(file *os.File, original intrusionJournalPlan, raw []byte) error {
	if file == nil {
		return errors.New("原事务观察锁缺失；未创建或修复")
	}
	if err := s.intrusionObservationLockCurrent(file); err != nil {
		return err
	}
	plan, current, err := s.intrusionJournalPending()
	if err != nil {
		return err
	}
	encoded, err := intrusionJournalEncode(original)
	if err != nil || plan.ID != original.ID || !bytes.Equal(raw, current) || !bytes.Equal(raw, encoded) {
		return errors.New("入侵防护只读观察不匹配原完整待恢复记录")
	}
	boot, err := os.ReadFile(s.systemPath("/proc/sys/kernel/random/boot_id"))
	if err != nil || len(boot) > 64 || string(boot) != strings.TrimSpace(string(boot))+"\n" || strings.TrimSpace(string(boot)) != original.BootID {
		return errors.New("入侵防护启动身份已改变；不能仅凭旧句柄许可恢复")
	}
	return nil
}

func (s *Service) intrusionPendingReadPreflight(ctx context.Context, file *os.File, plan intrusionJournalPlan, raw []byte, state string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.intrusionObservationOriginal(file, plan, raw); err != nil {
		return err
	}
	files, tree, err := s.intrusionJournalObserveFilesAndTree(ctx, plan, state)
	if err != nil {
		return err
	}
	// The plan was obtained from the private canonical original while the
	// real named SH lock is held. Mixed reads are for this observer only;
	// every mutation still requires the distinct EX/original queue gates.
	live, err := s.readIntrusionRuntime(ctx, &plan)
	if err != nil {
		return err
	}
	if state != "mixed" {
		if err = intrusionJournalRuntimeAt(plan, live, state); err != nil {
			return err
		}
	}
	if err = s.intrusionJournalCheckEffective(ctx, plan, files, live); err != nil {
		return err
	}
	after, afterTree, err := s.intrusionJournalObserveFilesAndTree(ctx, plan, state)
	if err != nil {
		return err
	}
	for i := range files {
		if !hardeningBackupSame(files[i], after[i]) {
			return errors.New("入侵防护文件在只读恢复预检期间改变")
		}
	}
	if !reflect.DeepEqual(tree, afterTree) {
		return errors.New("入侵防护配置树在只读恢复预检期间改变")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return s.intrusionObservationOriginal(file, plan, raw)
}

func intrusionTransactionView(plan intrusionJournalPlan, digest, state string) (intrusionTransactionObservation, error) {
	if err := intrusionJournalValidate(plan); err != nil {
		return intrusionTransactionObservation{}, err
	}
	before, err := intrusionJournalBeforeSettings(plan)
	if err != nil {
		return intrusionTransactionObservation{}, err
	}
	return intrusionTransactionObservation{ID: plan.ID, SHA256: digest, Action: plan.Action, StartedAt: plan.StartedAt, State: state, BeforeSettings: maps.Clone(before), TargetSettings: maps.Clone(plan.TargetSettings), BeforePorts: slices.Clone(plan.BeforePolicy.Ports), TargetPorts: slices.Clone(plan.TargetPorts), SSHObservedPorts: intrusionJournalObservedSSHPorts(plan), DurationChangesExistingBans: before["ban_time_minutes"] != plan.TargetSettings["ban_time_minutes"]}, nil
}

// Used by the versioned workspace API, not a release/acceptance receipt. Only
// bounded metadata is returned: no raw dump, action body, bans or file backup.
func (s *Service) inspectIntrusionWorkspace(ctx context.Context) (intrusionWorkspaceInspection, error) {
	out := intrusionWorkspaceInspection{Format: 1, CheckedAt: core.Now(), History: []intrusionTransactionObservation{}, BanDurationSemantics: "封禁时长策略适用于当前和后续使用默认时长的封禁；开始时间不重置，到期时间可能随配置或底层恢复改变", Detail: "状态尚未完整核对；只读检查不自动安装、恢复、重载或重启"}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return out, err
	}
	lock, err := s.intrusionObservationLock()
	if err != nil {
		return out, err
	}
	if lock != nil {
		defer lock.Close()
	}
	plan, raw, pendingErr := s.intrusionJournalPending()
	if pendingErr != nil && !errors.Is(pendingErr, os.ErrNotExist) {
		return out, pendingErr
	}
	inventory, err := s.intrusionJournalInventoryRead()
	if err != nil {
		return out, err
	}
	out.RetainedTemporaries = inventory.TemporaryFiles
	for _, terminal := range inventory.Records {
		row, err := intrusionTransactionView(terminal.Plan, terminal.PlanSHA256, terminal.State)
		if err != nil {
			return out, err
		}
		row.FinishedAt = terminal.FinishedAt
		row.Detail = "原任务的不可变闭合回执，不是当前健康证明"
		out.History = append(out.History, row)
	}
	sort.Slice(out.History, func(i, j int) bool {
		if out.History[i].FinishedAt == out.History[j].FinishedAt {
			return out.History[i].ID > out.History[j].ID
		}
		return out.History[i].FinishedAt > out.History[j].FinishedAt
	})
	if pendingErr == nil {
		row, err := intrusionTransactionView(plan, hardeningJournalDigest(raw), "pending")
		if err != nil {
			return out, err
		}
		state := "mixed"
		var check error
		if terminal, ok := inventory.Records[plan.ID]; ok {
			row.State = terminal.State + "_pending_cleanup"
			state = terminal.State
			if !intrusionTerminalMatches(terminal, plan, raw, terminal.State, terminal.RecoveryJobID) {
				check = errors.New("原终态与待恢复记录不一致；未许可覆盖")
			}
		}
		if check == nil {
			check = s.intrusionPendingReadPreflight(ctx, lock, plan, raw, state)
		}
		row.RecoveryPermitted = check == nil
		row.Detail = "当前只读预检通过；显式恢复提交时仍须重新核对原完整记录和实际状态"
		if check != nil {
			row.Detail = check.Error()
		}
		out.Pending = &row
		out.Detail = "原事务尚未闭合；不能把文件缺失当作未安装或把已执行步骤当作整体成功"
	} else {
		current, err := s.inspectIntrusion(ctx)
		if err != nil {
			return out, err
		}
		out.Current = &current
		out.StateKnown = true
		out.Detail = current.Detail
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = s.intrusionObservationLockCurrent(lock); err != nil {
		return out, err
	}
	_, after, afterErr := s.intrusionJournalPending()
	if pendingErr == nil {
		if afterErr != nil || !bytes.Equal(raw, after) {
			return out, errors.New("原待恢复记录在工作区采样期间改变")
		}
	} else if !errors.Is(afterErr, os.ErrNotExist) {
		return out, errors.New("采样期间出现新的入侵防护事务，未发布旧状态")
	}
	return out, nil
}
