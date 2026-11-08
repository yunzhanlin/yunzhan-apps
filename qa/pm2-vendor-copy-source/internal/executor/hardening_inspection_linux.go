//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net/http"
	"os"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

type hardeningParameterObservation struct {
	Key           string `json:"key"`
	Actual        string `json:"actual"`
	Target        string `json:"target"`
	Original      string `json:"original"`
	Managed       bool   `json:"managed"`
	OriginalKnown bool   `json:"original_known"`
	Reversible    bool   `json:"reversible"`
	Drift         bool   `json:"drift"`
	Detail        string `json:"detail"`
}

type hardeningTransactionObservation struct {
	ID                string `json:"id"`
	SHA256            string `json:"sha256"`
	Action            string `json:"action"`
	StartedAt         string `json:"started_at"`
	FinishedAt        string `json:"finished_at,omitempty"`
	FromProfile       string `json:"from_profile"`
	ToProfile         string `json:"to_profile"`
	State             string `json:"state"`
	RecoveryPermitted bool   `json:"recovery_permitted"`
	Detail            string `json:"detail"`
}

type hardeningInspection struct {
	Format              int                               `json:"format"`
	CheckedAt           string                            `json:"checked_at"`
	Installed           bool                              `json:"installed"`
	Healthy             bool                              `json:"healthy"`
	Version             string                            `json:"version"`
	Profile             string                            `json:"profile"`
	ConfigMatches       bool                              `json:"config_matches"`
	OriginalsComplete   bool                              `json:"originals_complete"`
	Parameters          []hardeningParameterObservation   `json:"parameters"`
	Pending             *hardeningTransactionObservation  `json:"pending"`
	History             []hardeningTransactionObservation `json:"history"`
	RetainedTemporaries int                               `json:"retained_temporaries"`
	Detail              string                            `json:"detail"`
}

// Observation may share an existing lock but must never create one, repair a
// directory, finish a journal, or run a write command. Absence is rechecked.
func (s *Service) hardeningObservationLock() (*os.File, error) {
	root, err := s.hardeningJournalRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	const name = "hardening-configuration.lock"
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !softwareManifestRecordInfo(info) || info.Mode().Perm() != 0600 {
		return nil, errors.New("加固观察锁身份异常，未修复")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	opened, e := f.Stat()
	visible, v := root.Lstat(name)
	if e != nil || v != nil || !os.SameFile(info, opened) || !os.SameFile(opened, visible) || !softwareManifestRecordInfo(opened) || !s.softwareManifestAnchorCurrent(root) {
		f.Close()
		return nil, errors.New("加固观察锁读取期间改变")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("加固变更正在执行；请在原任务结束后刷新，未创建新任务")
	}
	return f, nil
}

func hardeningTransactionView(plan hardeningJournalPlan, digest, state string) hardeningTransactionObservation {
	return hardeningTransactionObservation{ID: plan.ID, SHA256: digest, Action: plan.Action, StartedAt: plan.StartedAt, FromProfile: plan.FromProfile, ToProfile: plan.ToProfile, State: state}
}

func (s *Service) inspectHardening(ctx context.Context) (hardeningInspection, error) {
	out := hardeningInspection{Format: 1, CheckedAt: core.Now(), Parameters: []hardeningParameterObservation{}, History: []hardeningTransactionObservation{}, Detail: "未安装；只读采样，不自动配置、恢复或重启"}
	lock, err := s.hardeningObservationLock()
	if err != nil {
		return out, err
	}
	if lock != nil {
		defer lock.Close()
	}
	plan, pendingRaw, pendingErr := s.hardeningJournalPending()
	if pendingErr != nil && !errors.Is(pendingErr, os.ErrNotExist) {
		return out, pendingErr
	}
	inventory, err := s.hardeningJournalInventoryRead()
	if err != nil {
		return out, err
	}
	out.RetainedTemporaries = inventory.TemporaryFiles
	for _, terminal := range inventory.Records {
		row := hardeningTransactionView(terminal.Plan, terminal.PlanSHA256, terminal.State)
		row.FinishedAt = terminal.FinishedAt
		row.Detail = "原任务的完整持久回执；不是当前内核健康证明"
		out.History = append(out.History, row)
	}
	sort.Slice(out.History, func(i, j int) bool {
		if out.History[i].FinishedAt == out.History[j].FinishedAt {
			return out.History[i].ID > out.History[j].ID
		}
		return out.History[i].FinishedAt > out.History[j].FinishedAt
	})
	if pendingErr == nil {
		row := hardeningTransactionView(plan, hardeningJournalDigest(pendingRaw), "pending")
		check := s.hardeningJournalRecoveryPreflight(ctx, plan)
		if terminal, exists := inventory.Records[plan.ID]; exists {
			row.State = terminal.State + "_pending_cleanup"
			if terminal.PlanSHA256 != row.SHA256 || !hardeningJournalSameRawPlan(terminal.Plan, pendingRaw) {
				check = errors.New("原终态回执与待恢复记录冲突")
			} else {
				check = s.hardeningJournalVerifyState(ctx, plan, terminal.State)
			}
		}
		row.RecoveryPermitted = check == nil
		row.Detail = "可按原任务与完整摘要显式恢复；提交时仍重新核对实际状态"
		if check != nil {
			row.Detail = check.Error()
		}
		out.Pending = &row
	}
	config, err := s.hardeningConfigBackupsMode(false)
	if err != nil {
		return out, err
	}
	manifest, err := s.hardeningManifestBackup()
	if err != nil {
		return out, err
	}
	old, err := s.readSoftwareManifest("system-hardening")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	out.Installed = err == nil
	targets, originals := map[string]string{}, map[string]string{}
	if out.Installed {
		out.Profile, err = hardeningProfile(old.Settings)
		if err != nil {
			return out, err
		}
		out.Version = old.Version
		targets = hardeningValues(out.Profile)
		_, err = hardeningPrevious(old)
		out.OriginalsComplete = err == nil
		if err == nil {
			originals = maps.Clone(old.Previous)
		}
		if err != nil {
			out.Detail = err.Error()
			originals = map[string]string{}
		}
	}
	configErr := hardeningConfigMatches(config, old, out.Installed)
	if err = hardeningManifestMatches(manifest, old, out.Installed); err != nil {
		return out, err
	}
	out.ConfigMatches = configErr == nil
	allMatch := true
	for _, key := range hardeningSorted(hardeningValues("strict")) {
		row := hardeningParameterObservation{Key: key, Target: targets[key]}
		_, row.Managed = targets[key]
		row.Original, row.OriginalKnown = originals[key]
		row.Actual, err = s.sysctlValue(ctx, key)
		if err != nil || !hardeningValueValid(key, row.Actual) {
			row.Detail = "实际值无法核对"
			allMatch = false
		} else {
			row.Drift = row.Managed && row.Actual != row.Target
			row.Reversible = !(key == "kernel.unprivileged_bpf_disabled" && row.Actual == "1" || key == "kernel.yama.ptrace_scope" && row.Actual == "3")
			if !row.Reversible {
				row.Detail = "本次启动不可即时撤销的锁定值；不会猜测原值或自动重启"
			}
			if row.OriginalKnown {
				if restoreErr := hardeningReversible(key, row.Actual, row.Original); restoreErr != nil {
					row.Reversible = false
					row.Detail = restoreErr.Error()
					allMatch = false
				}
			}
			allMatch = allMatch && !row.Drift
		}
		out.Parameters = append(out.Parameters, row)
	}
	// Re-read complete file authorities, not merely their path names.
	now, err := s.hardeningJournalCurrentFiles()
	if err != nil {
		return out, err
	}
	before := append(config, manifest)
	for i := range before {
		if !hardeningBackupSame(before[i], now[i]) {
			return out, errors.New("加固状态在只读采样期间改变，请刷新")
		}
	}
	_, currentRaw, currentErr := s.hardeningJournalPending()
	if (pendingErr == nil) != (currentErr == nil) || currentErr != nil && !errors.Is(currentErr, os.ErrNotExist) || !bytes.Equal(pendingRaw, currentRaw) {
		return out, errors.New("加固原事务在只读采样期间改变，请刷新")
	}
	out.Healthy = out.Installed && allMatch && out.ConfigMatches && out.OriginalsComplete && out.Pending == nil
	if out.Pending != nil {
		out.Detail = "存在未闭合的原加固事务；未确认新基线生效，普通变更被阻止"
	} else if configErr != nil {
		out.Detail = configErr.Error()
	} else if out.Healthy {
		out.Detail = "实际内核、完整受管配置与原值记录通过核对；只读采样不执行修复"
	} else if out.Installed && out.OriginalsComplete {
		out.Detail = "发现参数偏差或实际值读取失败；未自动覆盖"
	}
	return out, nil
}

func (s *Service) hardeningInspectionRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/software/system-hardening/inspection", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		out, err := s.inspectHardening(r.Context())
		if err != nil {
			respond(w, 409, map[string]any{"error": err.Error(), "state_unknown": true})
			return
		}
		respond(w, 200, out)
	})
}
