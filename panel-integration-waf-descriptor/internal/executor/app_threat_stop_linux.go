//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func threatIDSLoadedStopPolicy(raw string) bool {
	if len(raw) > 8192 {
		return false
	}
	wanted := map[string]string{"FragmentPath": "/etc/systemd/system/panel-network-ids.service", "DropInPaths": "", "Transient": "no", "NeedDaemonReload": "no"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] || wanted[key] != value {
			return false
		}
		if _, ok := wanted[key]; !ok {
			return false
		}
		seen[key] = true
	}
	return len(seen) == len(wanted)
}

func threatIDSEmptyStopCommands(raw string) bool {
	// systemctl's command-array formatter omits an empty ExecStop even with
	// --all. Independently ask the fixed D-Bus object for both typed arrays;
	// missing output or an unknown/nonempty array is never an empty policy.
	return strings.TrimSpace(raw) == "a(sasbttttuii) 0\na(sasbttttuii) 0" && len(raw) < 128
}

func threatIDSCaptureStopValues(raw string) (map[string]string, bool) {
	if len(raw) > 4096 {
		return nil, false
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "ActiveState" && key != "MainPID") {
			return nil, false
		}
		if _, duplicate := values[key]; duplicate {
			return nil, false
		}
		values[key] = value
	}
	return values, len(values) == 2
}

func threatIDSSafeStopIdle(raw string) bool {
	values, ok := threatIDSCaptureStopValues(raw)
	return ok && values["MainPID"] == "0" && (values["ActiveState"] == "inactive" || values["ActiveState"] == "failed")
}

func threatIDSRecoveryActive(raw string) bool {
	values, ok := threatIDSCaptureStopValues(raw)
	pid, err := strconv.Atoi(values["MainPID"])
	return ok && err == nil && pid > 1 && strconv.Itoa(pid) == values["MainPID"] && values["ActiveState"] == "active"
}

func threatIDSResumeAfterRecovery(state *threatIDSRecoveryState, restoreRunning bool) bool {
	return state != nil && state.WasActive && !state.StopRequested && restoreRunning
}

func (s *Service) threatIDSValidateLoadedStop(ctx context.Context) error {
	loaded, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "--all", threatIDSService, "--property=FragmentPath,DropInPaths,Transient,NeedDaemonReload")
	if err != nil || !threatIDSLoadedStopPolicy(loaded) {
		return errors.New("IDS 已加载停止策略含外部扩展、停止命令或未重载配置；未停止未知单元")
	}
	commands, err := s.Config.Run(ctx, "/usr/bin/busctl", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/panel_2dnetwork_2dids_2eservice", "org.freedesktop.systemd1.Service", "ExecStop", "ExecStopPost")
	if err != nil || !threatIDSEmptyStopCommands(commands) {
		return errors.New("IDS 实际已加载的停止命令不是两个明确空数组；未停止未知策略")
	}
	return nil
}

// Caller owns the configuration lock and has independently checked both the
// journal source and every file in its recovery set. Unlike an explicit stop,
// recovery must not cancel the dependent capture job queued behind this boot
// prerequisite. An attested idle service therefore needs no stop dispatch.
func (s *Service) threatIDSRecoveryStopCapture(ctx context.Context, runtime threatIDSRuntime, account threatIDSAccount, restoreRunning bool) error {
	if err := s.threatIDSValidateLoadedStop(ctx); err != nil {
		return err
	}
	state, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", threatIDSService, "--property=ActiveState,MainPID")
	if err != nil {
		return err
	}
	if threatIDSSafeStopIdle(state) {
		return nil
	}
	// The cold-boot prerequisite must never have a native dependent running.
	// Unknown, activating, or noncanonical states remain recoverable evidence,
	// rather than authority to cancel a job or stop an unrelated process.
	if !restoreRunning || !threatIDSRecoveryActive(state) {
		return errors.New("IDS 开机恢复时采集不是明确空闲 / PID 0；未取消启动任务或停止未知进程")
	}
	configuration, err := s.threatIDSConfig()
	if err != nil {
		return err
	}
	active, _, err := s.threatIDSProcess(ctx, runtime, configuration, account)
	if err != nil || !active {
		return errors.New("IDS 恢复停止前的实际程序、账户、参数或权限不能核对；原恢复记录保留")
	}
	if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "stop", threatIDSService); err != nil {
		return err
	}
	state, err = s.Config.Run(ctx, "/usr/bin/systemctl", "show", threatIDSService, "--property=ActiveState,MainPID")
	if err != nil || !threatIDSStoppedUnit(state, false) {
		return errors.New("IDS 恢复停止后并非明确 inactive / PID 0；原恢复记录保留")
	}
	return nil
}

// Caller owns the IDS configuration lock. Never parse damaged rule data to
// stop, write its YAML, disable boot, seal logs, or dispatch an arbitrary unit.
func (s *Service) stopAttestedThreatIDS(ctx context.Context, expected int64) (any, error) {
	runtime, account, unit, err := s.threatIDSIdentity(ctx)
	if err != nil {
		return nil, err
	}
	configuration, readErr := s.threatIDSConfig()
	if expected < 0 || readErr == nil && expected != configuration.Revision || readErr != nil && expected != 0 {
		return nil, errors.New("IDS 停止修订冲突；配置不可读时须先刷新为未知修订 0，不能冒用旧修订")
	}
	if err := s.threatIDSValidateLoadedStop(ctx); err != nil {
		return nil, err
	}
	state, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", threatIDSService, "--property=ActiveState,MainPID")
	if err != nil {
		return nil, err
	}
	if !threatIDSSafeStopIdle(state) {
		active, _, err := s.threatIDSProcess(ctx, runtime, configuration, account)
		if err != nil || !active {
			return nil, errors.New("IDS 活跃进程的实际程序、账户、参数或权限不能核对；未停止外部进程")
		}
	}
	if _, err := os.Lstat(s.wafPendingPath()); err == nil {
		tx, err := s.readWAFTransaction()
		if err != nil {
			return nil, err
		}
		digest, err := nfsFileDigest(filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json"), 32<<10)
		if err != nil || tx.IDS.UnitSHA != unit.UnitSHA || tx.IDS.RuntimeRecordSHA != digest {
			return nil, errors.New("IDS 待恢复来源与当前可信停止单元不同；原记录保留")
		}
		// A later explicit stop overrides only automatic resumption, not the
		// original WasActive evidence, files, revision, owner or boot choice.
		if !tx.IDS.StopRequested {
			tx.IDS.StopRequested = true
			if err := s.wafTransactionContract(tx); err != nil {
				return nil, err
			}
			if err := wafWriteTransaction(s.wafPendingPath(), tx); err != nil {
				return nil, err
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "stop", threatIDSService); err != nil {
		return nil, err
	}
	state, err = s.Config.Run(ctx, "/usr/bin/systemctl", "show", threatIDSService, "--property=ActiveState,MainPID")
	if err != nil || !threatIDSStoppedUnit(state, false) {
		return nil, errors.New("IDS 停止后并非明确 inactive / PID 0；未宣称已停止")
	}
	return map[string]any{"capture_stopped_verified": true, "capture_started": false, "configuration_revision_known": readErr == nil, "expected_revision": expected, "files_preserved": true, "boot_choice_unchanged": true, "passive_only": true, "observation_required": true, "time": core.Now()}, nil
}
