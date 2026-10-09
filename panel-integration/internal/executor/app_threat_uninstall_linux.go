//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func threatIDSStoppedUnit(output string, missing bool) bool {
	if len(output) > 4096 {
		return false
	}
	wanted := map[string]string{"MainPID": "0", "ActiveState": "inactive"}
	if missing {
		wanted["LoadState"] = "not-found"
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] || wanted[key] != value {
			return false
		}
		seen[key] = true
	}
	return len(seen) == len(wanted)
}

// Called under the IDS namespace lock before removing installed.json. No
// event/archive/runtime files are deleted and unknown units are not stopped.
func (s *Service) threatIDSUninstallPreflight(ctx context.Context) error {
	items, err := s.readThreatIDSOperations()
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Operation.State == "queued" || item.Operation.State == "running" {
			return errors.New("IDS 原生后台操作尚未结束；保留应用，不卸载")
		}
	}
	if err := s.threatIDSUpgradeNoPending(); err != nil {
		return err
	}
	if _, err := os.Lstat(s.wafPendingPath()); !os.IsNotExist(err) {
		return errors.New("IDS 配置仍有待恢复事务；不卸载")
	}
	rotation, err := s.readThreatIDSRotation()
	if err != nil || rotation.Pending != nil || rotation.Retiring != nil {
		return errors.New("IDS 日志轮转尚未核对完成；保留记录并拒绝卸载")
	}
	dependency, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "panel-app-dependencies@network-threat-detection.service", "--property=ActiveState", "--value")
	if err != nil || strings.TrimSpace(dependency) != "inactive" && strings.TrimSpace(dependency) != "failed" {
		return errors.New("IDS 原生准备尚在运行或状态未知；不能卸载")
	}
	if _, err := os.Lstat(filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json")); os.IsNotExist(err) {
		state, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", threatIDSService, "--property=LoadState,ActiveState,MainPID")
		if err != nil || !threatIDSStoppedUnit(state, true) {
			return errors.New("IDS 没有受管运行时但存在未知采集单元；不卸载")
		}
		return nil
	} else if err != nil {
		return err
	}
	if _, _, _, err := s.threatIDSImmutable(ctx); err != nil {
		return err
	}
	boot, err := s.threatIDSBootState(ctx)
	if err != nil || boot {
		return errors.New("IDS 开机采集未明确关闭；先关闭后卸载")
	}
	state, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", threatIDSService, "--property=ActiveState,MainPID")
	if err != nil || !threatIDSStoppedUnit(state, false) {
		return errors.New("IDS 采集仍在运行或状态未知；先停止后卸载")
	}
	return nil
}
