//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type pm2UnitState struct {
	LoadState, ActiveState, SubState, MainPID, InvocationID, UnitFileState string
}

var pm2InvocationID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Observe both the running service and its persistent boot setting. An
// activating, missing, masked or incomplete service cannot be treated as stopped.
func (s *Service) readPM2UnitState(ctx context.Context, unit string) (pm2UnitState, error) {
	var result pm2UnitState
	out, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", unit, "--property=LoadState,MainPID,InvocationID,ActiveState,SubState,UnitFileState")
	if err != nil || len(out) > 4096 {
		return result, errors.New("无法核对 PM2 运行及开机启动状态，请刷新检查")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if _, duplicate := fields[key]; !ok || duplicate {
			return result, errors.New("PM2 服务状态不完整，请刷新检查")
		}
		fields[key] = value
	}
	if len(fields) != 6 {
		return result, errors.New("PM2 服务状态不完整，请刷新检查")
	}
	for _, key := range []string{"LoadState", "ActiveState", "SubState", "MainPID", "InvocationID", "UnitFileState"} {
		if _, present := fields[key]; !present {
			return result, errors.New("PM2 服务状态缺少必要字段，请刷新检查")
		}
	}
	result = pm2UnitState{fields["LoadState"], fields["ActiveState"], fields["SubState"], fields["MainPID"], fields["InvocationID"], fields["UnitFileState"]}
	pid, pidErr := strconv.ParseUint(result.MainPID, 10, 32)
	validProcess := result.ActiveState == "active" && result.SubState == "running" && pid > 1 && pm2InvocationID.MatchString(result.InvocationID) ||
		(result.ActiveState == "inactive" && result.SubState == "dead" || result.ActiveState == "failed" && result.SubState == "failed") && pid == 0
	validBoot := result.UnitFileState == "enabled" || result.UnitFileState == "disabled" || result.UnitFileState == "enabled-runtime"
	if result.LoadState != "loaded" || pidErr != nil || strconv.FormatUint(pid, 10) != result.MainPID || !validProcess || !validBoot || result.InvocationID != "" && !pm2InvocationID.MatchString(result.InvocationID) {
		return pm2UnitState{}, errors.New("PM2 服务正处于切换或未知状态，请刷新后操作")
	}
	return result, nil
}

func (s *Service) restorePM2BootState(ctx context.Context, unit string, before pm2UnitState) error {
	args := []string{"disable", unit}
	if before.UnitFileState == "enabled" {
		args = []string{"enable", unit}
	} else if before.UnitFileState == "enabled-runtime" {
		// A failed persistent start may have created a persistent link. Remove
		// it before restoring the original runtime-only enablement.
		if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "disable", unit); err != nil {
			return err
		}
		args = []string{"enable", "--runtime", unit}
	}
	_, err := s.Config.Run(ctx, "/usr/bin/systemctl", args...)
	return err
}

func (s *Service) controlPM2(ctx context.Context, app pm2App, action, unit string) (any, error) {
	before, err := s.readPM2UnitState(ctx, unit)
	if err != nil {
		return nil, err
	}
	args := []string{action, unit}
	switch action {
	case "start":
		args = []string{"enable", "--now", unit}
	case "stop":
		args = []string{"disable", "--now", unit}
	case "restart": // An explicit restart preserves the chosen boot setting.
	default:
		return nil, errors.New("PM2 服务操作无效")
	}
	_, err = s.Config.Run(ctx, "/usr/bin/systemctl", args...)
	if err == nil && action != "stop" {
		err = s.pm2Ready(ctx, unit, app.Port)
	}
	var after pm2UnitState
	if err == nil {
		after, err = s.readPM2UnitState(ctx, unit)
		if err == nil && (action == "stop" && (after.ActiveState != "inactive" || after.UnitFileState != "disabled") ||
			action != "stop" && after.ActiveState != "active" || action == "start" && after.UnitFileState != "enabled" ||
			action == "restart" && after.UnitFileState != before.UnitFileState) {
			err = errors.New("PM2 服务或开机启动状态未达到请求目标")
		}
	}
	if err != nil {
		if action == "start" {
			rollback, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			var stopErr error
			if before.ActiveState != "active" {
				_, stopErr = s.Config.Run(rollback, "/usr/bin/systemctl", "stop", unit)
			}
			bootErr := s.restorePM2BootState(rollback, unit, before)
			restored, verifyErr := s.readPM2UnitState(rollback, unit)
			if stopErr != nil || bootErr != nil || verifyErr != nil || restored.UnitFileState != before.UnitFileState ||
				before.ActiveState == "active" && restored.ActiveState != "active" || before.ActiveState != "active" && restored.ActiveState != "inactive" {
				return nil, errors.New("PM2 启动失败，原运行或开机设置未能完整恢复；项目清单保留，请核对")
			}
		}
		return nil, fmt.Errorf("PM2 服务操作未完成，项目清单保留: %w", err)
	}
	return map[string]any{"id": app.ID, "action": action, "ok": true, "state": after.ActiveState, "boot_enabled": after.UnitFileState == "enabled"}, nil
}
