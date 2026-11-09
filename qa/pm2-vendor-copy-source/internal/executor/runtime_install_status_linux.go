//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

func validateRuntimeInstallStatus(st InstallStatus, id string) error {
	release, known := runtimecatalog.Find(st.ReleaseID)
	if !core.ValidID(id) || st.JobID != id || !known || len(st.Steps) > 128 || len(st.Error) > 65536 {
		return errors.New("安装记录身份不可核实，原记录保留")
	}
	if st.ExtensionID != "" {
		if _, known := runtimecatalog.FindExtension(st.ExtensionID); !known || release.Family != "php" {
			return errors.New("安装扩展记录身份不可核实")
		}
	}
	switch st.State {
	case "queued", "running":
		if st.Error != "" {
			return errors.New("未完成安装记录含矛盾的错误结果")
		}
	case "succeeded":
		if st.Error != "" {
			return errors.New("安装成功记录含错误，未推断成功")
		}
	case "failed":
	default:
		return errors.New("安装记录状态未知，未推断结果")
	}
	return nil
}

// Observation never rewrites native evidence. In particular, an inactive unit
// cannot overwrite an atomic successful record or leave a stopped job reported
// as running forever. A stopped service without completion is uncertain, not a
// successful runtime installation and not permission to restart its compiler.
func readRuntimeInstallStatus(ctx context.Context, id string, run Command) (InstallStatus, error) {
	st, err := readInstall(id)
	if err != nil {
		return st, err
	}
	if err := validateRuntimeInstallStatus(st, id); err != nil {
		return st, err
	}
	if st.State != "queued" && st.State != "running" {
		if st.State == "failed" && st.Error == "" {
			st.Error = "原生安装已记录失败；具体错误缺失，请核对保留日志"
		}
		return st, nil
	}
	observe := func() (runtimeInstallUnitObservation, error) {
		return observeRuntimeInstallUnit(ctx, id, st.ReleaseID, run)
	}
	seen, err := observe()
	if err != nil {
		return st, err
	}
	if seen.terminal() {
		latest, err := readInstall(id)
		if err != nil {
			return st, err
		}
		if err := validateRuntimeInstallStatus(latest, id); err != nil || latest.ReleaseID != st.ReleaseID || latest.ExtensionID != st.ExtensionID {
			return st, errors.New("安装记录在服务核验期间身份变化，未修改或推断结果")
		}
		st = latest
		if st.State == "succeeded" || st.State == "failed" {
			if st.State == "failed" && st.Error == "" {
				st.Error = "原生安装已记录失败；具体错误缺失，请核对保留日志"
			}
			return st, nil
		}
		// A concurrent explicit start may have occurred after the first read.
		// Observe its actual new/pending generation instead of guessing failure.
		seen, err = observe()
		if err != nil {
			return st, err
		}
	}
	st.State, st.Error = seen.result(st.State)
	return st, nil
}

func runtimeInstallUnitName(id, releaseID string) string {
	if release, _ := runtimecatalog.Find(releaseID); release.Family == "docker" {
		return "panel-docker-install@" + id + ".service"
	}
	return "panel-install@" + id + ".service"
}

func observeRuntimeInstallUnit(ctx context.Context, id, releaseID string, run Command) (runtimeInstallUnitObservation, error) {
	output, err := run(ctx, "/usr/bin/systemctl", "show", "--property="+runtimeInstallUnitProperties, runtimeInstallUnitName(id, releaseID))
	if err != nil {
		return runtimeInstallUnitObservation{}, fmt.Errorf("安装服务状态读取失败，未修改原记录: %w", err)
	}
	return decodeRuntimeInstallUnitObservation(output)
}
