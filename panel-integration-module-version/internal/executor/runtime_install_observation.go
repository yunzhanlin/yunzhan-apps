package executor

import (
	"errors"
	"strconv"
	"strings"
)

const runtimeInstallUnitProperties = "LoadState,ActiveState,Result,ExecMainStartTimestampMonotonic,Job"

type runtimeInstallUnitObservation struct {
	Load, Active, Result string
	Started              uint64
	Pending              bool
}

// Parse one complete systemd observation, not independent property calls that
// can belong to different service generations. Unknown/partial reads do not
// mean stopped, failed, successful or never installed.
func decodeRuntimeInstallUnitObservation(text string) (runtimeInstallUnitObservation, error) {
	var out runtimeInstallUnitObservation
	if len(text) > 4096 {
		return out, errors.New("安装服务状态过大，未推断构建结果")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.ContainsAny(value, "\r\x00") || strings.TrimSpace(value) != value {
			return out, errors.New("安装服务状态格式不可核实")
		}
		if _, duplicate := values[key]; duplicate {
			return out, errors.New("安装服务状态含重复字段")
		}
		switch key {
		case "LoadState", "ActiveState", "Result", "ExecMainStartTimestampMonotonic", "Job":
		default:
			return out, errors.New("安装服务状态含未知字段")
		}
		values[key] = value
	}
	if len(values) != 5 {
		return out, errors.New("安装服务状态读取不完整，未推断结果")
	}
	out.Load, out.Active, out.Result = values["LoadState"], values["ActiveState"], values["Result"]
	switch out.Load {
	case "loaded", "not-found", "error", "bad-setting", "masked":
	default:
		return out, errors.New("安装服务加载状态未知")
	}
	switch out.Active {
	case "active", "activating", "deactivating", "reloading", "refreshing", "inactive", "failed":
	default:
		return out, errors.New("安装服务运行状态未知")
	}
	if out.Load == "loaded" {
		switch out.Result {
		case "success", "resources", "timeout", "exit-code", "signal", "core-dump", "watchdog", "start-limit-hit", "protocol", "oom-kill", "exec-condition", "condition":
		default:
			return out, errors.New("安装服务退出结果未知")
		}
	} else if out.Active != "inactive" || out.Result != "" && out.Result != "success" {
		return out, errors.New("安装服务加载与运行状态矛盾")
	}
	var err error
	out.Started, err = strconv.ParseUint(values["ExecMainStartTimestampMonotonic"], 10, 64)
	if err != nil {
		return out, errors.New("安装服务启动记录不可核实")
	}
	if job := values["Job"]; job != "" {
		id, err := strconv.ParseUint(job, 10, 64)
		if err != nil {
			return out, errors.New("安装服务排队状态不可核实")
		}
		out.Pending = id != 0
	}
	return out, nil
}

func (v runtimeInstallUnitObservation) terminal() bool {
	return v.Load != "loaded" || !v.Pending && (v.Active == "inactive" || v.Active == "failed")
}

func (v runtimeInstallUnitObservation) result(state string) (string, string) {
	if v.Load != "loaded" {
		return "needs_attention", "安装服务未加载或配置不可用；原构建记录保留，未自动重试或发布运行时"
	}
	if !v.terminal() {
		return state, ""
	}
	if v.Result != "success" {
		return "failed", "原生构建服务已退出（" + v.Result + "）；原构建记录与日志保留，请核对后显式重试"
	}
	if v.Active == "failed" {
		return "needs_attention", "安装服务失败状态与退出结果矛盾，未推断成功或修改原记录"
	}
	if v.Started == 0 {
		return "needs_attention", "安装服务没有实际启动记录；原请求保留，未自动重试或发布运行时"
	}
	return "needs_attention", "安装服务已退出但缺少可核实的完成记录；原构建记录与日志保留，未冒充成功或自动重试"
}
