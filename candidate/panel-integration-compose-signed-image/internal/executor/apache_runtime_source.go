package executor

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

// Change only reviewed ServerRoot and standard DSO loader paths. Site roots,
// rewrites, PHP sockets, log paths, comments and unrelated strings remain exact.
// Remove native body/CC blocks with their original policy before calling this.
func apacheRuntimeSource(source string, previous, next runtimecatalog.Release) (string, error) {
	selected, err := apacheSourceRelease(source)
	if err != nil || selected != previous {
		return "", errors.New("Apache 原配置与原运行版本不匹配")
	}
	known, ok := runtimecatalog.Find(next.ID)
	if !ok || known != next || next.Family != "apache" {
		return "", errors.New("Apache 目标版本不在审核目录中")
	}
	if apacheNativeDirectivesPresent(source) {
		return "", errors.New("Apache 原生模块必须先按原策略核对，不能直接改写 ABI 路径")
	}
	allowed := map[string]bool{}
	for _, name := range []string{"mpm_event", "authz_core", "authz_host", "unixd", "log_config", "mime", "dir", "env", "setenvif", "headers", "rewrite", "proxy", "proxy_fcgi", "remoteip", "unique_id"} {
		allowed[name+"_module"] = true
	}
	lines := strings.Split(source, "\n")
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "ServerRoot") {
			lines[index] = strings.Replace(line, previous.Prefix(), next.Prefix(), 1)
		} else if strings.EqualFold(fields[0], "LoadModule") {
			if len(fields) != 3 || !allowed[fields[1]] {
				return "", errors.New("Apache 含未审核模块加载，未猜测替换")
			}
			name := strings.TrimSuffix(fields[1], "_module")
			path := filepath.Join(previous.Prefix(), "modules/mod_"+name+".so")
			if fields[2] != path && fields[2] != strconv.Quote(path) {
				return "", errors.New("Apache 模块与原版本不一致，未替换")
			}
			lines[index] = strings.Replace(line, path, filepath.Join(next.Prefix(), "modules/mod_"+name+".so"), 1)
		}
	}
	result := strings.Join(lines, "\n")
	selected, err = apacheSourceRelease(result)
	if err != nil || selected != next {
		return "", errors.New("Apache 新运行版本选择不可核实")
	}
	return result, nil
}

// Pure plan: preserve every policy field, replacing only explicitly selected
// immutable engine IDs and advancing the existing loaded-generation revision.
func apacheRuntimePolicy(previous core.WAFConfig, engineID string) (core.WAFConfig, error) {
	raw, err := core.DecodeApacheWAFNativeCCConfig(core.WAFSettings(previous))
	if err != nil {
		return core.WAFConfig{}, err
	}
	next := raw
	needsEngine := apacheBodyActive(previous) || previous.ApacheCC != nil
	if needsEngine && !core.ValidID(engineID) || !needsEngine && engineID != "" {
		return core.WAFConfig{}, errors.New("Apache 运行版本切换须明确选择匹配的新引擎；无原生策略时不能附带引擎")
	}
	if needsEngine {
		if next.Body != nil {
			next.Body.EngineJobID = engineID
		}
		if next.ApacheCC != nil {
			next.ApacheCC.EngineJobID = engineID
		}
	}
	next.Policy.Revision++
	return next, nil
}
