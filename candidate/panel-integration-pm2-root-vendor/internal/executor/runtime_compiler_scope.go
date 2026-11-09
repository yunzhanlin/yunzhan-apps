package executor

import (
	"errors"
	"local/panel/internal/core"
	"regexp"
	"strconv"
	"strings"
)

// fdinfo belongs to the retained pidfd, not a freshly looked-up numeric PID.
// Linux reports Pid=-1 only after that task has been detached/reaped; POLLIN
// alone reports exit and can still describe an unreaped zombie.
func runtimeCompilerPIDFDTask(data []byte) (int, error) {
	if len(data) == 0 || len(data) > 4096 || !strings.HasSuffix(string(data), "\n") || strings.ContainsAny(string(data), "\r\x00") {
		return 0, errors.New("稳定进程引用的内核身份记录异常")
	}
	seen, pid := false, 0
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		value, ok := strings.CutPrefix(line, "Pid:\t")
		if !ok {
			continue
		}
		parsed, err := strconv.Atoi(value)
		if seen || err != nil || (parsed != -1 && parsed < 1) || strconv.Itoa(parsed) != value {
			return 0, errors.New("稳定进程引用缺少唯一、规范的进程身份")
		}
		seen, pid = true, parsed
	}
	if !seen {
		return 0, errors.New("内核未提供稳定进程引用的回收状态，未判定编译完成")
	}
	return pid, nil
}

var ownRuntimeCompilerUnit = regexp.MustCompile(`^panel-own-(runtime|apache-runtime)[a-z0-9_-]{1,110}\.service$`)
var ownApacheBodyCompilerUnit = regexp.MustCompile(`^panel-own-apache-body-worker[a-z0-9_-]{1,95}\.service$`)
var ownNginxWAFCompilerUnit = regexp.MustCompile(`^panel-own-waf-engine-build[a-z0-9_-]{1,95}\.service$`)
var ownAnalyticsHTMLCompilerUnit = regexp.MustCompile(`^panel-own-analytics-html-(build|worker)[a-z0-9_-]{1,85}\.service$`)

const nativeCompilerCollectionContract = "dedicated_cgroup_v2_pidfd_task_reaped_v2"

// Only the dedicated compiler service can collect its own members. Never
// accept a session/user scope, the panel daemon, a path or a caller's unit name.
func decodeRuntimeCompilerCgroup(text string) (string, error) {
	path, err := nativeCompilerCgroupUnit(text)
	if err != nil {
		return "", err
	}
	allowed := path == "panel-app-dependencies@pure-ftpd.service" || ownRuntimeCompilerUnit.MatchString(path)
	if id, ok := strings.CutPrefix(path, "panel-install@"); ok {
		id, service := strings.CutSuffix(id, ".service")
		allowed = service && core.ValidID(id)
	}
	if !allowed {
		return "", errors.New("当前服务不是固定运行时构建服务；禁止按 UID、进程名或其他服务回收")
	}
	return "/system.slice/" + path, nil
}

// The Apache body compiler has its own closed authority. It does not inherit
// generic runtime, HTTP acceptance, report reader or daemon unit permissions.
func decodeApacheBodyCompilerCgroup(text string) (string, error) {
	path, err := nativeCompilerCgroupUnit(text)
	if err != nil {
		return "", err
	}
	allowed := ownApacheBodyCompilerUnit.MatchString(path)
	if id, ok := strings.CutPrefix(path, "panel-apache-body-build@"); ok {
		id, service := strings.CutSuffix(id, ".service")
		allowed = service && core.ValidID(id)
	}
	if !allowed {
		return "", errors.New("当前服务不是固定 Apache 请求体编译服务，未执行或回收其他服务进程")
	}
	return "/system.slice/" + path, nil
}

// Nginx body compilation is a distinct authority. Neither a panel daemon nor
// Apache/runtime/HTTP/report units may launch or collect this compiler.
func decodeNginxWAFCompilerCgroup(text string) (string, error) {
	path, err := nativeCompilerCgroupUnit(text)
	if err != nil {
		return "", err
	}
	allowed := ownNginxWAFCompilerUnit.MatchString(path)
	if id, ok := strings.CutPrefix(path, "panel-waf-engine-build@"); ok {
		id, service := strings.CutSuffix(id, ".service")
		allowed = service && core.ValidID(id)
	}
	if !allowed {
		return "", errors.New("当前服务不是固定 Nginx 请求体编译服务，未执行或回收其他服务进程")
	}
	return "/system.slice/" + path, nil
}

func decodeAnalyticsHTMLCompilerCgroup(text string) (string, error) {
	path, err := nativeCompilerCgroupUnit(text)
	if err != nil {
		return "", err
	}
	allowed := ownAnalyticsHTMLCompilerUnit.MatchString(path)
	if id, ok := strings.CutPrefix(path, "panel-analytics-html-build@"); ok {
		id, service := strings.CutSuffix(id, ".service")
		allowed = service && core.ValidID(id)
	}
	if !allowed {
		return "", errors.New("当前服务不是固定网站分析 HTML 编译服务，未执行或回收其他服务进程")
	}
	return "/system.slice/" + path, nil
}

func nativeCompilerCgroupUnit(text string) (string, error) {
	if len(text) > 4096 || !strings.HasSuffix(text, "\n") || strings.Count(text, "\n") != 1 || strings.ContainsAny(text, "\r\x00") {
		return "", errors.New("不能核实运行时构建服务的唯一 cgroup v2 身份")
	}
	path, ok := strings.CutPrefix(strings.TrimSuffix(text, "\n"), "0::/system.slice/")
	if !ok || strings.Contains(path, "/") || len(path) > 160 {
		return "", errors.New("运行时编译不属于独立 systemd 服务，未执行或回收")
	}
	return path, nil
}
