package diskjob

import (
	"errors"
	"path"
	"regexp"
)

var ErrLaunch = errors.New("全盘固定工作入口或任务身份无效；未启动任何命令")
var releasedExecutor = regexp.MustCompile(`^/opt/panel/releases/[0-9]+\.[0-9]+\.[0-9]+([.-][a-z0-9]+)*/bin/panel-executor$`)

func UnitName(id string, inventory bool) (string, error) {
	if !ValidID(id) {
		return "", ErrLaunch
	}
	prefix := "panel-disk-host-"
	if inventory {
		prefix = "panel-disk-host-inventory-"
	}
	return prefix + id + ".scope", nil
}

// A scope retains the launcher's environment; nsenter replaces only the fixed
// PID1 mount/root/cwd view BEFORE the Go program creates runtime threads.
// setpriv drops bounding/ambient/inheritable capabilities before exec, so ALL
// Go threads inherit the same read/search-only capability, not just one thread.
// No shell, caller command, namespace, property, root path or budget is accepted.
// The caller must independently verify the approved running program's bytes.
func LaunchArguments(id, executor string, inventory bool) ([]string, error) {
	unit, err := UnitName(id, inventory)
	if err != nil || path.Clean(executor) != executor || executor != "/opt/panel/bin/panel-executor" && executor != "/opt/panel/current/bin/panel-executor" && !releasedExecutor.MatchString(executor) {
		return nil, ErrLaunch
	}
	runtime := "1800s"
	mode := "--disk-host-job=" + id
	if inventory {
		runtime = "10s"
		mode = "--disk-host-inventory=" + id
	}
	args := []string{"--scope", "--quiet", "--unit=" + unit, "--property=CPUQuota=20%", "--property=CPUQuotaPeriodSec=100ms", "--property=MemoryMax=512M", "--property=MemoryHigh=384M", "--property=MemorySwapMax=0", "--property=TasksMax=32", "--property=IOWeight=10", "--property=RuntimeMaxSec=" + runtime, "--property=TimeoutStopSec=10s", "--property=KillMode=control-group", "--property=SendSIGKILL=yes", "--property=OOMPolicy=kill", "/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "--root=/proc/1/root", "--wdns=/", "--", "/usr/bin/setpriv", "--bounding-set=-all,+dac_read_search", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", executor, mode}
	return args, nil
}
