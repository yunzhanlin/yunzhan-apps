//go:build linux

package executor

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func verifyApacheBodyWorkerCapabilities() error {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil || len(b) > 32<<10 {
		return errors.New("不能核对 Apache 专用构建监督进程权限")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if name, value, ok := strings.Cut(line, ":"); ok {
			fields[name] = strings.TrimSpace(value)
		}
	}
	// Root's exact closed set includes changed-UID cancellation, not a blanket
	// CAP_SYS_PTRACE/DAC_OVERRIDE grant. Reject a broken unit before filesystem
	// initialization, a record write, source download or compiler execution.
	if fields["NoNewPrivs"] != "1" {
		return errors.New("Apache 构建监督进程缺少禁止提权约束")
	}
	for _, name := range []string{"CapPrm", "CapEff", "CapBnd"} {
		value, err := strconv.ParseUint(fields[name], 16, 64)
		if err != nil || value != 0xe5 {
			return fmt.Errorf("Apache 构建监督进程 %s 不是固定权限集合；未开始写入或编译", name)
		}
	}
	for _, name := range []string{"CapInh", "CapAmb"} {
		value, err := strconv.ParseUint(fields[name], 16, 64)
		if err != nil || (value != 0 && value != 0xe5) {
			return errors.New("Apache 构建监督进程继承或环境权限不是固定集合")
		}
	}
	return nil
}

func apacheBodyCompilerSubreaper() error {
	// Adopt orphaned compiler grandchildren so cancellation can reap them,
	// not merely chmod their still-open files or leave zombies to PID 1.
	const prSetChildSubreaper = 36
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("不能建立 Apache 编译子进程回收边界: %w", errno)
	}
	return nil
}
