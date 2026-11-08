//go:build linux

package executor

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// The unified mount root is not normally the installer's own cgroup. Read
// the current, already closed-format systemd identity and every ancestor's
// memory ceiling. No caller path, cgroup creation or controller writes occur.
func compilerCurrentCgroupAvailable() (uint64, bool) {
	text, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, false
	}
	unit, err := nativeCompilerCgroupUnit(string(text))
	if err != nil {
		return 0, false
	}
	read := func(path string) ([]byte, error) {
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, 65))
	}
	var minimum uint64
	for _, dir := range []string{filepath.Join("/sys/fs/cgroup/system.slice", unit), "/sys/fs/cgroup/system.slice", "/sys/fs/cgroup"} {
		maximum, e1 := read(filepath.Join(dir, "memory.max"))
		current, e2 := read(filepath.Join(dir, "memory.current"))
		available, valid := compilerCgroupAvailable(maximum, current)
		if e1 != nil || e2 != nil || !valid {
			return 0, false
		}
		if available > 0 && (minimum == 0 || available < minimum) {
			minimum = available
		}
	}
	return minimum, true
}
