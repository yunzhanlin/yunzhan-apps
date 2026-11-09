//go:build linux

package executor

import (
	"context"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/runtimecatalog"
)

func admitRuntimePHPHostMemory(r runtimecatalog.Release) error {
	return admitRuntimePHPHostMemoryOwned(r, 0)
}

func admitRuntimePHPHostMemoryOwned(r runtimecatalog.Release, ownNonReclaimable uint64) error {
	selected, err := runtimePHPCompilerNeedsMemoryAdmission(r)
	if err != nil || !selected {
		return err
	}
	f, err := os.OpenFile("/proc/meminfo", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errRuntimePHPCompilerMemoryInventory
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return errRuntimePHPCompilerMemoryInventory
	}
	return runtimePHPCompilerMemoryAdmissionOwned(r, raw, ownNonReclaimable)
}

func admitRuntimePHPWorkerMemory(r runtimecatalog.Release) error {
	selected, err := runtimePHPCompilerNeedsMemoryAdmission(r)
	if err != nil || !selected {
		return err
	}
	owned, err := admitRuntimePHPCompilerKernelMemory()
	if err != nil {
		return err
	}
	return admitRuntimePHPHostMemoryOwned(r, owned.NonReclaimable)
}

// Source command boundaries (including make install) may see temporary host
// pressure after a successful link. Wait without a child or controller write,
// then re-read ALL original kernel/parent/host witnesses before admitting the
// next command. The initial install admission remains unchanged and immediate.
func waitRuntimePHPWorkerMemory(ctx context.Context, r runtimecatalog.Release) error {
	return awaitRuntimePHPCompilerMemory(ctx, r, func() error {
		return admitRuntimePHPWorkerMemory(r)
	}, runtimePHPCompilerMemoryDelay)
}

func runtimePHPCompilerMemoryDelay(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

func admitRuntimePHPCompilerKernelMemory() (runtimePHPCompilerOwnedMemory, error) {
	var owned runtimePHPCompilerOwnedMemory
	text, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return owned, errRuntimePHPCompilerMemoryKernel
	}
	scope, err := decodeRuntimeCompilerCgroup(string(text))
	if err != nil {
		return owned, errRuntimePHPCompilerMemoryKernel
	}
	root, err := os.OpenRoot("/sys/fs/cgroup")
	if err != nil {
		return owned, errRuntimePHPCompilerMemoryKernel
	}
	defer root.Close()
	mount, err := root.Open(".")
	if err != nil {
		return owned, errRuntimePHPCompilerMemoryKernel
	}
	var fs unix.Statfs_t
	err = unix.Fstatfs(int(mount.Fd()), &fs)
	rootInfo, statErr := mount.Stat()
	mount.Close()
	if err != nil || statErr != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return owned, errRuntimePHPCompilerMemoryKernel
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return owned, errRuntimePHPCompilerMemoryKernel
	}
	read := func(name string, limit int64) ([]byte, error) {
		f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, limit+1))
		if err != nil || int64(len(raw)) > limit {
			return nil, errRuntimePHPCompilerMemoryKernel
		}
		return raw, nil
	}
	prefix := strings.TrimPrefix(scope, "/") + "/"
	values := map[string]string{}
	for _, key := range []string{"memory.max", "memory.high", "memory.swap.max", "pids.max"} {
		raw, err := read(prefix+key, 64)
		if err != nil {
			return owned, errRuntimePHPCompilerMemoryKernel
		}
		values[key] = string(raw)
	}
	if err := runtimePHPCompilerMemoryKernelPolicy(values); err != nil {
		return owned, err
	}
	statRaw, e1 := read(prefix+"memory.stat", 65536)
	currentRaw, e2 := read(prefix+"memory.current", 32)
	if e1 != nil || e2 != nil {
		return owned, errRuntimePHPCompilerMemoryKernel
	}
	owned, err = runtimePHPCompilerMemoryFootprint(currentRaw, statRaw)
	if err != nil {
		return owned, err
	}
	for _, ancestor := range []string{"system.slice/", ""} {
		maximum, e1 := read(ancestor+"memory.max", 64)
		current, e2 := read(ancestor+"memory.current", 64)
		if ancestor == "" && os.IsNotExist(e1) && os.IsNotExist(e2) {
			// Only the true cgroup2 kernfs root lacks all non-root-only
			// memory/type interfaces; delegated/unknown roots are rejected.
			typeFile, typeErr := root.OpenFile("cgroup.type", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
			if typeErr == nil {
				typeFile.Close()
				return owned, errRuntimePHPCompilerMemoryKernel
			}
			controllers, err := read("cgroup.controllers", 4096)
			if err != nil || runtimePHPCompilerMemoryUncontrolledRoot(rootStat.Ino, controllers, true, true, os.IsNotExist(typeErr)) != nil {
				return owned, errRuntimePHPCompilerMemoryKernel
			}
			continue
		}
		if e1 != nil || e2 != nil {
			return owned, errRuntimePHPCompilerMemoryKernel
		}
		if err := runtimePHPCompilerMemoryAncestorOwned(maximum, current, owned.Charged); err != nil {
			return owned, err
		}
	}
	return owned, nil
}
