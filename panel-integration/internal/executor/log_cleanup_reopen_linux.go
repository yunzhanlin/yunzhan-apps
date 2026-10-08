//go:build linux

package executor

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (s *Service) prepareSiteLogReopen(ctx context.Context, active []plannedSiteLog) (func(context.Context) error, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	binary, err := s.nginxBinary()
	if err != nil {
		return nil, err
	}
	value, err := s.Config.RunWait(bounded, 3*time.Second, "/usr/bin/systemctl", "show", "nginx", "--property=ActiveState,MainPID")
	if err != nil {
		return nil, err
	}
	state, pidText := "", ""
	for _, line := range strings.Split(value, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if ok && key == "ActiveState" {
			state = val
		}
		if ok && key == "MainPID" {
			pidText = val
		}
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid < 2 || state != "active" {
		return nil, errors.New("Nginx 主进程未运行或身份不可核实；未开始轮转")
	}
	generation, err := captureWAFReloadGeneration(bounded, s.systemPath("/proc"), binary, pid)
	if err != nil {
		return nil, err
	}
	prior := make([]os.FileInfo, len(active))
	for i, item := range active {
		prior[i] = item.info
	}
	budget := 524288
	_, opened, err := siteLogProcessFiles(bounded, generation.ProcRoot, generation.Master, binary, nil, prior, &budget)
	if err != nil {
		return nil, err
	}
	for _, found := range opened {
		if !found {
			return nil, errors.New("Nginx 主进程未持有该站点活动日志；未开始轮转")
		}
	}
	return func(ctx context.Context) error {
		// A kernel process handle cannot be retargeted by PID reuse. No generic
		// kill command, fallback signal, restart or configuration reload exists.
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			return errors.New("内核无法固定 Nginx 进程句柄；不改用不安全的 PID 信号")
		}
		defer unix.Close(fd)
		identity, err := readWAFReloadProcess(generation.ProcRoot, pid)
		actual, exeErr := os.Readlink(filepath.Join(generation.ProcRoot, strconv.Itoa(pid), "exe"))
		if err != nil || exeErr != nil || identity.Start != generation.Master.Start || identity.Parent != generation.Master.Parent || actual != binary || ctx.Err() != nil {
			return errors.New("Nginx 主进程在轮转期间变化；未发送信号")
		}
		if err = unix.PidfdSendSignal(fd, unix.SIGUSR1, nil, 0); err != nil {
			return err
		}
		return waitSiteLogReopen(ctx, generation, s.systemPath("/var/log/nginx"), active)
	}, nil
}

func waitSiteLogReopen(ctx context.Context, generation *wafReloadGeneration, base string, active []plannedSiteLog) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		current := make([]os.FileInfo, len(active))
		prior := make([]os.FileInfo, len(active))
		ready := true
		for i, item := range active {
			prior[i] = item.info
			archive, err := os.Lstat(filepath.Join(base, item.target))
			if err != nil || privateLogEntry(archive) != nil || !os.SameFile(archive, item.info) {
				return errors.New("Nginx 轮转归档身份变化；保留且停止清理")
			}
			info, err := os.Lstat(filepath.Join(base, item.name))
			if errors.Is(err, os.ErrNotExist) {
				ready = false
				continue
			}
			if err != nil || privateLogEntry(info) != nil {
				return errors.New("Nginx 新活动日志归属或权限不可核实")
			}
			if os.SameFile(info, item.info) {
				ready = false
				continue
			}
			current[i] = info
		}
		if ready {
			latest, err := captureWAFReloadGeneration(bounded, generation.ProcRoot, generation.Binary, generation.Master.PID)
			if err != nil || latest.Master.Start != generation.Master.Start {
				return errors.New("Nginx 主进程在重开核实期间变化")
			}
			budget := 524288
			oldOpen, opened, err := siteLogProcessFiles(bounded, generation.ProcRoot, generation.Master, generation.Binary, prior, current, &budget)
			if err != nil {
				return err
			}
			ready = !oldOpen
			for _, found := range opened {
				ready = ready && found
			}
			seen := map[wafReloadProcess]bool{}
			for _, process := range append(append([]wafReloadProcess{}, generation.Workers...), latest.Workers...) {
				if seen[process] {
					continue
				}
				seen[process] = true
				oldOpen, _, err = siteLogProcessFiles(bounded, generation.ProcRoot, process, generation.Binary, prior, current, &budget)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					return err
				}
				ready = ready && !oldOpen
			}
			if ready {
				return bounded.Err()
			}
		}
		select {
		case <-bounded.Done():
			return errors.New("Nginx 未在 5 秒内证实关闭旧日志并打开新日志；不继续删除过期文件")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Inspect kernel file identities, not string paths: renamed/open files retain
// their inode. Do not mistake the existence of new names for writer recovery.
func siteLogProcessFiles(ctx context.Context, proc string, process wafReloadProcess, binary string, old, current []os.FileInfo, budget *int) (bool, []bool, error) {
	opened := make([]bool, len(current))
	before, err := readWAFReloadProcess(proc, process.PID)
	if errors.Is(err, os.ErrNotExist) || err == nil && (before.Start != process.Start || before.State == "Z" || before.State == "X") {
		return false, opened, os.ErrNotExist
	}
	if err != nil || before.Parent != process.Parent {
		return false, opened, errors.New("Nginx 写入进程身份变化")
	}
	base := filepath.Join(proc, strconv.Itoa(process.PID))
	actual, err := os.Readlink(filepath.Join(base, "exe"))
	if err != nil || actual != binary {
		return false, opened, errors.New("Nginx 写入程序身份变化")
	}
	dir, err := os.Open(filepath.Join(base, "fd"))
	if err != nil {
		return false, opened, err
	}
	entries, err := dir.ReadDir(65537)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 65536 {
		return false, opened, errors.New("Nginx 文件描述符不可核实或超过预算")
	}
	*budget -= len(entries)
	if *budget < 0 {
		return false, opened, errors.New("Nginx 全进程描述符超过核实预算")
	}
	oldOpen := false
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return false, opened, err
		}
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			return false, opened, errors.New("Nginx 描述符名称无效")
		}
		info, err := os.Stat(filepath.Join(base, "fd", entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, opened, err
		}
		for _, prior := range old {
			if os.SameFile(info, prior) {
				oldOpen = true
			}
		}
		for i, next := range current {
			if os.SameFile(info, next) {
				opened[i] = true
			}
		}
	}
	after, err := readWAFReloadProcess(proc, process.PID)
	if err != nil || after.Start != process.Start || after.Parent != process.Parent {
		return false, opened, errors.New("Nginx 写入身份在核实期间变化")
	}
	return oldOpen, opened, nil
}
