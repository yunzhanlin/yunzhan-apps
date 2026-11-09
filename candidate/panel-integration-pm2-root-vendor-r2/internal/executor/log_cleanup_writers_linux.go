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
	"syscall"
	"time"
)

type siteLogInode struct{ Device, Inode uint64 }

func siteLogWriterStart(proc string, pid int) (uint64, error) {
	data, e := readModuleProcFile(filepath.Join(proc, strconv.Itoa(pid), "stat"), 8192)
	if e != nil {
		return 0, e
	}
	if !strings.HasPrefix(string(data), strconv.Itoa(pid)+" (") {
		return 0, errors.New("日志写入进程身份无效")
	}
	info, e := parseProcStat(pid, string(data), uint64(os.Getpagesize()))
	if e != nil {
		return 0, errors.New("日志写入进程启动身份不可核实")
	}
	return info.StartTime, nil
}

func siteLogExpiredOpenWriters(ctx context.Context, proc string, expired []plannedSiteLog) error {
	if len(expired) == 0 {
		return ctx.Err()
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	inodes := map[siteLogInode]bool{}
	for _, item := range expired {
		stat, ok := item.info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("过期日志内核身份不可核实")
		}
		inodes[siteLogInode{uint64(stat.Dev), stat.Ino}] = true
	}
	dir, e := os.Open(proc)
	if e != nil {
		return e
	}
	entries, e := dir.ReadDir(16385)
	dir.Close()
	if e != nil && !errors.Is(e, io.EOF) || len(entries) > 16384 {
		return errors.New("进程目录不可核实或超过日志核实预算")
	}
	processes, budget := 0, 524288
	for _, entry := range entries {
		if e = bounded.Err(); e != nil {
			return e
		}
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid < 1 || strconv.Itoa(pid) != entry.Name() {
			continue
		}
		processes++
		if processes > 8192 {
			return errors.New("日志写入核实超过 8192 个进程；未开始删除")
		}
		start, e := siteLogWriterStart(proc, pid)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if e = siteLogProcessExpiredWriter(bounded, proc, pid, inodes, &budget); errors.Is(e, os.ErrNotExist) {
			continue
		} else if e != nil {
			return e
		}
		after, e := siteLogWriterStart(proc, pid)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || after != start {
			return errors.New("日志写入进程在核实期间变化；不删除归档")
		}
	}
	return bounded.Err()
}

func siteLogProcessExpiredWriter(ctx context.Context, proc string, pid int, inodes map[siteLogInode]bool, budget *int) error {
	base := filepath.Join(proc, strconv.Itoa(pid))
	dir, e := os.Open(filepath.Join(base, "fd"))
	if e != nil {
		return e
	}
	entries, e := dir.ReadDir(65537)
	dir.Close()
	if e != nil && !errors.Is(e, io.EOF) || len(entries) > 65536 {
		return errors.New("进程描述符目录不可核实或超过预算")
	}
	*budget -= len(entries)
	if *budget < 0 {
		return errors.New("日志写入核实超过 524288 个描述符；不删除归档")
	}
	for _, entry := range entries {
		if e = ctx.Err(); e != nil {
			return e
		}
		if _, e = strconv.ParseUint(entry.Name(), 10, 32); e != nil {
			return errors.New("描述符标识不可核实")
		}
		info, e := os.Stat(filepath.Join(base, "fd", entry.Name()))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ok || !inodes[siteLogInode{uint64(stat.Dev), stat.Ino}] {
			continue
		}
		data, e := readModuleProcFile(filepath.Join(base, "fdinfo", entry.Name()), 4096)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		flags, seen := "", false
		for _, line := range strings.Split(string(data), "\n") {
			key, value, found := strings.Cut(line, ":")
			if found && key == "flags" {
				if seen {
					return errors.New("日志描述符标志重复；不删除归档")
				}
				flags = strings.TrimSpace(value)
				seen = true
			}
		}
		mode, e := strconv.ParseUint(flags, 8, 64)
		if e != nil || !seen || mode&unix.O_ACCMODE == unix.O_ACCMODE {
			return errors.New("日志描述符写入模式不可核实；不删除归档")
		}
		if mode&unix.O_ACCMODE != unix.O_RDONLY {
			return errors.New("过期日志仍被进程以写入模式打开；保留归档并停止清理")
		}
	}
	return nil
}
