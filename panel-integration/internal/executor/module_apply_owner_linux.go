//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// A candidate daemon can start before commit only while the actual executor
// still owns the transaction lock. PID alone is insufficient after a crash.
type moduleApplyOwner struct {
	PID       int    `json:"pid"`
	StartTime uint64 `json:"start_time"`
}

func readModuleProcFile(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("事务进程信息不可验证")
	}
	return b, nil
}

func moduleProcessStart(procRoot string, pid int) (uint64, error) {
	if pid <= 1 {
		return 0, errors.New("事务进程身份无效")
	}
	b, e := readModuleProcFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"), 8192)
	if e != nil || !strings.HasPrefix(string(b), strconv.Itoa(pid)+" (") {
		return 0, errors.New("事务进程不存在或已变化")
	}
	p, e := parseProcStat(pid, string(b), uint64(os.Getpagesize()))
	if e != nil || p.StartTime == 0 || p.State == "Z" || p.State == "X" {
		return 0, errors.New("事务进程已退出或身份无效")
	}
	return p.StartTime, nil
}

func currentModuleApplyOwner() (*moduleApplyOwner, error) {
	pid := os.Getpid()
	start, e := moduleProcessStart("/proc", pid)
	if e != nil {
		return nil, e
	}
	return &moduleApplyOwner{PID: pid, StartTime: start}, nil
}

func moduleFlockOwner(data string, pid int, device uint64, inode uint64) bool {
	want := fmt.Sprintf("%x:%x:%d", unix.Major(device), unix.Minor(device), inode)
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 8 || fields[1] != "FLOCK" || fields[2] != "ADVISORY" || fields[3] != "WRITE" || fields[4] != strconv.Itoa(pid) || fields[6] != "0" || fields[7] != "EOF" {
			continue
		}
		// Kernel device fields are zero padded; normalize their numeric values.
		parts := strings.Split(fields[5], ":")
		if len(parts) != 3 {
			continue
		}
		major, e1 := strconv.ParseUint(parts[0], 16, 32)
		minor, e2 := strconv.ParseUint(parts[1], 16, 32)
		ino, e3 := strconv.ParseUint(parts[2], 10, 64)
		if e1 == nil && e2 == nil && e3 == nil && fmt.Sprintf("%x:%x:%d", major, minor, ino) == want {
			return true
		}
	}
	return false
}

func (s *Service) authorizeModuleCandidate(ctx context.Context, lockPath string, owner *moduleApplyOwner) error {
	if owner == nil || owner.PID <= 1 || owner.StartTime == 0 || s.Config.SystemRoot == "/" && os.Geteuid() != 0 {
		return errors.New("未完成事务缺少可信的执行进程，必须先恢复")
	}
	f, e := os.OpenFile(lockPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("事务锁文件身份或权限无效")
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e == nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		return errors.New("事务锁已释放，必须先恢复")
	} else if !errors.Is(e, unix.EWOULDBLOCK) && !errors.Is(e, unix.EAGAIN) {
		return errors.New("事务锁状态不可验证")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	pidText, e := s.Config.Run(checkCtx, "/usr/bin/systemctl", "show", "panel-executor.service", "--property=MainPID", "--value")
	pid, parseErr := strconv.Atoi(strings.TrimSpace(pidText))
	if e != nil || parseErr != nil || pid != owner.PID {
		return errors.New("未完成事务不属于正在运行的面板执行器")
	}
	procRoot := s.systemPath("/proc")
	start, e := moduleProcessStart(procRoot, owner.PID)
	if e != nil || start != owner.StartTime {
		return errors.New("事务进程已退出或 PID 被复用，必须先恢复")
	}
	status, e := readModuleProcFile(filepath.Join(procRoot, strconv.Itoa(owner.PID), "status"), 64<<10)
	if e != nil {
		return e
	}
	uid := strconv.Itoa(os.Geteuid())
	trusted := false
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && fields[0] == "Uid:" && fields[1] == uid && fields[2] == uid && fields[3] == uid && fields[4] == uid {
			trusted = true
		}
	}
	if !trusted {
		return errors.New("事务执行进程权限不可验证")
	}
	locks, e := readModuleProcFile(filepath.Join(procRoot, "locks"), 1<<20)
	if e != nil || !moduleFlockOwner(string(locks), owner.PID, uint64(stat.Dev), stat.Ino) {
		return errors.New("事务锁并非由记录中的执行进程持有")
	}
	return nil
}
