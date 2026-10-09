//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func threatIDSRotationBinding(p *threatIDSRotationPending, in threatIDSConfig, account threatIDSAccount, unit threatIDSUnitRecord, runtimeSHA string) error {
	if p == nil || p.Revision != in.Revision || p.RuntimeSHA != runtimeSHA || p.UnitSHA != unit.UnitSHA || p.UID != account.UID || p.GID != account.GID {
		return errors.New("IDS 待轮转源或配置已改变；保留证据")
	}
	return nil
}

// This gate is shared by the API and the fixed root ExecStartPre. Starting
// through systemctl directly must not bypass an interrupted output journal.
func (s *Service) threatIDSStartOutputReady() error {
	v, err := s.readThreatIDSRotation()
	if err != nil {
		return err
	}
	if v.Pending != nil || v.Retiring != nil {
		return errors.New("IDS 输出轮转或保留仍待恢复；拒绝启动采集")
	}
	return nil
}

func (s *Service) threatIDSRotationHistory(v threatIDSRotation) (string, error) {
	dir, err := s.threatIDSHistoryDirectory(false)
	if err != nil {
		return "", err
	}
	allowed := map[string]bool{}
	for _, entry := range v.Archives {
		if _, err := s.threatIDSArchiveFile(entry); err != nil {
			return "", err
		}
		allowed["eve-"+entry.ID+".json"] = true
	}
	if v.Pending != nil {
		allowed["eve-"+v.Pending.ID+".json"] = true
	}
	f, err := os.Open(dir)
	if err != nil {
		return "", err
	}
	defer f.Close()
	entries, err := f.ReadDir(threatIDSHistoryLimit + 2)
	if err != nil && err != io.EOF || len(entries) > threatIDSHistoryLimit+1 {
		return "", errors.New("IDS 归档容量或目录状态异常；不清理未知文件")
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || !entry.Type().IsRegular() {
			return "", errors.New("IDS 归档包含未知文件；保留且拒绝接管")
		}
	}
	return dir, nil
}

// A renamed archive is inside a root-only directory, so the capture account
// cannot reopen it. Before cold sealing, refuse any retained descriptor in ANY
// process owned by that account, not just the now-inactive MainPID. Enumerate
// twice, with fixed process/FD budgets; unknown/denied observations fail closed.
func (s *Service) threatIDSArchiveDetached(ctx context.Context, old os.FileInfo, account threatIDSAccount) error {
	for range 2 {
		proc, err := os.Open(s.systemPath("/proc"))
		if err != nil {
			return err
		}
		entries, err := proc.ReadDir(4097)
		proc.Close()
		if err != nil && err != io.EOF || len(entries) > 4096 {
			return errors.New("IDS 停止后的账户进程集合无法有界核对")
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid < 2 || strconv.Itoa(pid) != entry.Name() {
				continue
			}
			base := filepath.Join(s.systemPath("/proc"), entry.Name())
			info, err := os.Lstat(base)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil || !info.IsDir() {
				return errors.New("IDS 停止后的进程身份读取异常")
			}
			if err := threatIDSDetachedProc(ctx, base, old, account); err != nil {
				return err
			}
		}
	}
	return nil
}

// Pin the proc directory, then resolve status/fd relative to that descriptor.
// An exit/reused numerical PID cannot redirect this check to a new process.
func threatIDSDetachedProc(ctx context.Context, base string, old os.FileInfo, account threatIDSAccount) error {
	fd, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return errors.New("IDS 停止后的进程目录不可固定")
	}
	defer unix.Close(fd)
	statusFD, err := unix.Openat(fd, "status", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return errors.New("IDS 停止后的内核账户信息不可读取")
	}
	statusFile := os.NewFile(uintptr(statusFD), "private-proc-status")
	status, readErr := io.ReadAll(io.LimitReader(statusFile, 64<<10+1))
	statusFile.Close()
	if readErr != nil || ctx.Err() != nil {
		return errors.New("IDS 停止后的内核账户读取未完成")
	}
	matching, err := threatIDSProcAccount(status, account.UID)
	if err != nil || !matching {
		return err
	}
	fdNumber, err := unix.Openat(fd, "fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return errors.New("IDS 账户进程句柄不可核对；未封存")
	}
	fds := os.NewFile(uintptr(fdNumber), "private-proc-fd")
	defer fds.Close()
	files, readErr := fds.ReadDir(257)
	if readErr != nil && readErr != io.EOF || len(files) > 256 {
		return errors.New("IDS 账户进程句柄超过冷恢复核对预算")
	}
	wanted := old.Sys().(*syscall.Stat_t)
	for _, file := range files {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var actual unix.Stat_t
		err := unix.Fstatat(fdNumber, file.Name(), &actual, 0)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil || uint64(actual.Dev) == uint64(wanted.Dev) && actual.Ino == wanted.Ino {
			return errors.New("IDS 已停止但归档仍被账户进程持有或句柄未知；未封存")
		}
	}
	return nil
}

// Caller holds the module lock and has verified immutable source/configuration.
// Never start/stop/enable a unit here. Before-rename interruption merely cancels
// the owned intent; after-rename interruption seals the exact recorded inode.
func (s *Service) recoverThreatIDSStoppedRotation(ctx context.Context, v threatIDSRotation, account threatIDSAccount) (threatIDSRotation, error) {
	if err := validateThreatIDSRotation(v); err != nil {
		return v, err
	}
	if err := validateThreatIDSAccount(account); err != nil {
		return v, err
	}
	state, err := s.moduleCommand(ctx, 3*time.Second, "/usr/bin/systemctl", "show", threatIDSService, "--property=ActiveState,MainPID")
	if err != nil || !threatIDSStoppedUnit(state, false) {
		return v, errors.New("IDS 冷恢复要求采集明确停止且 MainPID=0；未自动停止或启动")
	}
	v, err = s.retireThreatIDSArchiveContext(ctx, v)
	if err != nil || v.Pending == nil {
		return v, err
	}
	p := v.Pending
	if p.UID != account.UID || p.GID != account.GID {
		return v, errors.New("IDS 冷恢复账户与待轮转来源不符")
	}
	dir, err := s.threatIDSRotationHistory(v)
	if err != nil {
		return v, err
	}
	live := s.systemPath("/var/lib/panel-network-ids/logs/eve.json")
	archive := filepath.Join(dir, "eve-"+p.ID+".json")
	old, err := os.Lstat(archive)
	if os.IsNotExist(err) {
		if p.Sealed != nil {
			return v, errors.New("IDS 已记录封存的归档缺失；不当作未开始轮转")
		}
		info, err := threatIDSOutputInfo(live, account)
		if err != nil {
			return v, err
		}
		st := info.Sys().(*syscall.Stat_t)
		if uint64(st.Dev) != p.Device || st.Ino != p.Inode || ctx.Err() != nil {
			return v, errors.New("IDS 未改名的原始日志已变化；未撤销轮转意图")
		}
		v.Pending = nil
		return v, s.writeThreatIDSRotation(v)
	}
	if err != nil {
		return v, err
	}
	if info, err := threatIDSOutputInfo(live, account); err == nil {
		if os.SameFile(info, old) {
			return v, errors.New("IDS 冷恢复活动日志与归档不是独立文件")
		}
	} else if !os.IsNotExist(err) {
		return v, err
	}
	if err := s.threatIDSArchiveDetached(ctx, old, account); err != nil {
		return v, err
	}
	sealed, err := threatIDSSealArchive(ctx, archive, p, account, func() error { return s.writeThreatIDSRotation(v) })
	if err != nil {
		return v, err
	}
	if _, err := s.threatIDSArchiveFile(sealed); err != nil {
		return v, err
	}
	v.Archives = append(v.Archives, sealed)
	v.Pending = nil
	if err := s.writeThreatIDSRotation(v); err != nil {
		return v, err
	}
	return s.retireThreatIDSArchiveContext(ctx, v)
}

func (s *Service) recoverThreatIDSOutputLocked(ctx context.Context, expectedRevision int64) (threatIDSRotation, error) {
	v, err := s.readThreatIDSRotation()
	if err != nil {
		return v, err
	}
	_, account, unit, err := s.threatIDSImmutable(ctx)
	if err != nil {
		return v, err
	}
	in, err := s.threatIDSConfig()
	if err != nil || expectedRevision < 1 || in.Revision != expectedRevision {
		return v, errors.New("IDS 输出恢复修订冲突；未改变日志或运行选择")
	}
	if err := s.threatIDSNativeConfig(in); err != nil {
		return v, err
	}
	if v.Pending != nil {
		digest, err := nfsFileDigest(filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json"), 32<<10)
		if err != nil {
			return v, err
		}
		if err := threatIDSRotationBinding(v.Pending, in, account, unit, digest); err != nil {
			return v, err
		}
	}
	return s.recoverThreatIDSStoppedRotation(ctx, v, account)
}
