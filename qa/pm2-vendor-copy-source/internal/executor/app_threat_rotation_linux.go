//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"local/panel/internal/core"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const threatIDSHistoryLimit = 4
const threatIDSRotationThreshold = 1 << 20

type threatIDSArchive struct {
	ID     string `json:"id"`
	At     string `json:"at"`
	SHA    string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}
type threatIDSRotationPending struct {
	ID         string            `json:"id"`
	At         string            `json:"at"`
	Device     uint64            `json:"device"`
	Inode      uint64            `json:"inode"`
	UID        uint32            `json:"uid"`
	GID        uint32            `json:"gid"`
	Revision   int64             `json:"revision"`
	RuntimeSHA string            `json:"runtime_sha256"`
	UnitSHA    string            `json:"unit_sha256"`
	Sealed     *threatIDSArchive `json:"sealed,omitempty"`
}
type threatIDSRotation struct {
	Format           int                       `json:"format"`
	Archives         []threatIDSArchive        `json:"archives"`
	Pending          *threatIDSRotationPending `json:"pending,omitempty"`
	Retiring         *threatIDSArchive         `json:"retiring,omitempty"`
	Retired          []threatIDSArchive        `json:"retired"`
	RetirementUnlink bool                      `json:"retirement_unlink,omitempty"`
}

func validateThreatIDSRotation(v threatIDSRotation) error {
	if v.Format != 1 || v.Archives == nil || v.Retired == nil || len(v.Archives) > threatIDSHistoryLimit+1 || len(v.Retired) > 8 || v.Pending != nil && v.Retiring != nil {
		return errors.New("IDS 轮转记录结构或容量异常")
	}
	seen := map[string]bool{}
	valid := validThreatIDSArchive
	for _, entry := range append(append([]threatIDSArchive{}, v.Archives...), v.Retired...) {
		if !valid(entry) || seen[entry.ID] {
			return errors.New("IDS 轮转归档身份、摘要或大小无效")
		}
		seen[entry.ID] = true
	}
	if v.Retiring != nil {
		if !valid(*v.Retiring) || len(v.Archives) != threatIDSHistoryLimit+1 || v.Archives[0] != *v.Retiring {
			return errors.New("IDS 退休集合不是已核对最早归档")
		}
	}
	if v.RetirementUnlink && v.Retiring == nil {
		return errors.New("IDS 归档移除阶段缺少精确退役集合")
	}
	if v.Pending != nil {
		p := v.Pending
		if !core.ValidID(p.ID) || seen[p.ID] || !validWAFRotationTime(p.At) || p.Device == 0 || p.Inode == 0 || validateThreatIDSAccount(threatIDSAccount{Format: 1, UID: p.UID, GID: p.GID}) != nil || p.Revision < 1 || p.Revision >= 1<<60 || !threatPackageSHA.MatchString(p.RuntimeSHA) || !threatPackageSHA.MatchString(p.UnitSHA) || len(v.Archives) > threatIDSHistoryLimit {
			return errors.New("IDS 待轮转记录来源或范围无效")
		}
		if p.Sealed != nil && (!valid(*p.Sealed) || p.Sealed.ID != p.ID || p.Sealed.At != p.At || p.Sealed.Device != p.Device || p.Sealed.Inode != p.Inode) {
			return errors.New("IDS 待提交封存摘要与原始轮转身份不符")
		}
	}
	return nil
}

func validThreatIDSArchive(entry threatIDSArchive) bool {
	return core.ValidID(entry.ID) && validWAFRotationTime(entry.At) && threatPackageSHA.MatchString(entry.SHA) && entry.Bytes > 0 && entry.Bytes <= threatEVEByteLimit && entry.Device > 0 && entry.Inode > 0
}
func (s *Service) threatIDSRotationPath() string {
	return filepath.Join(s.moduleDir("network-threat-detection"), "output-rotation.json")
}
func (s *Service) readThreatIDSRotation() (threatIDSRotation, error) {
	v := threatIDSRotation{Format: 1, Archives: []threatIDSArchive{}, Retired: []threatIDSArchive{}}
	b, err := ftpPrivateRead(s.threatIDSRotationPath(), 16<<10)
	if os.IsNotExist(err) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	if decodeThreatIDSPrivateJSON(b, &v) != nil {
		return v, errors.New("IDS 轮转记录不可解析；保留且拒绝覆盖")
	}
	return v, validateThreatIDSRotation(v)
}
func (s *Service) writeThreatIDSRotation(v threatIDSRotation) error {
	if err := validateThreatIDSRotation(v); err != nil {
		return err
	}
	if _, err := s.readThreatIDSRotation(); err != nil {
		return err
	}
	return moduleWrite(s.threatIDSRotationPath(), v)
}
func (s *Service) threatIDSHistoryDirectory(create bool) (string, error) {
	parent := s.systemPath("/var/lib/panel-network-ids")
	if err := threatIDSTrustedParents(parent, false); err != nil {
		return "", err
	}
	path := filepath.Join(parent, "history")
	if create {
		if err := os.Mkdir(path, 0700); err == nil {
			// The executor's primary group is panel, not root. Only the
			// directory actually created here is made root-private; an
			// existing foreign directory is never adopted or repaired.
			if err := os.Chown(path, 0, 0); err != nil {
				return "", err
			}
			if err := os.Chmod(path, 0700); err != nil {
				return "", err
			}
			if err := wafBodyLogSyncDirectory(parent); err != nil {
				return "", err
			}
		} else if !os.IsExist(err) {
			return "", err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || stat.Uid != 0 || stat.Gid != 0 {
		return "", errors.New("IDS 归档目录不是固定 root 私有目录；未修复")
	}
	return path, nil
}
func (s *Service) threatIDSArchiveFile(entry threatIDSArchive) (string, error) {
	if !validThreatIDSArchive(entry) {
		return "", errors.New("IDS 归档身份或路径不是封闭受管记录")
	}
	dir, err := s.threatIDSHistoryDirectory(false)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "eve-"+entry.ID+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return path, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 || uint64(st.Dev) != entry.Device || st.Ino != entry.Inode || info.Size() != entry.Bytes {
		return path, errors.New("IDS 已封存归档身份或模式被外部改变")
	}
	digest, err := nfsFileDigest(path, threatEVEByteLimit)
	if err != nil || digest != entry.SHA {
		return path, errors.New("IDS 已封存归档完整摘要不符；未删除")
	}
	return path, nil
}

// Only the oldest sealed, root-owned, fully matched archive may be retired.
// Persist intent before unlink and preserve eight digest-only tombstones. A
// foreign edit or unknown missing archive cannot be treated as successful.
func (s *Service) retireThreatIDSArchive(v threatIDSRotation) (threatIDSRotation, error) {
	return s.retireThreatIDSArchiveContext(context.Background(), v)
}

// Rename the verified oldest archive into an exclusive private retirement
// slot, verify that actual inode again, and durably authorize unlink BEFORE
// removal. A missing file without this second phase cannot become a tombstone.
func (s *Service) retireThreatIDSArchiveContext(ctx context.Context, v threatIDSRotation) (threatIDSRotation, error) {
	if err := validateThreatIDSRotation(v); err != nil {
		return v, err
	}
	if v.Retiring == nil && len(v.Archives) <= threatIDSHistoryLimit {
		return v, nil
	}
	dir, err := s.threatIDSHistoryDirectory(false)
	if err != nil {
		return v, err
	}
	entry := v.Archives[0]
	path := filepath.Join(dir, "eve-"+entry.ID+".json")
	staged := filepath.Join(dir, "retiring-eve-"+entry.ID+".json")
	allowed := map[string]bool{}
	for i, other := range v.Archives {
		allowed["eve-"+other.ID+".json"] = true
		if i > 0 {
			if _, err := s.readThreatIDSArchiveSnapshot(ctx, other); err != nil {
				return v, err
			}
		}
	}
	if v.Retiring != nil {
		allowed[filepath.Base(staged)] = true
	}
	f, err := os.Open(dir)
	if err != nil {
		return v, err
	}
	files, readErr := f.ReadDir(threatIDSHistoryLimit + 2)
	f.Close()
	if readErr != nil && readErr != io.EOF || len(files) > threatIDSHistoryLimit+1 {
		return v, errors.New("IDS 退役目录容量或读取异常；未移除")
	}
	for _, file := range files {
		if !allowed[file.Name()] || !file.Type().IsRegular() {
			return v, errors.New("IDS 退役集合包含未知文件；保留")
		}
	}
	if v.Retiring == nil && len(v.Archives) > threatIDSHistoryLimit {
		if _, err := readThreatIDSPrivateArchiveFile(ctx, entry, path); err != nil {
			return v, err
		}
		v.Retiring = &entry
		if err := s.writeThreatIDSRotation(v); err != nil {
			return v, err
		}
	}
	_, sourceErr := os.Lstat(path)
	_, stagedErr := os.Lstat(staged)
	if sourceErr != nil && !os.IsNotExist(sourceErr) || stagedErr != nil && !os.IsNotExist(stagedErr) {
		return v, errors.New("IDS 退役路径身份读取异常")
	}
	if sourceErr == nil {
		if stagedErr == nil || v.RetirementUnlink {
			return v, errors.New("IDS 退役槽冲突或已移除阶段又出现原文件；未覆盖")
		}
		if _, err := readThreatIDSPrivateArchiveFile(ctx, entry, path); err != nil {
			return v, err
		}
		if err := unix.Renameat2(unix.AT_FDCWD, path, unix.AT_FDCWD, staged, unix.RENAME_NOREPLACE); err != nil {
			return v, err
		}
		if err := wafBodyLogSyncDirectory(dir); err != nil {
			return v, err
		}
		stagedErr = nil
	}
	if stagedErr == nil {
		if _, err := readThreatIDSPrivateArchiveFile(ctx, entry, staged); err != nil {
			return v, err
		}
		if !v.RetirementUnlink {
			v.RetirementUnlink = true
			if err := s.writeThreatIDSRotation(v); err != nil {
				return v, err
			}
		}
		if ctx.Err() != nil {
			return v, ctx.Err()
		}
		if err := os.Remove(staged); err != nil {
			return v, err
		}
		if err := wafBodyLogSyncDirectory(dir); err != nil {
			return v, err
		}
	} else if !v.RetirementUnlink {
		return v, errors.New("IDS 归档缺失但没有已核对退役槽的移除意图；未宣称退役成功")
	}
	v.Archives = append([]threatIDSArchive{}, v.Archives[1:]...)
	v.Retired = append(v.Retired, entry)
	if len(v.Retired) > 8 {
		v.Retired = append([]threatIDSArchive{}, v.Retired[len(v.Retired)-8:]...)
	}
	v.Retiring = nil
	v.RetirementUnlink = false
	return v, s.writeThreatIDSRotation(v)
}

func (s *Service) threatIDSPinProcess(ctx context.Context, runtime threatIDSRuntime, account threatIDSAccount, in threatIDSConfig) (int, int, uint64, error) {
	verified, _, err := s.threatIDSProcess(ctx, runtime, in, account)
	if err != nil || !verified {
		return -1, 0, 0, errors.New("IDS 轮转需要已核对的实际采集进程")
	}
	text, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", threatIDSService, "--property=MainPID", "--value")
	pid, parseErr := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || parseErr != nil || pid < 2 {
		return -1, 0, 0, errors.New("IDS 轮转主进程身份未知")
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return -1, 0, 0, errors.New("内核不支持固定 IDS 进程句柄；不退回不安全 PID 信号")
	}
	start, err := moduleProcessStart(s.systemPath("/proc"), pid)
	if err != nil {
		unix.Close(fd)
		return -1, 0, 0, err
	}
	verified, _, err = s.threatIDSProcessExpected(ctx, runtime, in, account, pid)
	actual, exeErr := os.Stat(filepath.Join(s.systemPath("/proc"), strconv.Itoa(pid), "exe"))
	wanted, statErr := os.Stat(runtime.Binary)
	second, secondErr := moduleProcessStart(s.systemPath("/proc"), pid)
	if err != nil || !verified || exeErr != nil || statErr != nil || !os.SameFile(actual, wanted) || secondErr != nil || second != start {
		unix.Close(fd)
		return -1, 0, 0, errors.New("IDS 轮转固定身份期间进程已改变")
	}
	return fd, pid, start, nil
}

func threatIDSOutputInfo(path string, account threatIDSAccount) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 0 || info.Size() > threatEVEByteLimit || st.Uid != account.UID || st.Gid != account.GID || st.Nlink != 1 {
		return nil, errors.New("IDS 活动或待封存日志归属、模式或大小异常")
	}
	return info, nil
}

func (s *Service) threatIDSReopen(ctx context.Context, fd, pid int, start uint64, old os.FileInfo, live string, account threatIDSAccount) error {
	current, err := moduleProcessStart(s.systemPath("/proc"), pid)
	if err != nil || current != start || ctx.Err() != nil {
		return errors.New("IDS 已退出或 PID 复用；未发送轮转信号")
	}
	actualPID, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", threatIDSService, "--property=MainPID", "--value")
	if err != nil || strings.TrimSpace(actualPID) != strconv.Itoa(pid) {
		return errors.New("IDS 主进程已改变；未向旧进程发送轮转信号")
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGHUP, nil, 0); err != nil {
		return err
	}
	child, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	for {
		info, err := threatIDSOutputInfo(live, account)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && !os.SameFile(info, old) {
			current, err := moduleProcessStart(s.systemPath("/proc"), pid)
			if err != nil || current != start {
				return errors.New("IDS 重开日志期间退出")
			}
			fds, err := os.ReadDir(filepath.Join(s.systemPath("/proc"), strconv.Itoa(pid), "fd"))
			if err != nil || len(fds) > 256 {
				return errors.New("IDS 文件句柄无法有界核对")
			}
			oldHeld, newHeld := false, false
			for _, item := range fds {
				actual, err := os.Stat(filepath.Join(s.systemPath("/proc"), strconv.Itoa(pid), "fd", item.Name()))
				if err != nil {
					continue
				}
				oldHeld = oldHeld || os.SameFile(actual, old)
				newHeld = newHeld || os.SameFile(actual, info)
			}
			if !oldHeld && newHeld {
				return nil
			}
		}
		select {
		case <-child.Done():
			return errors.New("IDS 未核对到新日志句柄和旧句柄关闭；保留待轮转证据")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Snapshot a closed archive through a no-follow descriptor, and persist its
// full digest BEFORE changing ownership. Interrupted sealing never adopts an
// unknown root-owned inode or recomputes a new digest for changed evidence.
func threatIDSSealArchive(ctx context.Context, path string, p *threatIDSRotationPending, account threatIDSAccount, persist func() error) (threatIDSArchive, error) {
	var empty threatIDSArchive
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return empty, err
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	rootOwned := ok && st.Uid == 0 && st.Gid == 0
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() < 1 || before.Size() > threatEVEByteLimit || st.Nlink != 1 || uint64(st.Dev) != p.Device || st.Ino != p.Inode || rootOwned && p.Sealed == nil || !rootOwned && (st.Uid != account.UID || st.Gid != account.GID) {
		return empty, errors.New("IDS 封存文件身份或已记录阶段不符；没有接管")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, threatEVEByteLimit+1))
	if err != nil || n != before.Size() || ctx.Err() != nil {
		return empty, errors.New("IDS 封存完整摘要读取未完成")
	}
	after, err := f.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(before, current) || current.Mode()&os.ModeSymlink != 0 || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return empty, errors.New("IDS 已关闭的归档在封存期间被改变；未改权限")
	}
	entry := threatIDSArchive{ID: p.ID, At: p.At, SHA: hex.EncodeToString(h.Sum(nil)), Bytes: n, Device: p.Device, Inode: p.Inode}
	if p.Sealed != nil && *p.Sealed != entry {
		return empty, errors.New("IDS 先前封存摘要或大小被外部改变；未重新认证")
	}
	if p.Sealed == nil {
		p.Sealed = &entry
		if err := persist(); err != nil {
			return empty, err
		}
	}
	if !rootOwned {
		if err := f.Chown(0, 0); err != nil {
			return empty, err
		}
		if err := f.Sync(); err != nil {
			return empty, err
		}
	}
	return entry, nil
}

func (s *Service) rotateThreatIDSLocked(ctx context.Context) (threatIDSRotation, error) {
	return s.rotateThreatIDSLockedChoice(ctx, false)
}

func (s *Service) rotateThreatIDSLockedChoice(ctx context.Context, explicit bool) (threatIDSRotation, error) {
	v, err := s.readThreatIDSRotation()
	if err != nil {
		return v, err
	}
	if _, err := os.Lstat(s.wafPendingPath()); !os.IsNotExist(err) {
		return v, errors.New("IDS 配置待恢复；轮转不改变恢复集合")
	}
	runtime, account, unit, err := s.threatIDSImmutable(ctx)
	if err != nil {
		return v, err
	}
	in, err := s.threatIDSConfig()
	if err != nil {
		return v, err
	}
	if err := s.threatIDSNativeConfig(in); err != nil {
		return v, err
	}
	// Refuse stopped/unknown engines before creating history, writing an
	// intent, or retiring an archive. A failed manual request is not itself a
	// new interrupted rotation; cold recovery is a separate explicit action.
	fd, pid, start, err := s.threatIDSPinProcess(ctx, runtime, account, in)
	if err != nil {
		return v, err
	}
	defer unix.Close(fd)
	v, err = s.retireThreatIDSArchiveContext(ctx, v)
	if err != nil {
		return v, err
	}
	if err := s.prepareThreatIDSLogs(account); err != nil {
		return v, err
	}
	dir, err := s.threatIDSHistoryDirectory(true)
	if err != nil {
		return v, err
	}
	if _, err := s.threatIDSRotationHistory(v); err != nil {
		return v, err
	}
	live := s.systemPath("/var/lib/panel-network-ids/logs/eve.json")
	if v.Pending == nil {
		info, err := threatIDSOutputInfo(live, account)
		if err != nil {
			return v, err
		}
		if info.Size() < threatIDSRotationThreshold && !explicit || info.Size() == 0 {
			return v, nil
		}
		st := info.Sys().(*syscall.Stat_t)
		digest, err := nfsFileDigest(filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json"), 32<<10)
		if err != nil {
			return v, err
		}
		v.Pending = &threatIDSRotationPending{ID: core.ID(), At: core.Now(), Device: uint64(st.Dev), Inode: st.Ino, UID: account.UID, GID: account.GID, Revision: in.Revision, RuntimeSHA: digest, UnitSHA: unit.UnitSHA}
		if err := s.writeThreatIDSRotation(v); err != nil {
			return v, err
		}
	}
	p := v.Pending
	digest, err := nfsFileDigest(filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json"), 32<<10)
	if err != nil {
		return v, err
	}
	if err := threatIDSRotationBinding(p, in, account, unit, digest); err != nil {
		return v, err
	}
	archive := filepath.Join(dir, "eve-"+p.ID+".json")
	old, err := os.Lstat(archive)
	if os.IsNotExist(err) {
		old, err = threatIDSOutputInfo(live, account)
		if err != nil {
			return v, err
		}
		st := old.Sys().(*syscall.Stat_t)
		if uint64(st.Dev) != p.Device || st.Ino != p.Inode {
			return v, errors.New("IDS 待轮转活动 inode 已变化；没有替换")
		}
		if err := unix.Renameat2(unix.AT_FDCWD, live, unix.AT_FDCWD, archive, unix.RENAME_NOREPLACE); err != nil {
			return v, err
		}
		if err := wafBodyLogSyncDirectory(filepath.Dir(live)); err != nil {
			return v, err
		}
		if err := wafBodyLogSyncDirectory(dir); err != nil {
			return v, err
		}
	} else if err != nil {
		return v, err
	}
	st, ok := old.Sys().(*syscall.Stat_t)
	// An interrupted seal is accepted only against its durable full digest.
	sealed := ok && st.Uid == 0 && st.Gid == 0
	if !ok || !old.Mode().IsRegular() || old.Mode().Perm() != 0600 || st.Nlink != 1 || uint64(st.Dev) != p.Device || st.Ino != p.Inode || old.Size() < 1 || old.Size() > threatEVEByteLimit || sealed && p.Sealed == nil || !sealed && (st.Uid != account.UID || st.Gid != account.GID) {
		return v, errors.New("IDS 待封存归档身份被外部改变")
	}
	if err := s.threatIDSReopen(ctx, fd, pid, start, old, live, account); err != nil {
		return v, err
	}
	entry, err := threatIDSSealArchive(ctx, archive, p, account, func() error { return s.writeThreatIDSRotation(v) })
	if err != nil {
		return v, err
	}
	if _, err := s.threatIDSArchiveFile(entry); err != nil {
		return v, err
	}
	v.Archives = append(v.Archives, entry)
	v.Pending = nil
	if err := s.writeThreatIDSRotation(v); err != nil {
		return v, err
	}
	return s.retireThreatIDSArchiveContext(ctx, v)
}

func (s *Service) runThreatIDSRotationWorker(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var warnings threatIDSRotationWarningBudget
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !s.moduleInstalled("network-threat-detection") {
			continue
		}
		info, err := os.Lstat(s.systemPath("/var/lib/panel-network-ids/logs/eve.json"))
		pending, recordErr := s.readThreatIDSRotation()
		if recordErr == nil && pending.Pending == nil && pending.Retiring == nil && (os.IsNotExist(err) || err == nil && info.Size() < threatIDSRotationThreshold) {
			continue
		}
		svc := s.threatIDSTransactionService()
		lock, err := svc.lockWAFConfiguration()
		if errors.Is(err, errWAFConfigurationBusy) {
			continue
		}
		if err == nil {
			cycle, cancel := context.WithTimeout(ctx, 15*time.Second)
			state, stateErr := svc.moduleCommand(cycle, 3*time.Second, "/usr/bin/systemctl", "show", threatIDSService, "--property=ActiveState,MainPID")
			if stateErr != nil {
				err = errors.New("IDS 轮转服务状态不可读取；未改变输出")
			} else if !threatIDSStoppedUnit(state, false) {
				_, err = svc.rotateThreatIDSLocked(cycle)
			}
			cancel()
			lock.Close()
		}
		if err != nil && ctx.Err() == nil {
			if emit, count := warnings.deferCycle(time.Now()); emit {
				log.Printf("IDS private output rotation deferred; cycles=%d; no success claimed: %.512s", count, fmt.Sprint(err))
			}
		}
	}
}
