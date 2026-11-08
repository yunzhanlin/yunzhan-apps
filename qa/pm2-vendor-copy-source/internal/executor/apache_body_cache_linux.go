//go:build linux

package executor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const apacheBodyCacheBytes = uint64(128 << 20)
const apacheBodyCacheInodes = uint64(4096)
const apacheBodyCacheReserveBytes = uint64(32 << 20)

type apacheBodyCacheBudget struct {
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
	TotalInodes    uint64 `json:"total_inodes"`
	AvailableNodes uint64 `json:"available_inodes"`
}

// A body inspection limit or a free-disk check is not a hard cache quota.
// Require an actual dedicated bounded tmpfs, with bounded inode consumption,
// through the opened descriptor. tmpfs uses RAM/swap, never site data storage.
// This function neither mounts, repairs, expands nor cleans any filesystem.
func verifyApacheBodyCacheQuota() (apacheBodyCacheBudget, error) {
	return verifyApacheBodyCacheQuotaView(false)
}

func verifyApacheBodyCacheQuotaView(readOnlyGuard bool) (apacheBodyCacheBudget, error) {
	var budget apacheBodyCacheBudget
	if err := apacheBodyOwnedAncestors(apacheBodyTemporary); err != nil {
		return budget, err
	}
	f, err := os.OpenFile(apacheBodyTemporary, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return budget, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0755 || before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return budget, errors.New("Apache 请求体硬限额缓存目录类型或权限异常")
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	// Root's primary group may be panel in the executor and root in Apache.
	// The shared cache mount has one fixed root:root identity for both callers.
	if !ok || owner.Uid != 0 || owner.Gid != 0 {
		return budget, errors.New("Apache 请求体硬限额缓存必须由 root:root 控制")
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &fs); err != nil {
		return budget, err
	}
	budget, err = apacheBodyCacheFilesystemBudgetView(fs, readOnlyGuard)
	if err != nil {
		return budget, err
	}
	if err := apacheBodyCacheDedicatedMount(f, uint64(owner.Dev)); err != nil {
		return apacheBodyCacheBudget{}, err
	}
	current, err := os.Lstat(apacheBodyTemporary)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, current) || current.Mode() != before.Mode() {
		return budget, errors.New("Apache 请求体硬限额缓存在核验期间被替换")
	}
	return budget, nil
}

// Match the opened descriptor's kernel mount ID, not just a name in the
// mount table. A subdirectory bind or a cache on a shared qualifying tmpfs
// must not be mistaken for the dedicated filesystem root. fdinfo is used
// instead of newer statx flags to retain the older supported kernel ABI.
func apacheBodyCacheDedicatedMount(f *os.File, device uint64) error {
	mountID, err := apacheBodyCacheDescriptorMountID(f)
	if err != nil {
		return err
	}
	info, err := apacheBodyCacheProcRead("/proc/self/mountinfo", 2<<20)
	if err != nil {
		return err
	}
	return apacheBodyCacheMountInfoRoot(info, mountID, device)
}

func apacheBodyCacheDescriptorMountID(f *os.File) (string, error) {
	fdinfo, err := apacheBodyCacheProcRead(fmt.Sprintf("/proc/self/fdinfo/%d", f.Fd()), 4096)
	if err != nil {
		return "", err
	}
	mountID := ""
	for _, line := range strings.Split(string(fdinfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "mnt_id:" {
			if mountID != "" {
				return "", errors.New("Apache 缓存描述符挂载身份重复")
			}
			if id, err := strconv.ParseUint(fields[1], 10, 64); err != nil || id == 0 {
				return "", errors.New("Apache 缓存描述符挂载身份异常")
			}
			mountID = fields[1]
		}
	}
	if mountID == "" {
		return "", errors.New("Apache 缓存描述符没有实际挂载身份")
	}
	return mountID, nil
}

// The fixed PID1 mount unit calls this read-only guard before first mounting.
// It must not hide existing unmounted evidence or replace a foreign mount.
// No path/options/cleanup or general mount authority is exposed to the API.
func CheckApacheBodyCacheMount() error {
	// ProtectSystem=strict deliberately makes this guard's namespace read-only.
	// A qualifying bounded mount may be read-only here; never grant readiness
	// from this check. The actual Apache/executor preparation remains writable-
	// only and independently validates its own opened descriptor before use.
	return checkApacheBodyCacheMount(true)
}

func checkApacheBodyCacheMount(readOnlyGuard bool) error {
	if os.Geteuid() != 0 {
		return errors.New("Apache 缓存挂载前检查只能由 root 执行")
	}
	if _, err := verifyApacheBodyCacheQuotaView(readOnlyGuard); err == nil {
		return nil
	}
	if err := apacheBodyOwnedAncestors(apacheBodyTemporary); err != nil {
		return err
	}
	f, err := os.OpenFile(apacheBodyTemporary, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode() != os.ModeDir|0755 || owner.Uid != 0 || owner.Gid != 0 {
		return errors.New("Apache 未挂载缓存的身份或权限异常，未接管")
	}
	mountID, err := apacheBodyCacheDescriptorMountID(f)
	if err != nil {
		return err
	}
	info, err := apacheBodyCacheProcRead("/proc/self/mountinfo", 2<<20)
	if err != nil {
		return err
	}
	found := false
	for _, line := range strings.Split(string(info), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != mountID {
			continue
		}
		if found || len(fields) < 10 || fields[4] == apacheBodyTemporary {
			return errors.New("Apache 缓存已有未通过固定硬限额核验的挂载，未覆盖")
		}
		found = true
	}
	if !found {
		return errors.New("Apache 未挂载缓存的实际文件系统身份不可核对")
	}
	if entries, err := f.ReadDir(1); !errors.Is(err, io.EOF) || len(entries) != 0 {
		return errors.New("Apache 未挂载缓存已有内容或不可读取，未隐藏或清理")
	}
	current, err := os.Lstat(apacheBodyTemporary)
	if err != nil || !os.SameFile(st, current) || current.Mode() != st.Mode() {
		return errors.New("Apache 缓存路径在挂载前检查期间变化")
	}
	return nil
}

// Run from the verified candidate before an installer changes any program,
// account, directory or service. A missing leaf is permissible at this point:
// provisioning and the stricter PID1 pre-mount guard still run later. Existing
// contents/mounts use exactly the same read-only authority as the cold guard.
// There are deliberately no caller-selected paths or mount/cleanup options.
func CheckApacheBodyCacheUpgradePreflight() error {
	if os.Geteuid() != 0 {
		return errors.New("Apache 缓存升级前检查只能由 root 执行")
	}
	if _, err := os.Lstat(apacheBodyTemporary); err == nil {
		return checkApacheBodyCacheMount(false)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(apacheBodyTemporary)
	if err := apacheBodyOwnedAncestors(parent); err != nil {
		return err
	}
	f, err := os.OpenFile(parent, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return err
	}
	if !before.IsDir() || before.Mode().Perm()&0022 != 0 {
		return errors.New("Apache 缓存父目录在升级前检查期间变为可写或非目录，未更改服务")
	}
	var leaf unix.Stat_t
	if err := unix.Fstatat(int(f.Fd()), filepath.Base(apacheBodyTemporary), &leaf, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return errors.New("Apache 缓存路径在升级前检查期间出现或无法核对，未更改服务")
	}
	current, err := os.Lstat(parent)
	if err != nil || !os.SameFile(before, current) || current.Mode() != before.Mode() {
		return errors.New("Apache 缓存父目录在升级前检查期间变化，未更改服务")
	}
	first, firstOK := before.Sys().(*syscall.Stat_t)
	last, lastOK := current.Sys().(*syscall.Stat_t)
	if !firstOK || !lastOK || first.Uid != 0 || last.Uid != first.Uid || last.Gid != first.Gid {
		return errors.New("Apache 缓存父目录身份在升级前检查期间变化，未更改服务")
	}
	return nil
}

func apacheBodyCacheProcRead(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &fs); err != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, errors.New("Apache 缓存挂载信息不是实际内核 proc 文件")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(b) == 0 || int64(len(b)) > limit {
		return nil, errors.New("Apache 缓存挂载信息为空或超过读取上限")
	}
	return b, nil
}

func apacheBodyCacheMountInfoRoot(info []byte, mountID string, device uint64) error {
	matched := false
	dev := fmt.Sprintf("%d:%d", unix.Major(device), unix.Minor(device))
	for _, line := range strings.Split(string(info), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != mountID {
			continue
		}
		separator := -1
		for i, field := range fields {
			if i >= 6 && field == "-" {
				separator = i
				break
			}
		}
		if matched || separator < 6 || len(fields) != separator+4 || fields[2] != dev || fields[3] != "/" || fields[4] != apacheBodyTemporary || fields[separator+1] != "tmpfs" {
			return errors.New("Apache 缓存不是独立 tmpfs 根挂载或描述符身份矛盾")
		}
		matched = true
	}
	if !matched {
		return errors.New("Apache 缓存实际挂载身份不在内核挂载表中")
	}
	return nil
}

func apacheBodyCacheFilesystemBudget(fs unix.Statfs_t) (apacheBodyCacheBudget, error) {
	return apacheBodyCacheFilesystemBudgetView(fs, false)
}

func apacheBodyCacheFilesystemBudgetView(fs unix.Statfs_t, readOnlyGuard bool) (apacheBodyCacheBudget, error) {
	if readOnlyGuard {
		// Ignore only the guard's non-writable namespace view. Filesystem type,
		// exact physical capacities, noexec/nosuid/nodev and mount-root identity
		// still have to pass. Neither installer nor activation uses this mode.
		fs.Flags &^= unix.ST_RDONLY
	}
	var budget apacheBodyCacheBudget
	flags := int64(unix.ST_NODEV | unix.ST_NOSUID | unix.ST_NOEXEC)
	if fs.Type != unix.TMPFS_MAGIC || fs.Bsize <= 0 || fs.Bsize > 1<<20 || int64(fs.Flags)&flags != flags || int64(fs.Flags)&unix.ST_RDONLY != 0 {
		return budget, errors.New("Apache 请求体缓存缺少可写 tmpfs 及 nodev/nosuid/noexec 保护，未启用")
	}
	blockSize := uint64(fs.Bsize)
	// Compare before multiplying: an unknown huge capacity cannot overflow
	// into the accepted fixed 128 MiB contract.
	if apacheBodyCacheBytes%blockSize != 0 || fs.Blocks != apacheBodyCacheBytes/blockSize || fs.Bavail > fs.Blocks || fs.Bfree > fs.Blocks || fs.Files != apacheBodyCacheInodes || fs.Ffree > fs.Files {
		return budget, errors.New("Apache 请求体缓存不是固定 128 MiB / 4096 inode 硬上限，未启用")
	}
	budget = apacheBodyCacheBudget{TotalBytes: fs.Blocks * blockSize, AvailableBytes: fs.Bavail * blockSize, TotalInodes: fs.Files, AvailableNodes: fs.Ffree}
	return budget, nil
}
