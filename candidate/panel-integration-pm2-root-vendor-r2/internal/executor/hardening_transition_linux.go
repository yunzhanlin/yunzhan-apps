//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Kernel documentation: BPF=1 cannot be cleared during the running boot;
// BPF=2 disables the same unprivileged calls but is administratively reversible.
// Likewise, never introduce the irreversible Yama=3 latch through rollback.
func hardeningValueValid(key, value string) bool {
	n, err := strconv.Atoi(value)
	if err != nil || strconv.Itoa(n) != value || n < 0 {
		return false
	}
	limit := 1
	switch key {
	case "fs.protected_fifos", "fs.protected_regular", "kernel.kptr_restrict", "kernel.unprivileged_bpf_disabled":
		limit = 2
	case "kernel.yama.ptrace_scope":
		limit = 3
	default:
		if _, ok := hardeningValues("strict")[key]; !ok {
			return false
		}
	}
	return n <= limit
}

func hardeningProfile(settings map[string]any) (string, error) {
	profile, ok := settings["profile"].(string)
	if len(settings) != 1 || !ok || (profile != "baseline" && profile != "strict") {
		return "", errors.New("系统加固配置必须是完整的 baseline 或 strict 配置，未执行变更")
	}
	return profile, nil
}

func (s *Service) hardeningMutationLock() (*os.File, error) {
	root, err := s.softwareManifestDirectory()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := "hardening-configuration.lock"
	flags := os.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		flags |= os.O_CREATE | os.O_EXCL
	} else if err != nil {
		return nil, err
	} else if !softwareManifestRecordInfo(info) || info.Mode().Perm() != 0600 {
		return nil, errors.New("加固变更锁类型、归属、链接数或权限异常，未修复")
	}
	f, err := root.OpenFile(name, flags, 0600)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	visible, visibleErr := root.Lstat(name)
	if err != nil || visibleErr != nil || !softwareManifestRecordInfo(opened) || opened.Mode().Perm() != 0600 || !os.SameFile(opened, visible) || info != nil && !os.SameFile(info, opened) || !s.softwareManifestAnchorCurrent(root) {
		f.Close()
		return nil, errors.New("加固变更锁命名身份改变")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("另一个系统加固变更尚未结束，未等待重放")
	}
	return f, nil
}

func hardeningSorted(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func hardeningReversible(key, current, next string) error {
	if (key == "kernel.unprivileged_bpf_disabled" && (current == "1" || next == "1") || key == "kernel.yama.ptrace_scope" && (current == "3" || next == "3")) && current != next {
		return fmt.Errorf("内核参数 %s 已处于或将进入本次启动不可撤销状态，未更改配置；需管理员核对重启恢复方案，不能承诺即时回滚", key)
	}
	return nil
}

func hardeningPrevious(manifest softwareManifest) (map[string]string, error) {
	profile, err := hardeningProfile(manifest.Settings)
	if err != nil {
		return nil, err
	}
	keys := hardeningValues(profile)
	if len(manifest.Previous) != len(keys) {
		return nil, errors.New("原加固参数的完整恢复基线缺失；未猜测旧值或修改配置")
	}
	for key := range keys {
		value, ok := manifest.Previous[key]
		if !ok || !hardeningValueValid(key, value) {
			return nil, errors.New("原加固参数恢复基线不可核对；未执行变更")
		}
	}
	return keys, nil
}

func hardeningFileInfo(info os.FileInfo, private bool) bool {
	if private {
		return softwareManifestRecordInfo(info)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uint32(os.Geteuid()) && owner.Nlink == 1 && info.Mode().IsRegular() && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && info.Mode().Perm()&0022 == 0
}

func hardeningReadBackup(root *os.Root, relative, absolute string, private bool) (fileBackup, error) {
	return hardeningReadBackupLimit(root, relative, absolute, private, 64<<10)
}

func hardeningReadBackupLimit(root *os.Root, relative, absolute string, private bool, limit int64) (fileBackup, error) {
	backup := fileBackup{path: absolute, mode: 0644}
	if private {
		backup.mode = 0600
	}
	info, err := root.Lstat(relative)
	if errors.Is(err, os.ErrNotExist) {
		return backup, nil
	}
	if err != nil {
		return backup, err
	}
	if limit < 1 || limit > hardeningJournalBytes || !hardeningFileInfo(info, private) || info.Size() < 1 || info.Size() > limit {
		return backup, errors.New("加固配置/清单的类型、身份、链接数、权限或容量无效，未读取或覆盖")
	}
	f, err := root.OpenFile(relative, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return backup, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !hardeningFileInfo(opened, private) {
		return backup, errors.New("加固文件打开期间身份改变")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, afterErr := f.Stat()
	visible, visibleErr := root.Lstat(relative)
	anchor, anchorErr := root.Stat(".")
	named, namedErr := os.Lstat(root.Name())
	if err != nil || afterErr != nil || visibleErr != nil || anchorErr != nil || namedErr != nil || !os.SameFile(anchor, named) || !named.IsDir() || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, after) || !os.SameFile(info, visible) || !hardeningFileInfo(after, private) || !hardeningFileInfo(visible, private) || int64(len(raw)) != info.Size() || after.Size() != info.Size() || visible.Size() != info.Size() || after.ModTime() != info.ModTime() || visible.ModTime() != info.ModTime() {
		return backup, errors.New("加固文件读取期间内容或命名身份改变")
	}
	backup.data = raw
	backup.mode = info.Mode().Perm()
	backup.owner, err = fileOwnerForInfo(info)
	backup.existed = err == nil
	return backup, err
}

func hardeningBackupSame(a, b fileBackup) bool {
	if a.path != b.path || a.existed != b.existed {
		return false
	}
	if !a.existed {
		return true
	}
	return a.mode == b.mode && a.owner != nil && b.owner != nil && *a.owner == *b.owner && bytes.Equal(a.data, b.data)
}

func (s *Service) hardeningManifestBackup() (fileBackup, error) {
	root, err := s.softwareManifestDirectory()
	if err != nil {
		return fileBackup{}, err
	}
	defer root.Close()
	return hardeningReadBackup(root, "system-hardening.json", s.softwareManifestPath("system-hardening"), true)
}

func hardeningManifestMatches(backup fileBackup, manifest softwareManifest, installed bool) error {
	if backup.existed != installed {
		return errors.New("加固清单安装身份在准备期间变化")
	}
	if !installed {
		return nil
	}
	var decoded softwareManifest
	fields := map[string]bool{"id": true, "version": true, "settings": true, "previous": true, "installed_at": true}
	if decodeApacheWAFPrivateJSON(backup.data, &decoded, fields, 100000) != nil {
		return errors.New("加固清单内容不完整或含未知字段")
	}
	a, err := json.Marshal(decoded)
	if err != nil {
		return err
	}
	b, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if !bytes.Equal(a, b) {
		return errors.New("加固清单在准备期间变化，未执行变更")
	}
	return nil
}

func (s *Service) hardeningOriginalFilesCurrent(config []fileBackup, manifest fileBackup) error {
	current, err := s.hardeningConfigBackups()
	if err != nil {
		return err
	}
	if len(current) != len(config) {
		return errors.New("加固配置库存改变")
	}
	for i := range current {
		if !hardeningBackupSame(current[i], config[i]) {
			return errors.New("加固配置在准备期间变化，未覆盖")
		}
	}
	now, err := s.hardeningManifestBackup()
	if err != nil {
		return err
	}
	if !hardeningBackupSame(now, manifest) {
		return errors.New("加固清单在准备期间变化，未覆盖")
	}
	return nil
}

func hardeningConfigMatches(backups []fileBackup, manifest softwareManifest, installed bool) error {
	count := 0
	for _, backup := range backups {
		if !backup.existed {
			continue
		}
		count++
		if !installed {
			return errors.New("存在未登记的加固配置，未覆盖或自动接管")
		}
		profile, err := hardeningProfile(manifest.Settings)
		if err != nil {
			return err
		}
		want := hardeningValues(profile)
		valid := bytes.Equal(backup.data, []byte(renderSysctl(want)))
		// Original strict1 bytes are recognized, never silently normalized or
		// certified reversible. The kernel preflight rejects its locked value.
		if !valid && profile == "strict" {
			want["kernel.unprivileged_bpf_disabled"] = "1"
			valid = bytes.Equal(backup.data, []byte(renderSysctl(want)))
		}
		if !valid {
			return errors.New("原加固配置与已登记基线不一致，未覆盖外部修改")
		}
	}
	if installed && count != 1 {
		return errors.New("原加固配置缺失或同时存在两份，未猜测接管")
	}
	return nil
}

// Only undo our exact candidate bytes. A directory, link or changed external
// record is preserved and explicitly reported, never removed as compensation.
func (s *Service) hardeningRestoreManifest(before fileBackup, candidate []byte, removed bool) error {
	now, err := s.hardeningManifestBackup()
	if err != nil {
		return fmt.Errorf("清单身份改变，保留外来对象: %w", err)
	}
	if hardeningBackupSame(before, now) {
		return nil
	}
	if removed && !now.existed && before.existed {
		return restoreFiles([]fileBackup{before})
	}
	if !removed && now.existed && now.mode == 0600 && bytes.Equal(now.data, candidate) {
		return restoreFiles([]fileBackup{before})
	}
	return errors.New("清单并非本次操作的完整候选，未覆盖或删除外部变更")
}

// Anchor config traversal at the actual SystemRoot. Every named component below
// it must be owned by this executor and must not redirect through symlinks.
func (s *Service) hardeningConfigBackups() ([]fileBackup, error) {
	return s.hardeningConfigBackupsMode(true)
}

func (s *Service) hardeningConfigBackupsMode(create bool) ([]fileBackup, error) {
	rootPath := s.Config.SystemRoot
	if !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return nil, errors.New("加固系统根目录不规范")
	}
	rootInfo, err := os.Lstat(rootPath)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("加固系统根目录不可信")
	}
	owner, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || rootInfo.Mode().Perm()&0022 != 0 {
		return nil, errors.New("加固系统根目录归属或权限无效")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	for _, name := range []string{"etc", "etc/sysctl.d"} {
		info, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			if !create {
				return nil, errors.New("加固配置原父目录缺失，未由只读核对重建")
			}
			if err = root.Mkdir(name, 0755); err != nil {
				return nil, err
			}
			info, err = root.Lstat(name)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("加固配置父目录异常，未跟随或修复")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("加固配置父目录归属异常")
		}
	}
	backups := []fileBackup{}
	for _, name := range []string{"99-zz-panel-hardening.conf", "90-panel-hardening.conf"} {
		file := s.systemPath("/etc/sysctl.d/" + name)
		backup, err := hardeningReadBackup(root, "etc/sysctl.d/"+name, file, false)
		if err != nil {
			return nil, err
		}
		backups = append(backups, backup)
	}
	return backups, nil
}

func (s *Service) hardeningReadValues(ctx context.Context, keys map[string]string) (map[string]string, error) {
	values := map[string]string{}
	for _, key := range hardeningSorted(keys) {
		value, err := s.sysctlValue(ctx, key)
		if err != nil || !hardeningValueValid(key, value) {
			return nil, fmt.Errorf("内核参数 %s 的实际值无法核对，未执行变更", key)
		}
		values[key] = value
	}
	return values, nil
}

func (s *Service) hardeningVerify(ctx context.Context, expected map[string]string) error {
	actual, err := s.hardeningReadValues(ctx, expected)
	if err != nil {
		return err
	}
	if !maps.Equal(actual, expected) {
		return errors.New("内核参数实际值与本次期望不一致")
	}
	return nil
}

func (s *Service) hardeningRollback(before map[string]string, backups []fileBackup, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	restored := restoreFiles(backups)
	for _, key := range hardeningSorted(before) {
		actual, err := s.sysctlValue(ctx, key)
		if err != nil {
			restored = errors.Join(restored, err)
			continue
		}
		if actual == before[key] {
			continue
		}
		if err = hardeningReversible(key, actual, before[key]); err == nil {
			_, err = s.Config.Run(ctx, "/usr/sbin/sysctl", "-w", key+"="+before[key])
		}
		restored = errors.Join(restored, err)
	}
	restored = errors.Join(restored, s.hardeningVerify(ctx, before))
	if restored != nil {
		return errors.Join(cause, fmt.Errorf("即时恢复未完成；原安装记录未宣称成功，请核对实际参数: %w", restored))
	}
	return fmt.Errorf("%w；已核对恢复本次操作前的实际参数和配置文件", cause)
}
