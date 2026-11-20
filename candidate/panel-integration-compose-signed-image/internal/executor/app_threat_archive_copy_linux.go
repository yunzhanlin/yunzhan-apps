//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func threatIDSProducerName(id string) string {
	return "producer-eve-" + id + ".json"
}

func threatIDSCopyDirectoryCurrent(directory *os.File, path string) error {
	opened, err := directory.Stat()
	named, namedErr := os.Lstat(path)
	if err != nil || namedErr != nil || !os.SameFile(opened, named) || !opened.IsDir() || opened.Mode() != os.ModeDir|0700 || named.Mode() != opened.Mode() {
		return errors.New("IDS 副本目录身份或权限改变；未接管")
	}
	owner, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Gid != 0 {
		return errors.New("IDS 副本目录不是 root 私有目录")
	}
	return threatIDSTrustedParents(path, false)
}

func threatIDSOpenCopyDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "history" {
		return nil, errors.New("IDS 副本目录位置无效")
	}
	if err := threatIDSTrustedParents(path, false); err != nil {
		return nil, err
	}
	directory, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	if err := threatIDSCopyDirectoryCurrent(directory, path); err != nil {
		directory.Close()
		return nil, err
	}
	return directory, nil
}

// An unnamed root inode cannot have a producer's pre-existing descriptor.
// A crash before publication closes and removes it instead of leaving an
// ambiguous named partial file. Never fall back to renaming or chowning the
// producer inode when the filesystem does not support this operation.
func threatIDSAnonymousArchive(directory *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("IDS 文件系统不支持或无法建立匿名私有副本；原数据保留: %w", err)
	}
	file := os.NewFile(uintptr(fd), "unnamed-ids-archive")
	if err := file.Chown(0, 0); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func threatIDSCopyFilesystemReady(path string) error {
	directory, err := threatIDSOpenCopyDirectory(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	file, err := threatIDSAnonymousArchive(directory)
	if err != nil {
		return err
	}
	return file.Close()
}

func threatIDSCopySourceInfo(info os.FileInfo, p *threatIDSRotationPending, account threatIDSAccount) bool {
	owner, ok := info.Sys().(*syscall.Stat_t)
	accountOwned := ok && owner.Uid == account.UID && owner.Gid == account.GID
	knownProtected := ok && p.Source != nil && p.Sealed != nil && owner.Uid == 0 && owner.Gid == 0
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		(accountOwned || knownProtected) && owner.Nlink == 1 && uint64(owner.Dev) == p.Device && owner.Ino == p.Inode &&
		info.Size() > 0 && info.Size() <= threatEVEByteLimit
}

func threatIDSCopySourceCurrent(directory, file *os.File, name string, before os.FileInfo, p *threatIDSRotationPending, account threatIDSAccount) error {
	after, err := file.Stat()
	if err != nil || !threatIDSCopySourceInfo(after, p, account) || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return errors.New("IDS 原来源在复制期间变化；没有修改原数据")
	}
	previous, current := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
	var named unix.Stat_t
	if previous.Ctim != current.Ctim || unix.Fstatat(int(directory.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		named.Dev != uint64(current.Dev) || named.Ino != current.Ino || named.Mode&unix.S_IFMT != unix.S_IFREG || named.Nlink != 1 ||
		named.Uid != current.Uid || named.Gid != current.Gid {
		return errors.New("IDS 原来源路径或元数据在复制期间变化")
	}
	return nil
}

func threatIDSSealIndependentArchive(ctx context.Context, path string, p *threatIDSRotationPending, account threatIDSAccount, persist func() error) (threatIDSArchive, error) {
	var empty threatIDSArchive
	if os.Geteuid() != 0 || ctx.Err() != nil || persist == nil || !validThreatIDSCopyPending(p) || !core.ValidID(p.ID) || !validWAFRotationTime(p.At) || p.Device == 0 || p.Inode == 0 || p.Revision < 1 || p.Revision >= 1<<60 || !threatPackageSHA.MatchString(p.RuntimeSHA) || !threatPackageSHA.MatchString(p.UnitSHA) ||
		p.UID != account.UID || p.GID != account.GID || validateThreatIDSAccount(account) != nil || filepath.Base(path) != "eve-"+p.ID+".json" {
		return empty, errors.New("IDS 独立副本的账户、意图或位置无效")
	}
	dir := filepath.Dir(path)
	directory, err := threatIDSOpenCopyDirectory(dir)
	if err != nil {
		return empty, err
	}
	defer directory.Close()
	finalName := filepath.Base(path)
	producerName := threatIDSProducerName(p.ID)
	var final unix.Stat_t
	finalErr := unix.Fstatat(int(directory.Fd()), finalName, &final, unix.AT_SYMLINK_NOFOLLOW)
	if finalErr != nil && !errors.Is(finalErr, syscall.ENOENT) {
		return empty, finalErr
	}
	// A durable preparation record witnesses an inode born root-private.
	// Existing files without that record are never adopted as private copies.
	if finalErr == nil && p.Sealed != nil {
		if _, err := readThreatIDSPrivateArchiveFile(ctx, *p.Sealed, path); err != nil {
			return empty, err
		}
		if err := threatIDSCopyDirectoryCurrent(directory, dir); err != nil {
			return empty, err
		}
		if err := threatIDSProtectProducerAfterCopy(ctx, dir, *p.Sealed); err != nil {
			return empty, err
		}
		return *p.Sealed, nil
	}
	var producer unix.Stat_t
	producerErr := unix.Fstatat(int(directory.Fd()), producerName, &producer, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(producerErr, syscall.ENOENT) {
		if p.Source != nil || p.Sealed != nil || finalErr != nil {
			return empty, errors.New("IDS 已移动的原来源缺失；不猜测或覆盖文件")
		}
		source, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return empty, err
		}
		info, statErr := source.Stat()
		source.Close()
		if statErr != nil || !threatIDSCopySourceInfo(info, p, account) {
			return empty, errors.New("IDS 首次封存的原来源身份不符")
		}
		if err := unix.Renameat2(int(directory.Fd()), finalName, int(directory.Fd()), producerName, unix.RENAME_NOREPLACE); err != nil {
			return empty, err
		}
		if err := directory.Sync(); err != nil {
			return empty, err
		}
		finalErr = syscall.ENOENT
	} else if producerErr != nil {
		return empty, producerErr
	} else if finalErr == nil {
		return empty, errors.New("IDS 副本位置已有未知文件；原来源保留，未覆盖")
	}

	fd, err := unix.Openat(int(directory.Fd()), producerName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, err
	}
	source := os.NewFile(uintptr(fd), "preserved-ids-producer")
	defer source.Close()
	before, err := source.Stat()
	if err != nil || !threatIDSCopySourceInfo(before, p, account) {
		return empty, errors.New("IDS 待复制原来源身份或边界不符")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, &contextReader{ctx, io.NewSectionReader(source, 0, before.Size()+1)})
	if err != nil || size != before.Size() || ctx.Err() != nil {
		return empty, errors.New("IDS 原来源完整摘要读取未完成")
	}
	if err := threatIDSCopySourceCurrent(directory, source, producerName, before, p, account); err != nil {
		return empty, err
	}
	witness := threatIDSArchiveSource{Device: p.Device, Inode: p.Inode, UID: account.UID, GID: account.GID, Bytes: size, SHA: hex.EncodeToString(hash.Sum(nil))}
	if p.Source != nil && *p.Source != witness {
		return empty, errors.New("IDS 已记录的原来源摘要变化；未重新认证")
	}
	if p.Source == nil {
		p.Source = &witness
		if err := threatIDSCopyDirectoryCurrent(directory, dir); err != nil {
			return empty, err
		}
		if err := persist(); err != nil {
			return empty, err
		}
	}

	copy, err := threatIDSAnonymousArchive(directory)
	if err != nil {
		return empty, err
	}
	defer copy.Close()
	combined := sha256.New()
	n, err := io.Copy(io.MultiWriter(copy, combined), &contextReader{ctx, io.NewSectionReader(source, 0, witness.Bytes+1)})
	if err != nil || ctx.Err() != nil || n != witness.Bytes || hex.EncodeToString(combined.Sum(nil)) != witness.SHA {
		return empty, errors.New("IDS 独立副本与已记录来源不一致；未发布")
	}
	if err := threatIDSCopySourceCurrent(directory, source, producerName, before, p, account); err != nil {
		return empty, err
	}
	if err := copy.Sync(); err != nil {
		return empty, err
	}
	info, err := copy.Stat()
	if err != nil {
		return empty, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Gid != 0 || owner.Nlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != witness.Bytes ||
		uint64(owner.Dev) != witness.Device || owner.Ino == witness.Inode {
		return empty, errors.New("IDS 匿名副本不是独立 root 私有 inode")
	}
	entry := threatIDSArchive{ID: p.ID, At: p.At, SHA: witness.SHA, Bytes: witness.Bytes, Device: uint64(owner.Dev), Inode: owner.Ino, Source: &witness}
	previous := p.Sealed
	p.Sealed = &entry
	if err := threatIDSCopyDirectoryCurrent(directory, dir); err != nil {
		p.Sealed = previous
		return empty, err
	}
	if err := persist(); err != nil {
		p.Sealed = previous
		return empty, err
	}
	if err := unix.Linkat(int(copy.Fd()), "", int(directory.Fd()), finalName, unix.AT_EMPTY_PATH); err != nil {
		return empty, fmt.Errorf("IDS 原子发布私有副本失败；没有覆盖其他文件: %w", err)
	}
	if err := copy.Sync(); err != nil {
		return empty, err
	}
	if err := directory.Sync(); err != nil {
		return empty, err
	}
	if err := threatIDSCopyDirectoryCurrent(directory, dir); err != nil {
		return empty, err
	}
	if _, err := readThreatIDSPrivateArchiveFile(ctx, entry, path); err != nil {
		return empty, err
	}
	if err := threatIDSProtectProducerAfterCopy(ctx, dir, entry); err != nil {
		return empty, err
	}
	return entry, nil
}

// Chown is deliberately only metadata protection for the preserved producer.
// It occurs after the independent copy is durable; old descriptors can still
// change producer bytes, but cannot change the authoritative copy's inode.
func threatIDSProtectProducerAfterCopy(ctx context.Context, dir string, entry threatIDSArchive) error {
	if entry.Source == nil {
		return nil
	}
	if !validThreatIDSArchive(entry) || ctx.Err() != nil {
		return errors.New("IDS 原来源保护缺少完整副本或操作已取消")
	}
	if _, err := readThreatIDSPrivateArchiveFile(ctx, entry, filepath.Join(dir, "eve-"+entry.ID+".json")); err != nil {
		return err
	}
	directory, err := threatIDSOpenCopyDirectory(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	name := threatIDSProducerName(entry.ID)
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(fd), "protected-ids-producer")
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	accountOwned := ok && owner.Uid == entry.Source.UID && owner.Gid == entry.Source.GID
	rootOwned := ok && owner.Uid == 0 && owner.Gid == 0
	var named unix.Stat_t
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || owner.Nlink != 1 ||
		(!accountOwned && !rootOwned) || uint64(owner.Dev) != entry.Source.Device || owner.Ino != entry.Source.Inode ||
		unix.Fstatat(int(directory.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || named.Dev != uint64(owner.Dev) || named.Ino != owner.Ino || named.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("IDS 原来源身份改变；未更改未知对象权限")
	}
	if !rootOwned {
		if err := source.Chown(0, 0); err != nil {
			return err
		}
	}
	if err := source.Sync(); err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	if err := threatIDSProducerIdentity(directory, name, *entry.Source); err != nil {
		return err
	}
	return threatIDSCopyDirectoryCurrent(directory, dir)
}
