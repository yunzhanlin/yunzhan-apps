//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"syscall"
)

func apacheCCIndependentCopy(copy, source, fresh apacheCCArchiveFile) bool {
	return validApacheCCArchiveFile(copy) && copy.UID == uint32(os.Geteuid()) && copy.GID == uint32(os.Getegid()) && copy.Device == source.Device && copy.Inode != source.Inode && copy.Inode != fresh.Inode && copy.Bytes == source.Bytes && copy.SHA256 == source.SHA256
}

// The preserved producer inode is forensic material, not archive authority.
// Its content can still change through an old descriptor, even after chown.
// Snapshot digests bind only its fixed pathname identity; the explicit format
// field source_identity_only prevents interpreting the sentinel as raw bytes.
func apacheCCArchiveSourceIdentity(f *os.File, path string, uid, gid int) (apacheCCArchiveFile, error) {
	st, err := f.Stat()
	if err != nil {
		return apacheCCArchiveFile{}, err
	}
	named, err := os.Lstat(path)
	owner, ok := st.Sys().(*syscall.Stat_t)
	if err != nil || !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || owner.Uid != uint32(uid) || owner.Gid != uint32(gid) || owner.Nlink != 1 || !os.SameFile(st, named) || named.Mode() != st.Mode() {
		return apacheCCArchiveFile{}, errors.New("CC 原来源文件的路径、账户、权限或单链接身份不匹配")
	}
	return apacheCCArchiveFile{Device: uint64(owner.Dev), Inode: owner.Ino, UID: owner.Uid, GID: owner.Gid, Bytes: 0, SHA256: core.Hash("")}, nil
}

func apacheCCArchiveSourceStatus(ctx context.Context, path string, witness apacheCCArchiveFile) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	identity, err := apacheCCArchiveSourceIdentity(f, path, os.Geteuid(), os.Getegid())
	if err != nil || identity.Device != witness.Device || identity.Inode != witness.Inode {
		return "", errors.New("CC 原来源文件身份缺失或变化；未忽略原文件")
	}
	actual, err := apacheCCArchiveInspect(ctx, f, path, os.Geteuid(), os.Getegid())
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	witness.UID, witness.GID = uint32(os.Geteuid()), uint32(os.Getegid())
	if err != nil || actual != witness {
		return "changed-after-copy", nil
	}
	return "matches-witness", nil
}

// Root ownership alone is not provenance: an old format-1 archive may be the
// former producer inode. Unknown recovery must prove the new format and a
// different inode before exposing any file as an independent private copy.
func (s *Service) verifyApacheCCCopyProvenance(dir, id string, copy apacheCCArchiveFile) error {
	var intent apacheCCArchiveIntent
	_, err := readApacheCCArchivePhase(filepath.Join(dir, "intent.json"), &intent)
	uid, gid, accountErr := s.apacheCCArchiveWorker()
	if err != nil || accountErr != nil || intent.Format != apacheCCArchiveFormat || intent.ID != id || intent.Request.RequestID != id || intent.Request.ExpectedRevision < 1 || intent.Request.ExpectedRevision > 1000000000 || !validApacheNumericRotationTime(intent.At) || !validApacheCCArchiveFile(intent.Source) || intent.Source.Bytes == 0 || intent.Source.UID != uint32(uid) || intent.Source.GID != uint32(gid) || intent.TailIncomplete && !intent.Request.AllowIncomplete || copy.Device != intent.Source.Device || copy.Inode == intent.Source.Inode || copy.Bytes > intent.Source.Bytes {
		return errors.New("CC 未证明该文件是新版独立 Root 副本；保留原证据，不将旧 inode 追认为副本")
	}
	return nil
}
