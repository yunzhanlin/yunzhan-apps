//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"syscall"
)

// HTTP runs as root:panel while native programme checks normally run as
// root:root. Exact 0600 files under fixed 0700 Root directories give the group
// no access. A reader's current group is not the historical inode's group.
// Keep the actual GID in every full witness; never normalize recorded data.
func apacheCCArchivePrivateOwner(info os.FileInfo) (int, int, error) {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return 0, 0, errors.New("CC 私有证据不属于固定 Root 所有者")
	}
	return os.Geteuid(), int(owner.Gid), nil
}

func apacheCCArchivePrivateStat(info os.FileInfo) (apacheCCArchiveFile, error) {
	uid, gid, err := apacheCCArchivePrivateOwner(info)
	if err != nil {
		return apacheCCArchiveFile{}, err
	}
	return apacheCCArchiveStat(info, uid, gid)
}

func apacheCCArchivePrivateInspect(ctx context.Context, f *os.File, path string) (apacheCCArchiveFile, error) {
	info, err := f.Stat()
	if err != nil {
		return apacheCCArchiveFile{}, err
	}
	uid, gid, err := apacheCCArchivePrivateOwner(info)
	if err != nil {
		return apacheCCArchiveFile{}, err
	}
	return apacheCCArchiveInspect(ctx, f, path, uid, gid)
}

func apacheCCArchivePrivateSourceIdentity(f *os.File, path string) (apacheCCArchiveFile, error) {
	info, err := f.Stat()
	if err != nil {
		return apacheCCArchiveFile{}, err
	}
	uid, gid, err := apacheCCArchivePrivateOwner(info)
	if err != nil {
		return apacheCCArchiveFile{}, err
	}
	return apacheCCArchiveSourceIdentity(f, path, uid, gid)
}
