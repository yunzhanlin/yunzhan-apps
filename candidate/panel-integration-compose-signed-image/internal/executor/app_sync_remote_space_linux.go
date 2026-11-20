//go:build linux

package executor

import (
	"errors"

	"github.com/pkg/sftp"
)

var (
	errRemoteBackupSpace    = errors.New("远端备份文件系统的可用空间或 inode 不足，未开始本次文件交接")
	errRemoteBackupReadOnly = errors.New("远端备份文件系统只读，未开始本次文件交接")
)

type remoteBackupSpace struct {
	state           string
	blockSize       uint64
	availableBytes  uint64
	availableInodes uint64
	hasInodeLimit   bool
}

func inspectRemoteBackupSpace(client *remoteSyncClient, backupRoot string) remoteBackupSpace {
	if version, ok := client.HasExtension("statvfs@openssh.com"); !ok || version != "2" {
		return remoteBackupSpace{state: "unsupported"}
	}
	stats, err := client.StatVFS(backupRoot)
	if err != nil {
		return remoteBackupSpace{state: "unavailable"}
	}
	return remoteBackupSpaceFromStats(stats)
}

func remoteBackupSpaceFromStats(stats *sftp.StatVFS) remoteBackupSpace {
	const maxExactJSONInteger = 1<<53 - 1
	const sftpStatVFSReadOnly = 1
	if stats.Frsize == 0 || stats.Frsize > maxExactJSONInteger ||
		stats.Bavail > stats.Blocks || stats.Bavail > maxExactJSONInteger/stats.Frsize ||
		stats.Files != 0 && (stats.Favail > stats.Files || stats.Favail > maxExactJSONInteger) {
		return remoteBackupSpace{state: "unavailable"}
	}
	state := "available"
	if stats.Flag&sftpStatVFSReadOnly != 0 {
		state = "read_only"
	}
	return remoteBackupSpace{
		state:           state,
		blockSize:       stats.Frsize,
		availableBytes:  stats.Bavail * stats.Frsize,
		availableInodes: stats.Favail,
		hasInodeLimit:   stats.Files != 0,
	}
}

func (s remoteBackupSpace) admit(size int64) error {
	if s.state == "read_only" {
		return errRemoteBackupReadOnly
	}
	if s.state != "available" {
		// Keep the existing staging/checkpoint path for servers that cannot
		// answer statvfs. Even an available sample is advisory and can race.
		return nil
	}
	// Allow one fragment for the transaction directory and round the stage
	// file up to a fragment. Rename and hard-link reuse existing file inodes.
	requiredBlocks := (uint64(size)+s.blockSize-1)/s.blockSize + 1
	if requiredBlocks > s.availableBytes/s.blockSize || s.hasInodeLimit && s.availableInodes < 2 {
		return errRemoteBackupSpace
	}
	return nil
}
