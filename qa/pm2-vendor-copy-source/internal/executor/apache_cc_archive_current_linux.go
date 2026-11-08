//go:build linux

package executor

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type apacheCCArchiveCurrent struct {
	Available         bool  `json:"available"`
	Bytes             int64 `json:"bytes"`
	MaxBytes          int64 `json:"max_bytes"`
	TailIncomplete    bool  `json:"tail_incomplete"`
	CapacityNearLimit bool  `json:"capacity_near_limit"`
	ReadOnly          bool  `json:"read_only"`
}

func (s *Service) readApacheCCArchiveCurrent(ctx context.Context, required bool) (apacheCCArchiveCurrent, error) {
	out := apacheCCArchiveCurrent{MaxBytes: apacheCCLogMaxBytes, ReadOnly: true}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	f, err := s.openApacheCCArchiveCurrentMode(false)
	if errors.Is(err, os.ErrNotExist) && !required {
		return out, nil
	}
	if err != nil {
		return out, errors.New("CC 原日志缺失或身份不可核对，未显示为零字节")
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		return out, errors.New("CC 日志正在写入或归档，请稍后只读核对")
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	uid, gid, err := s.apacheCCArchiveWorker()
	if err != nil {
		return out, err
	}
	before, err := apacheCCLogFileIdentity(f, uid, gid)
	if err != nil {
		return out, err
	}
	var tail [1]byte
	if before.Size() > 0 {
		if _, err := f.ReadAt(tail[:], before.Size()-1); err != nil {
			return out, err
		}
		out.TailIncomplete = tail[0] != '\n'
	}
	after, statErr := f.Stat()
	named, nameErr := os.Lstat(s.systemPath(apacheCCLogPath))
	if statErr != nil || nameErr != nil || !apacheBodyEventsSameFile(before, after) || !apacheBodyEventsSameFile(after, named) {
		return out, errors.New("CC 原日志在只读核对期间变化，未采用旧状态")
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.Available, out.Bytes, out.CapacityNearLimit = true, before.Size(), before.Size() >= apacheCCLogMaxBytes-4096
	return out, nil
}
