//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type threatIDSHistorySummary struct {
	Archives         int    `json:"archives"`
	ArchiveBytes     int64  `json:"archive_bytes"`
	ArchiveLimit     int    `json:"archive_limit"`
	ArchiveByteLimit int64  `json:"archive_byte_limit"`
	RotateAtBytes    int64  `json:"rotate_at_bytes"`
	RecordLimit      int    `json:"record_limit"`
	RetiredDigests   int    `json:"retired_digests"`
	Pending          bool   `json:"pending"`
	OldestRotationAt string `json:"oldest_rotation_at,omitempty"`
}

// Verify the bytes returned to the parser, not a separately opened pathname's
// digest. Archives are bounded root-private snapshots, never arbitrary files.
func (s *Service) readThreatIDSArchiveSnapshot(ctx context.Context, entry threatIDSArchive) ([]byte, error) {
	if !validThreatIDSArchive(entry) {
		return nil, errors.New("IDS 归档身份无效")
	}
	dir, err := s.threatIDSHistoryDirectory(false)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "eve-"+entry.ID+".json")
	return readThreatIDSPrivateArchiveFile(ctx, entry, path)
}

// Only callers resolving an exact ledger-derived name in the verified private
// history directory use this helper, including the recoverable retirement slot.
func readThreatIDSPrivateArchiveFile(ctx context.Context, entry threatIDSArchive, path string) ([]byte, error) {
	if !validThreatIDSArchive(entry) {
		return nil, errors.New("IDS 私有归档身份无效")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	identity := func(info os.FileInfo) bool {
		st, ok := info.Sys().(*syscall.Stat_t)
		return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && st.Uid == 0 && st.Gid == 0 && st.Nlink == 1 && uint64(st.Dev) == entry.Device && st.Ino == entry.Inode && info.Size() == entry.Bytes
	}
	if !identity(before) || ctx.Err() != nil {
		return nil, errors.New("IDS 封存归档不是记录中的私有文件")
	}
	data, err := io.ReadAll(io.LimitReader(f, threatEVEByteLimit+1))
	if err != nil || ctx.Err() != nil || int64(len(data)) != entry.Bytes || fmt.Sprintf("%x", sha256.Sum256(data)) != entry.SHA {
		return nil, errors.New("IDS 实际归档快照完整摘要不匹配")
	}
	after, err := f.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !identity(after) || !identity(current) || !os.SameFile(before, current) || !before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(current.ModTime()) {
		return nil, errors.New("IDS 归档读取期间身份或内容发生变化")
	}
	return data, nil
}

func (s *Service) threatIDSHistorySources(ctx context.Context) ([]threatEVESource, threatIDSHistorySummary, error) {
	out := threatIDSHistorySummary{ArchiveLimit: threatIDSHistoryLimit, ArchiveByteLimit: threatEVEByteLimit, RotateAtBytes: threatIDSRotationThreshold, RecordLimit: threatEVERecordLimit}
	v, err := s.readThreatIDSRotation()
	if err != nil {
		return nil, out, err
	}
	out.Pending = v.Pending != nil || v.Retiring != nil
	if out.Pending {
		return nil, out, errors.New("IDS 轮转或归档保留仍待恢复；未当作完整历史")
	}
	if len(v.Archives) > threatIDSHistoryLimit {
		return nil, out, errors.New("IDS 待保留归档超出完整查询容量")
	}
	out.Archives = len(v.Archives)
	out.RetiredDigests = len(v.Retired)
	dir, err := s.threatIDSHistoryDirectory(false)
	if os.IsNotExist(err) && len(v.Archives) == 0 {
		return nil, out, nil
	}
	if err != nil {
		return nil, out, err
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, out, err
	}
	defer f.Close()
	entries, err := f.ReadDir(threatIDSHistoryLimit + 1)
	if err != nil && err != io.EOF || len(entries) != len(v.Archives) {
		return nil, out, errors.New("IDS 历史目录含未记录或缺失文件；未隐藏未知数据")
	}
	allowed := map[string]bool{}
	for _, entry := range v.Archives {
		allowed["eve-"+entry.ID+".json"] = true
		out.ArchiveBytes += entry.Bytes
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || !entry.Type().IsRegular() {
			return nil, out, errors.New("IDS 历史目录含未知条目")
		}
	}
	sources := []threatEVESource{}
	for i := len(v.Archives) - 1; i >= 0; i-- {
		data, err := s.readThreatIDSArchiveSnapshot(ctx, v.Archives[i])
		if err != nil {
			return nil, out, err
		}
		sources = append(sources, threatEVESource{Reader: bytes.NewReader(data)})
	}
	if len(v.Archives) > 0 {
		out.OldestRotationAt = v.Archives[0].At
	}
	return sources, out, nil
}
