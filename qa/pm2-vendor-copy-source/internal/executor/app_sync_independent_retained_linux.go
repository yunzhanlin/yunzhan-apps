//go:build linux

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"reflect"
	"sort"

	"golang.org/x/sys/unix"
)

// Close only a known, fully inventoried copy intent. Original incomplete bytes
// stay in their original inodes; this is never a successful backup receipt.
func (s *Service) retainRemoteCopy(cfg remoteSyncConfig, in core.AppModuleInput) (any, error) {
	r, err := s.readRemoteCopyRecord(cfg.ID, in.ResourceID)
	if err != nil || remoteCopyStateSHA(r) != in.ExpectedSHA || r.Result != nil {
		return nil, errors.New("须核对独立备份当前状态摘要；完整副本不转为残片，未知或已变化记录不覆盖")
	}
	files := []remoteCopyFile{}
	for _, attempt := range r.Attempts {
		d, err := s.remoteCopyDirectory(cfg.ID, in.ResourceID, attempt, false)
		if err != nil {
			return nil, err
		}
		for _, source := range r.Intent.Source.Snapshot.Files {
			info, err := d.Lstat(source.Name)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				d.Close()
				return nil, err
			}
			metadata, err := remoteCopyFileMetadata(info, attempt+"/"+source.Name, "")
			if err != nil || metadata.Bytes > source.File.Size {
				d.Close()
				return nil, errors.New("原残片容量或身份变化，未保留关闭")
			}
			f, err := d.OpenFile(source.Name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				d.Close()
				return nil, err
			}
			opened, openErr := f.Stat()
			h := sha256.New()
			n, readErr := io.Copy(h, io.LimitReader(f, metadata.Bytes+1))
			after, afterErr := f.Stat()
			visible, visibleErr := d.Lstat(source.Name)
			closeErr := f.Close()
			if openErr != nil || readErr != nil || afterErr != nil || visibleErr != nil || closeErr != nil || n != metadata.Bytes || !programQueueSame(info, opened) || !programQueueSame(info, after) || !programQueueSame(info, visible) || !d.current() {
				d.Close()
				return nil, errors.New("原残片读取期间变化，未宣称关闭或完整成功")
			}
			metadata.SHA = hex.EncodeToString(h.Sum(nil))
			files = append(files, metadata)
		}
		d.Close()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	if r.Retained != nil {
		if !reflect.DeepEqual(r.Retained.Files, files) {
			return nil, errors.New("已保留原残片内容变化，未重新声明有效")
		}
		return map[string]any{"independent_backup": remoteCopyPublic(r, cfg.Revision, false), "replayed": true, "original_fragments_preserved": true, "backup_complete": false, "remote_files_changed": false, "scope": remoteCopyScope}, nil
	}
	d, err := s.remoteCopyDirectory(cfg.ID, in.ResourceID, "", false)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	if _, err = remoteCopyPublish(d, "retained.json", remoteCopyRetained{Format: 1, IntentSHA: r.SHA, Files: files, RetainedAt: core.Now()}); err != nil {
		return nil, err
	}
	r, err = s.readRemoteCopyRecord(cfg.ID, in.ResourceID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"independent_backup": remoteCopyPublic(r, cfg.Revision, false), "original_fragments_preserved": true, "backup_complete": false, "remote_files_changed": false, "scope": remoteCopyScope}, nil
}
