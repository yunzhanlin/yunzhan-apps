//go:build linux

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"reflect"
	"sort"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const remoteUnpublishedMaxParts = 8
const remoteUnpublishedMaxMetadataBytes int64 = remoteCopyMaxRecords * (remoteUnpublishedMaxParts + 1) * remoteCopyRecordLimit
const remoteUnpublishedReceipt = "unpublished-retained.json"
const remoteUnpublishedScope = "只离线核对尚未发布主意图的本机私有目录：必须没有intent.json、尝试目录或数据文件，只允许有界的原记录片段。片段内容只计算摘要，不解释为源归档、连接或复制授权。明确保留后仍不是成功备份，不能恢复或下载为完整文件；原目录、片段和inode保留。未知条目、符号链接、硬链接、错误属主、权限或超限会拒绝完整库存，不自动忽略或删除。"

type remoteUnpublishedDirectory struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
}
type remoteUnpublishedSnapshot struct {
	Format        int                        `json:"format"`
	TargetID      string                     `json:"remote_target_id"`
	TransactionID string                     `json:"backup_transaction_id"`
	Directory     remoteUnpublishedDirectory `json:"directory"`
	Fragments     []remoteCopyFile           `json:"fragments"`
}
type remoteUnpublishedRetention struct {
	Format           int                       `json:"format"`
	Version          string                    `json:"app_version"`
	Snapshot         remoteUnpublishedSnapshot `json:"snapshot"`
	SnapshotSHA      string                    `json:"snapshot_sha256"`
	ReviewedSpecSHA  string                    `json:"reviewed_config_spec_sha256"`
	ReviewedRevision int64                     `json:"reviewed_config_revision"`
	RetainedAt       string                    `json:"retained_at"`
}
type remoteUnpublishedCopy struct {
	Snapshot remoteUnpublishedSnapshot
	SHA      string
	Retained *remoteUnpublishedRetention
	Bytes    int64
}
type remoteCopyInventory struct {
	Records          []remoteCopyRecord
	Unpublished      []remoteUnpublishedCopy
	Bytes            int64
	UnpublishedBytes int64
}

func (v remoteCopyInventory) count() int { return len(v.Records) + len(v.Unpublished) }
func remoteUnpublishedSHA(snapshot remoteUnpublishedSnapshot) string {
	raw, _ := json.Marshal(snapshot)
	return core.Hash(string(raw))
}

func remoteUnpublishedFragment(d *modulePrivateDirectory, name string) (remoteCopyFile, error) {
	info, err := d.Lstat(name)
	if err != nil || !remoteCopyTemporary(name) || info.Size() > remoteCopyRecordLimit {
		return remoteCopyFile{}, errors.New("未发布原记录片段名称或容量异常，未忽略")
	}
	metadata, err := remoteCopyFileMetadata(info, name, "")
	if err != nil {
		return remoteCopyFile{}, err
	}
	f, err := d.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return remoteCopyFile{}, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !programQueueSame(info, opened) {
		return remoteCopyFile{}, errors.New("原记录片段打开期间变化")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, remoteCopyRecordLimit+1))
	after, statErr := f.Stat()
	visible, visibleErr := d.Lstat(name)
	closeErr := f.Close()
	if err != nil || statErr != nil || visibleErr != nil || closeErr != nil || n != info.Size() || !programQueueSame(info, after) || !programQueueSame(info, visible) || !d.current() {
		return remoteCopyFile{}, errors.New("原记录片段读取期间变化，未返回不完整核对")
	}
	metadata.SHA = hex.EncodeToString(h.Sum(nil))
	return metadata, nil
}

// The only admitted absence is an unpublished master intent. A malformed,
// existing intent, source file, attempt directory or unknown entry retains the
// original fail-closed behavior; fragment bytes never supply copy authority.
func (s *Service) readUnpublishedRemoteCopy(target, transaction string) (remoteUnpublishedCopy, error) {
	var out remoteUnpublishedCopy
	d, err := s.remoteCopyDirectory(target, transaction, "", false)
	if err != nil {
		return out, err
	}
	defer d.Close()
	if _, err = d.Lstat("intent.json"); !errors.Is(err, os.ErrNotExist) {
		return out, errors.New("已存在原意图或不能核对缺失状态，未当作未发布片段")
	}
	dir, err := d.Stat(".")
	if err != nil || !moduleRecordInfo(dir, true, false) {
		return out, errors.New("未发布原目录身份无法核对")
	}
	st := dir.Sys().(*syscall.Stat_t)
	out.Snapshot = remoteUnpublishedSnapshot{Format: 1, TargetID: target, TransactionID: transaction, Directory: remoteUnpublishedDirectory{uint64(st.Dev), st.Ino, st.Uid, st.Gid, uint32(dir.Mode().Perm())}, Fragments: []remoteCopyFile{}}
	entries, err := remoteCopyEntries(d, remoteUnpublishedMaxParts+1)
	if err != nil {
		return out, err
	}
	names := []string{}
	for _, entry := range entries {
		name := entry.Name()
		names = append(names, name)
		if name == remoteUnpublishedReceipt {
			continue
		}
		if len(out.Snapshot.Fragments) >= remoteUnpublishedMaxParts {
			return out, errors.New("未发布原片段超过8份上限；原字节保留")
		}
		part, err := remoteUnpublishedFragment(d, name)
		if err != nil {
			return out, err
		}
		out.Snapshot.Fragments = append(out.Snapshot.Fragments, part)
		out.Bytes += part.Bytes
	}
	sort.Slice(out.Snapshot.Fragments, func(i, j int) bool { return out.Snapshot.Fragments[i].Name < out.Snapshot.Fragments[j].Name })
	out.SHA = remoteUnpublishedSHA(out.Snapshot)
	var receipt remoteUnpublishedRetention
	raw, err := remoteCopyMetadata(d, remoteUnpublishedReceipt, &receipt)
	if err == nil {
		_, atErr := time.Parse(time.RFC3339, receipt.RetainedAt)
		if receipt.Format != 1 || receipt.Version != appcatalog.FilesSyncUnpublishedRetentionVersion || receipt.SnapshotSHA != out.SHA || !reflect.DeepEqual(receipt.Snapshot, out.Snapshot) || !coreSHA.MatchString(receipt.ReviewedSpecSHA) || receipt.ReviewedRevision < 1 || receipt.ReviewedRevision > 1000000000 || atErr != nil {
			return out, errors.New("未发布片段保留回执未绑定全部原字节与目录身份")
		}
		out.Retained = &receipt
		out.Bytes += int64(len(raw))
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	latest, err := remoteCopyEntries(d, remoteUnpublishedMaxParts+1)
	current := []string{}
	for _, e := range latest {
		current = append(current, e.Name())
	}
	sort.Strings(names)
	sort.Strings(current)
	visible, statErr := d.Stat(".")
	if err != nil || statErr != nil || !os.SameFile(dir, visible) || !moduleRecordInfo(visible, true, false) || !reflect.DeepEqual(names, current) || !d.current() {
		return out, errors.New("未发布原目录清单读取期间变化")
	}
	return out, nil
}

func remoteUnpublishedPublic(v remoteUnpublishedCopy, revision int64) map[string]any {
	state, retainedAt := "unpublished-needs-review", ""
	if v.Retained != nil {
		state, retainedAt = "unpublished-retained", v.Retained.RetainedAt
	}
	files := []map[string]any{}
	for _, f := range v.Snapshot.Fragments {
		files = append(files, map[string]any{"name": f.Name, "bytes": f.Bytes, "sha256": f.SHA})
	}
	return map[string]any{"remote_target_id": v.Snapshot.TargetID, "backup_transaction_id": v.Snapshot.TransactionID, "revision": revision, "fragment_state": state, "snapshot_sha256": v.SHA, "retained_at": retainedAt, "retained_bytes": v.Bytes, "fragments": files, "root_private": true, "backup_complete": false, "source_authority": false, "downloadable": false}
}

func (s *Service) remoteUnpublishedReport(cfg remoteSyncConfig, in core.AppModuleInput) (any, error) {
	if cfg.ID != in.RemoteTargetID || cfg.Revision != in.ExpectedRevision || remoteCopyInput("remote-copy-fragments", in) != nil {
		return nil, errors.New("原片段库存查询须绑定当前连接和修订")
	}
	all, err := s.allRemoteCopyInventory()
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	for _, v := range all.Unpublished {
		if v.Snapshot.TargetID == cfg.ID {
			rows = append(rows, remoteUnpublishedPublic(v, cfg.Revision))
		}
	}
	limit := in.Limit
	if limit == 0 {
		limit = 16
	}
	start := min(in.Offset, len(rows))
	return map[string]any{"unpublished_records": rows[start:min(start+limit, len(rows))], "total": len(rows), "offset": in.Offset, "limit": limit, "global_copies": all.count(), "retained_bytes": all.Bytes, "unpublished_bytes": all.UnpublishedBytes, "remote_files_changed": false, "scope": remoteUnpublishedScope}, nil
}

func (s *Service) retainUnpublishedRemoteCopy(cfg remoteSyncConfig, in core.AppModuleInput) (any, error) {
	if cfg.ID != in.RemoteTargetID || cfg.Revision != in.ExpectedRevision || !coreSHA.MatchString(cfg.SpecSHA) || remoteCopyInput("retain-remote-copy-fragments", in) != nil {
		return nil, errors.New("原片段保留须核对当前连接、修订、完整摘要和精确确认")
	}
	all, err := s.allRemoteCopyInventory()
	if err != nil {
		return nil, err
	}
	var selected *remoteUnpublishedCopy
	for i := range all.Unpublished {
		v := &all.Unpublished[i]
		if v.Snapshot.TargetID == cfg.ID && v.Snapshot.TransactionID == in.ResourceID {
			selected = v
		}
	}
	if selected == nil || selected.SHA != in.ExpectedSHA {
		return nil, errors.New("未发布原片段完整状态摘要已变化或不是可核对的主意图缺失；原文件保留")
	}
	if selected.Retained != nil {
		if selected.Retained.ReviewedSpecSHA != cfg.SpecSHA || selected.Retained.ReviewedRevision != cfg.Revision {
			return nil, errors.New("原保留回执不属于本次连接修订，未重复写入")
		}
		return map[string]any{"unpublished_record": remoteUnpublishedPublic(*selected, cfg.Revision), "replayed": true, "original_fragments_preserved": true, "backup_complete": false, "remote_files_changed": false, "scope": remoteUnpublishedScope}, nil
	}
	if len(selected.Snapshot.Fragments) >= remoteUnpublishedMaxParts || all.UnpublishedBytes > remoteUnpublishedMaxMetadataBytes-remoteCopyRecordLimit {
		return nil, errors.New("保留回执需要额外片段与容量余量；已达上限，原记录不自动删除或覆盖")
	}
	d, err := s.remoteCopyDirectory(cfg.ID, in.ResourceID, "", false)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	if err = remoteCopyFreeSpace(d, remoteCopyRecordLimit); err != nil {
		return nil, err
	}
	current, err := s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID)
	if err != nil || current.SHA != selected.SHA || current.Retained != nil {
		return nil, errors.New("原片段状态在写入前变化；未追加保留回执")
	}
	receipt := remoteUnpublishedRetention{Format: 1, Version: appcatalog.FilesSyncUnpublishedRetentionVersion, Snapshot: current.Snapshot, SnapshotSHA: current.SHA, ReviewedSpecSHA: cfg.SpecSHA, ReviewedRevision: cfg.Revision, RetainedAt: core.Now()}
	if _, err = remoteCopyPublish(d, remoteUnpublishedReceipt, receipt); err != nil {
		return nil, err
	}
	current, err = s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID)
	if err != nil || current.Retained == nil {
		return nil, errors.New("原保留回执尚未完整核对；原片段和结果保留，不能视为未执行")
	}
	return map[string]any{"unpublished_record": remoteUnpublishedPublic(current, cfg.Revision), "original_fragments_preserved": true, "backup_complete": false, "remote_files_changed": false, "scope": remoteUnpublishedScope}, nil
}
