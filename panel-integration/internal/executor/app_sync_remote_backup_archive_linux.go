//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

const remoteBackupArchiveMax = 512
const remoteBackupArchiveBytes int64 = 1 << 30
const remoteBackupArchiveScope = "受控迁移实际远端事务目录，保留全部字节、权限、硬链接和原事务身份；不删除备份、不改公开目标、检查点或同步任务。每个连接归档最多 512 份、1 GiB 逻辑字节，不是磁盘硬配额。先暂停该连接计划、核对原任务和完整文件摘要，再明确确认；中断仅显式恢复，未核对前拒绝新传输和连接改写。硬链接暂存仍可能随公开目标的外部写入改变，不是独立不可变快照。仅支持可信 Linux/OpenSSH 同文件系统、协作的非 root SFTP 账户；目录重命名不是内核条件式无覆盖，不防御同账户恶意并发替换。"

type remoteBackupArchiveFile struct {
	Name string     `json:"name"`
	File moduleFile `json:"file"`
}
type remoteBackupSnapshot struct {
	TargetID      string                    `json:"remote_target_id"`
	TransactionID string                    `json:"backup_transaction_id"`
	Revision      int64                     `json:"revision"`
	SpecSHA       string                    `json:"spec_sha256"`
	Owner         uint32                    `json:"owner"`
	Files         []remoteBackupArchiveFile `json:"files"`
}
type remoteBackupArchiveRecord struct {
	Snapshot    remoteBackupSnapshot `json:"snapshot"`
	SHA         string               `json:"snapshot_sha256"`
	State       string               `json:"state"`
	CreatedAt   string               `json:"created_at"`
	CompletedAt string               `json:"completed_at,omitempty"`
}

func remoteBackupSnapshotSHA(v remoteBackupSnapshot) string {
	b, _ := json.Marshal(v)
	return core.Hash(string(b))
}
func remoteBackupSnapshotBytes(v remoteBackupSnapshot) int64 {
	var n int64
	for _, f := range v.Files {
		n += f.File.Size
	}
	return n
}
func (s *Service) remoteBackupArchiveRecordPath(target, id string) string {
	return filepath.Join(s.remoteSyncDir(), "backup-archive", target, id+".json")
}
func remoteBackupArchivePaths(cfg remoteSyncConfig, id string) (base, container, destination string) {
	base = path.Join(cfg.Target.BackupRoot, "yunzhan-backup-archive-"+cfg.ID)
	container = path.Join(base, id)
	destination = path.Join(container, "files")
	return
}
func validateRemoteBackupArchiveRecord(r remoteBackupArchiveRecord, target, id string) error {
	v := r.Snapshot
	if !syncPlanID.MatchString(target) || !core.ValidID(id) || v.TargetID != target || v.TransactionID != id || v.Revision < 1 || !coreSHA.MatchString(v.SpecSHA) || v.Owner == 0 || len(v.Files) > 2 || v.Files == nil || r.SHA != remoteBackupSnapshotSHA(v) {
		return errors.New("远端备份归档记录身份或摘要损坏，保留原记录")
	}
	for i, f := range v.Files {
		if (f.Name != "previous" && f.Name != "staged") || !validRemoteFile(f.File) || i > 0 && v.Files[i-1].Name >= f.Name {
			return errors.New("远端归档文件记录不可核对")
		}
	}
	created, err := time.Parse(time.RFC3339, r.CreatedAt)
	if err != nil {
		return errors.New("远端归档时间无效")
	}
	switch r.State {
	case "prepared", "reserved":
		if r.CompletedAt != "" {
			return errors.New("未提交归档含完成时间")
		}
	case "committed":
		finished, err := time.Parse(time.RFC3339, r.CompletedAt)
		if err != nil || finished.Before(created) {
			return errors.New("远端归档完成时间无效")
		}
	default:
		return errors.New("远端归档阶段无效")
	}
	return nil
}
func (s *Service) readRemoteBackupArchiveRecord(target, id string) (remoteBackupArchiveRecord, error) {
	var r remoteBackupArchiveRecord
	if !syncPlanID.MatchString(target) || !core.ValidID(id) {
		return r, errors.New("远端归档标识无效")
	}
	if err := remoteRead(s.remoteBackupArchiveRecordPath(target, id), &r); err != nil {
		return r, err
	}
	return r, validateRemoteBackupArchiveRecord(r, target, id)
}

// Every local record remains reserved forever; archive replay cannot make a
// transaction ID eligible for a second move. Missing records in unsafe parent
// namespaces are never treated as a fresh operation.
func (s *Service) allRemoteBackupArchiveRecords(target string) ([]remoteBackupArchiveRecord, error) {
	if !syncPlanID.MatchString(target) {
		return nil, errors.New("远端归档连接标识无效")
	}
	base := filepath.Join(s.remoteSyncDir(), "backup-archive")
	if _, err := os.Lstat(base); errors.Is(err, os.ErrNotExist) {
		return []remoteBackupArchiveRecord{}, nil
	} else if err != nil {
		return nil, err
	}
	for _, dir := range []string{s.remoteSyncDir(), base} {
		if err := remotePrivateDirectory(dir); err != nil {
			return nil, err
		}
	}
	targets, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	if len(targets) > 16 {
		return nil, errors.New("远端归档连接目录超限")
	}
	for _, entry := range targets {
		if !syncPlanID.MatchString(entry.Name()) || !entry.IsDir() {
			return nil, errors.New("远端归档根目录含未知条目")
		}
		if err = remotePrivateDirectory(filepath.Join(base, entry.Name())); err != nil {
			return nil, err
		}
	}
	dir := filepath.Join(base, target)
	if _, err = os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return []remoteBackupArchiveRecord{}, nil
	} else if err != nil {
		return nil, err
	}
	if err = remotePrivateDirectory(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > remoteBackupArchiveMax {
		return nil, errors.New("归档记录超过 512 份，未返回不完整库存")
	}
	rows := make([]remoteBackupArchiveRecord, 0, len(entries))
	var bytes int64
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !core.ValidID(id) {
			return nil, errors.New("远端归档目录含未知记录")
		}
		st, err := os.Lstat(s.remoteBackupArchiveRecordPath(target, id))
		if err != nil {
			return nil, err
		}
		if st.Size() > 8192 || st.Size() < 0 {
			return nil, errors.New("远端归档记录过大")
		}
		r, err := s.readRemoteBackupArchiveRecord(target, id)
		if err != nil {
			return nil, err
		}
		n := remoteBackupSnapshotBytes(r.Snapshot)
		if bytes > remoteBackupArchiveBytes-n {
			return nil, errors.New("远端归档记录超过 1 GiB 逻辑字节")
		}
		bytes += n
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Snapshot.TransactionID < rows[j].Snapshot.TransactionID })
	return rows, nil
}
func (s *Service) remoteBackupArchivePending(target string) (bool, error) {
	rows, err := s.allRemoteBackupArchiveRecords(target)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.State != "committed" {
			return true, nil
		}
	}
	return false, nil
}
func (s *Service) remoteBackupArchiveIdle(cfg remoteSyncConfig, allowID string) error {
	jobs, err := s.allRemoteJobs()
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if j.TargetID == cfg.ID && (j.State == "running" || j.State == "queued") {
			return errors.New("同步仍执行或排队，归档未修改远端")
		}
	}
	cp, err := s.readRemoteCheckpoint(cfg, "")
	if err != nil {
		return err
	}
	if cp.Pending != nil {
		return errors.New("先恢复原文件交接，归档未修改远端")
	}
	plans, err := s.allRemotePlans()
	if err != nil {
		return err
	}
	for _, p := range plans {
		if p.TargetID == cfg.ID && p.Enabled {
			return errors.New("先暂停计划并核对原任务，归档未修改远端")
		}
	}
	rows, err := s.allRemoteBackupArchiveRecords(cfg.ID)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.State != "committed" && r.Snapshot.TransactionID != allowID {
			return errors.New("先显式恢复原备份归档，不接收另一归档")
		}
	}
	return nil
}
func remoteBackupArchiveInput(action string, in core.AppModuleInput) error {
	rest := in
	rest.RemoteTargetID = ""
	rest.ExpectedRevision = 0
	if action == "remote-backup-archive" {
		rest.Limit = 0
		rest.Offset = 0
		if in.Limit < 0 || in.Limit > 32 || in.Offset < 0 || in.Offset > remoteBackupArchiveMax {
			return errors.New("归档库存分页超限")
		}
	} else {
		rest.ResourceID = ""
		if !core.ValidID(in.ResourceID) {
			return errors.New("请选择原备份事务标识")
		}
		if action == "archive-remote-backup" || action == "recover-remote-backup" {
			rest.ExpectedSHA = ""
			rest.Confirm = ""
			prefix := "ARCHIVE BACKUP "
			if action == "recover-remote-backup" {
				prefix = "RECOVER BACKUP "
			}
			if !coreSHA.MatchString(in.ExpectedSHA) || in.Confirm != prefix+in.ResourceID {
				return errors.New("归档或恢复须完整摘要和精确确认")
			}
		}
	}
	if !reflect.DeepEqual(rest, core.AppModuleInput{}) {
		return errors.New("备份维护只接受所选连接、当前修订、原事务标识、摘要与精确确认，不接受路径、凭据或同步策略")
	}
	return nil
}
func remoteBackupSnapshotAt(c *remoteSyncClient, cfg remoteSyncConfig, dir, id string, owner uint32) (remoteBackupSnapshot, error) {
	v := remoteBackupSnapshot{TargetID: cfg.ID, TransactionID: id, Revision: cfg.Revision, SpecSHA: cfg.SpecSHA, Owner: owner, Files: []remoteBackupArchiveFile{}}
	if err := remoteDirCheck(c, dir, &owner, true); err != nil {
		return v, err
	}
	entries, err := c.ReadDir(dir)
	if err != nil {
		return v, err
	}
	if len(entries) > 2 {
		return v, errors.New("备份事务含未知条目")
	}
	for _, e := range entries {
		if e.Name() != "previous" && e.Name() != "staged" {
			return v, errors.New("备份事务含未知文件，不迁移证据")
		}
		p := path.Join(dir, e.Name())
		st, err := c.Lstat(p)
		if err != nil {
			return v, err
		}
		if !remoteBackupOwnedFile(st, owner) {
			return v, errors.New("备份文件身份异常，不迁移证据")
		}
		f, exists, err := remoteFileDigest(c, p)
		if err != nil || !exists {
			return v, errors.New("备份内容不可核对，不迁移证据")
		}
		after, err := c.Lstat(p)
		if err != nil || !remoteBackupOwnedFile(after, owner) {
			return v, errors.New("备份读取后所有者或身份改变")
		}
		v.Files = append(v.Files, remoteBackupArchiveFile{e.Name(), f})
	}
	sort.Slice(v.Files, func(i, j int) bool { return v.Files[i].Name < v.Files[j].Name })
	final, err := c.ReadDir(dir)
	if err != nil || len(final) != len(v.Files) {
		return v, errors.New("备份读取期间目录内容改变")
	}
	names := map[string]bool{}
	for _, e := range final {
		names[e.Name()] = true
	}
	for _, f := range v.Files {
		if !names[f.Name] {
			return v, errors.New("备份读取期间文件身份改变")
		}
	}
	return v, nil
}
func remoteBackupSnapshotMatches(c *remoteSyncClient, cfg remoteSyncConfig, dir string, r remoteBackupArchiveRecord) error {
	v, err := remoteBackupSnapshotAt(c, cfg, dir, r.Snapshot.TransactionID, r.Snapshot.Owner)
	if err != nil {
		return err
	}
	v.Revision = r.Snapshot.Revision
	if !reflect.DeepEqual(v, r.Snapshot) {
		return errors.New("当前备份与已审查完整摘要不同，保留两处内容")
	}
	return nil
}
func remoteBackupArchivePublic(r remoteBackupArchiveRecord, revision int64) map[string]any {
	return map[string]any{"backup_transaction_id": r.Snapshot.TransactionID, "remote_target_id": r.Snapshot.TargetID, "revision": revision, "backup_bytes": remoteBackupSnapshotBytes(r.Snapshot), "backup_snapshot_sha256": r.SHA, "backup_archive_state": r.State, "created_at": r.CreatedAt, "completed_at": r.CompletedAt, "pending_recovery": r.State != "committed", "content_verified": false}
}

// A native mkdir with remote umask 022 may succeed before a lost reply/kill
// prevents chmod. Only a journal-bound PREPARED, same-owner, canonical, EMPTY
// 0755 directory inside the already-private BackupRoot is recognizable here.
// Read-only inventory never repairs it. Committed/nonempty/foreign namespaces
// retain the strict 0700 check; explicit recovery rechecks original bytes first.
func remoteBackupPreparingDirectory(c *remoteSyncClient, dir string, owner uint32, prepared bool) (bool, error) {
	if !prepared {
		return false, remoteDirCheck(c, dir, &owner, true)
	}
	if err := remoteDirCheck(c, dir, &owner, false); err != nil {
		return false, err
	}
	st, err := c.Lstat(dir)
	if err != nil {
		return false, err
	}
	if st.Mode().Perm() == 0700 {
		return false, nil
	}
	if !prepared || st.Mode().Perm() != 0755 {
		return false, errors.New("归档目录权限不是 0700，未接管或修改")
	}
	children, err := c.ReadDir(dir)
	if err != nil || len(children) != 0 {
		return false, errors.New("准备阶段的宽权限归档目录非空或不可核对，未接管")
	}
	return true, nil
}

// Inventory has already checked the full canonical parent chain. Check each
// immediate child using fresh lstat + realpath, rather than re-reading every
// ancestor twice for each of 512 transactions. This keeps all identity/link/
// permission checks within the bounded query. Like directory Rename, this is
// scoped to a cooperative trusted account, not malicious same-account races.
func remoteBackupArchiveInventoryChild(c *remoteSyncClient, parent, dir string, owner uint32, prepared bool) error {
	if path.Dir(dir) != parent || path.Base(dir) == "." || path.Base(dir) == ".." {
		return errors.New("归档库存不是已核对目录的直接子项")
	}
	st, err := c.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("归档库存子项不存在、包含链接或不是目录")
	}
	attrs, ok := st.Sys().(*sftp.FileStat)
	if !ok || owner == 0 || attrs.UID != owner {
		return errors.New("归档库存子目录不是同一非 root 所有者")
	}
	canonical, err := c.RealPath(dir)
	if err != nil || canonical != dir {
		return errors.New("归档库存子目录规范路径改变")
	}
	if st.Mode().Perm() == 0700 {
		return nil
	}
	if prepared && st.Mode().Perm() == 0755 {
		children, err := c.ReadDir(dir)
		if err == nil && len(children) == 0 {
			return nil
		}
	}
	return errors.New("归档库存子目录权限异常或准备容器非空，未接管")
}

func remoteBackupAllPrepared(rows []remoteBackupArchiveRecord) bool {
	if len(rows) == 0 {
		return false
	}
	for _, r := range rows {
		if r.State != "prepared" {
			return false
		}
	}
	return true
}

// Capacity accounting reads all actual containers, not just the requested
// page. Unknown/foreign entries and missing committed archives fail closed.
func (s *Service) remoteBackupArchiveInventory(c *remoteSyncClient, cfg remoteSyncConfig, owner uint32) ([]remoteBackupArchiveRecord, int64, error) {
	rows, err := s.allRemoteBackupArchiveRecords(cfg.ID)
	if err != nil {
		return nil, 0, err
	}
	known := map[string]remoteBackupArchiveRecord{}
	for _, r := range rows {
		if r.Snapshot.SpecSHA != cfg.SpecSHA || r.Snapshot.Owner != owner || r.Snapshot.Revision > cfg.Revision {
			return nil, 0, errors.New("归档记录与当前远端身份不符")
		}
		known[r.Snapshot.TransactionID] = r
	}
	base, _, _ := remoteBackupArchivePaths(cfg, core.ID())
	_, err = c.Lstat(base)
	if errors.Is(err, os.ErrNotExist) {
		for _, r := range rows {
			if r.State != "prepared" {
				return nil, 0, errors.New("已预留或提交的远端归档目录丢失")
			}
		}
		return rows, 0, nil
	} else if err != nil {
		return nil, 0, err
	}
	if _, err = remoteBackupPreparingDirectory(c, base, owner, remoteBackupAllPrepared(rows)); err != nil {
		return nil, 0, err
	}
	entries, err := c.ReadDir(base)
	if err != nil {
		return nil, 0, err
	}
	var total int64
	seen := map[string]bool{}
	for _, entry := range entries {
		r, ok := known[entry.Name()]
		if !ok {
			return nil, 0, errors.New("远端归档含未登记的事务，未返回不完整库存")
		}
		seen[entry.Name()] = true
		_, container, destination := remoteBackupArchivePaths(cfg, entry.Name())
		if err = remoteBackupArchiveInventoryChild(c, base, container, owner, r.State == "prepared"); err != nil {
			return nil, 0, err
		}
		children, err := c.ReadDir(container)
		if err != nil {
			return nil, 0, err
		}
		if len(children) == 0 && r.State != "committed" {
			continue
		}
		if len(children) != 1 || children[0].Name() != "files" {
			return nil, 0, errors.New("远端归档容器含未知条目或已提交文件丢失")
		}
		if err = remoteBackupArchiveInventoryChild(c, container, destination, owner, false); err != nil {
			return nil, 0, err
		}
		files, err := c.ReadDir(destination)
		if err != nil {
			return nil, 0, err
		}
		if len(files) > 2 {
			return nil, 0, errors.New("归档事务含未知条目")
		}
		if len(files) != len(r.Snapshot.Files) {
			return nil, 0, errors.New("远端归档文件数量与原记录不同")
		}
		for _, f := range files {
			if (f.Name() != "previous" && f.Name() != "staged") || !remoteBackupOwnedFile(f, owner) {
				return nil, 0, errors.New("远端归档文件身份异常")
			}
			matched := false
			for _, expected := range r.Snapshot.Files {
				if expected.Name == f.Name() && expected.File.Size == f.Size() && expected.File.Mode == uint32(f.Mode().Perm()) {
					matched = true
				}
			}
			if !matched {
				return nil, 0, errors.New("远端归档元数据与原记录不同")
			}
			if total > remoteBackupArchiveBytes-f.Size() {
				return nil, 0, errors.New("远端归档超过 1 GiB 逻辑字节")
			}
			total += f.Size()
		}
	}
	for _, r := range rows {
		if !seen[r.Snapshot.TransactionID] && r.State != "prepared" {
			return nil, 0, errors.New("已预留或提交的远端归档事务丢失")
		}
	}
	return rows, total, nil
}
func (s *Service) remoteBackupArchiveReport(c *remoteSyncClient, cfg remoteSyncConfig, in core.AppModuleInput, owner uint32) (any, error) {
	rows, total, err := s.remoteBackupArchiveInventory(c, cfg, owner)
	if err != nil {
		return nil, err
	}
	limit := in.Limit
	if limit == 0 {
		limit = 16
	}
	start := min(in.Offset, len(rows))
	end := min(start+limit, len(rows))
	out := []map[string]any{}
	for _, r := range rows[start:end] {
		out = append(out, remoteBackupArchivePublic(r, cfg.Revision))
	}
	return map[string]any{"remote_backup_archive": out, "total": len(rows), "archive_bytes": total, "transaction_limit": remoteBackupArchiveMax, "byte_limit": remoteBackupArchiveBytes, "limit": limit, "offset": in.Offset, "remote_files_changed": false, "content_verified": false, "scope": remoteBackupArchiveScope}, nil
}
func (s *Service) remoteBackupArchivePreview(c *remoteSyncClient, cfg remoteSyncConfig, in core.AppModuleInput, owner uint32) (any, error) {
	r, err := s.readRemoteBackupArchiveRecord(cfg.ID, in.ResourceID)
	if err == nil {
		if r.Snapshot.SpecSHA != cfg.SpecSHA || r.Snapshot.Owner != owner {
			return nil, errors.New("原归档身份与连接不符")
		}
		if _, _, err = s.remoteBackupArchiveInventory(c, cfg, owner); err != nil {
			return nil, err
		}
		_, _, destination := remoteBackupArchivePaths(cfg, in.ResourceID)
		source := path.Join(cfg.Target.BackupRoot, "yunzhan-sync-"+cfg.ID, in.ResourceID)
		_, sourceErr := c.Lstat(source)
		_, destinationErr := c.Lstat(destination)
		if sourceErr != nil && !errors.Is(sourceErr, os.ErrNotExist) {
			return nil, sourceErr
		}
		if destinationErr != nil && !errors.Is(destinationErr, os.ErrNotExist) {
			return nil, destinationErr
		}
		location := source
		if sourceErr == nil && errors.Is(destinationErr, os.ErrNotExist) && r.State != "committed" {
		} else if errors.Is(sourceErr, os.ErrNotExist) && destinationErr == nil {
			location = destination
		} else {
			return nil, errors.New("原备份和归档位置状态不唯一，未核对内容")
		}
		if err = remoteBackupSnapshotMatches(c, cfg, location, r); err != nil {
			return nil, err
		}
		row := remoteBackupArchivePublic(r, cfg.Revision)
		row["content_verified"] = true
		return map[string]any{"backup_maintenance": row, "remote_files_changed": false, "scope": remoteBackupArchiveScope}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err = s.remoteBackupArchiveIdle(cfg, ""); err != nil {
		return nil, err
	}
	if _, _, err = remoteBackupInventory(c, cfg, owner); err != nil {
		return nil, err
	}
	if _, _, err = s.remoteBackupArchiveInventory(c, cfg, owner); err != nil {
		return nil, err
	}
	v, err := remoteBackupSnapshotAt(c, cfg, path.Join(cfg.Target.BackupRoot, "yunzhan-sync-"+cfg.ID, in.ResourceID), in.ResourceID, owner)
	if err != nil {
		return nil, err
	}
	r = remoteBackupArchiveRecord{Snapshot: v, SHA: remoteBackupSnapshotSHA(v), State: "prepared", CreatedAt: core.Now()}
	row := remoteBackupArchivePublic(r, cfg.Revision)
	row["backup_archive_state"] = "reviewed"
	row["content_verified"] = true
	row["pending_recovery"] = false
	return map[string]any{"backup_maintenance": row, "remote_files_changed": false, "scope": remoteBackupArchiveScope}, nil
}

// Only explicit archive/recovery reaches this function. A durable local intent
// precedes the first remote mutation. Recovery derives source/destination
// presence and verifies original bytes; it never issues a second move after a
// committed/lost reply. No Remove, PosixRename, shell or SSH exec fallback.
func (s *Service) archiveRemoteBackup(c *remoteSyncClient, cfg remoteSyncConfig, in core.AppModuleInput, owner uint32, recover bool) (any, error) {
	r, err := s.readRemoteBackupArchiveRecord(cfg.ID, in.ResourceID)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if recover && !exists {
		return nil, errors.New("无原归档记录，不猜测恢复")
	}
	if exists {
		if r.SHA != in.ExpectedSHA || r.Snapshot.SpecSHA != cfg.SpecSHA || r.Snapshot.Owner != owner {
			return nil, errors.New("原归档摘要或身份改变，未迁移")
		}
		if r.State != "committed" && !recover {
			return nil, errors.New("原归档未提交，请按原摘要显式恢复，不重新提交")
		}
	}
	if err = s.remoteBackupArchiveIdle(cfg, in.ResourceID); err != nil {
		return nil, err
	}
	rows, total, err := s.remoteBackupArchiveInventory(c, cfg, owner)
	if err != nil {
		return nil, err
	}
	base, container, destination := remoteBackupArchivePaths(cfg, in.ResourceID)
	source := path.Join(cfg.Target.BackupRoot, "yunzhan-sync-"+cfg.ID, in.ResourceID)
	if !exists {
		if _, _, err = remoteBackupInventory(c, cfg, owner); err != nil {
			return nil, err
		}
		if len(rows) >= remoteBackupArchiveMax {
			return nil, errors.New("远端备份归档已达 512 份，不自动删除")
		}
		if _, err = c.Lstat(container); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("远端归档标识已存在或不能核对，未接管")
		}
		v, err := remoteBackupSnapshotAt(c, cfg, source, in.ResourceID, owner)
		if err != nil {
			return nil, err
		}
		if remoteBackupSnapshotSHA(v) != in.ExpectedSHA {
			return nil, errors.New("已审查备份内容改变，未迁移")
		}
		if total > remoteBackupArchiveBytes-remoteBackupSnapshotBytes(v) {
			return nil, errors.New("远端归档 1 GiB 预算不足，不自动删除证据")
		}
		r = remoteBackupArchiveRecord{Snapshot: v, SHA: in.ExpectedSHA, State: "prepared", CreatedAt: core.Now()}
		if err = moduleWrite(s.remoteBackupArchiveRecordPath(cfg.ID, in.ResourceID), r); err != nil {
			return nil, err
		}
		if _, err = s.readRemoteBackupArchiveRecord(cfg.ID, in.ResourceID); err != nil {
			return nil, err
		}
	}
	if r.State == "committed" {
		if _, err = c.Lstat(source); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("已归档原标识在活动目录重现，保留两处内容")
		}
		if err = remoteBackupSnapshotMatches(c, cfg, destination, r); err != nil {
			return nil, err
		}
		row := remoteBackupArchivePublic(r, cfg.Revision)
		row["content_verified"] = true
		return map[string]any{"backup_maintenance": row, "replayed": true, "remote_files_changed": false, "scope": remoteBackupArchiveScope}, nil
	}
	if _, err = c.Lstat(base); errors.Is(err, os.ErrNotExist) {
		if err = c.Mkdir(base); err != nil {
			return nil, err
		}
		if err = c.Chmod(base, 0700); err != nil {
			return nil, err
		}
		if err = remoteSyncDirectory(c, cfg.Target.BackupRoot); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	// An acknowledged mkdir can be followed by a lost reply before chmod.
	// Repair only after explicit recovery and original-source digest validation.
	fixBase, err := remoteBackupPreparingDirectory(c, base, owner, r.State == "prepared" && remoteBackupAllPrepared(append(rows, r)))
	if err != nil {
		return nil, err
	}
	if fixBase {
		if !recover || remoteBackupSnapshotMatches(c, cfg, source, r) != nil {
			return nil, errors.New("准备目录权限待核对，只能按原摘要显式恢复")
		}
		if err = c.Chmod(base, 0700); err != nil {
			return nil, err
		}
		if err = remoteSyncDirectory(c, cfg.Target.BackupRoot); err != nil {
			return nil, err
		}
	}
	if err = remoteDirCheck(c, base, &owner, true); err != nil {
		return nil, err
	}
	if _, err = c.Lstat(container); errors.Is(err, os.ErrNotExist) {
		if r.State != "prepared" {
			return nil, errors.New("原预留归档容器丢失，不重新创建")
		}
		if err = c.Mkdir(container); err != nil {
			return nil, err
		}
		if err = c.Chmod(container, 0700); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	fixContainer, err := remoteBackupPreparingDirectory(c, container, owner, r.State == "prepared")
	if err != nil {
		return nil, err
	}
	if fixContainer {
		if !recover || remoteBackupSnapshotMatches(c, cfg, source, r) != nil {
			return nil, errors.New("准备容器权限待核对，只能按原摘要显式恢复")
		}
		if err = c.Chmod(container, 0700); err != nil {
			return nil, err
		}
	}
	if err = remoteDirCheck(c, container, &owner, true); err != nil {
		return nil, err
	}
	children, err := c.ReadDir(container)
	if err != nil {
		return nil, err
	}
	_, sourceErr := c.Lstat(source)
	sourceExists := sourceErr == nil
	if sourceErr != nil && !errors.Is(sourceErr, os.ErrNotExist) {
		return nil, sourceErr
	}
	if len(children) == 0 && sourceExists {
		if err = remoteBackupSnapshotMatches(c, cfg, source, r); err != nil {
			return nil, err
		}
		if total > remoteBackupArchiveBytes-remoteBackupSnapshotBytes(r.Snapshot) {
			return nil, errors.New("归档恢复时预算不足，保留原事务")
		}
		if err = remoteSyncDirectory(c, container); err != nil {
			return nil, err
		}
		if err = remoteSyncDirectory(c, base); err != nil {
			return nil, err
		}
		r.State = "reserved"
		if err = moduleWrite(s.remoteBackupArchiveRecordPath(cfg.ID, in.ResourceID), r); err != nil {
			return nil, err
		}
		// Destination is a previously absent child in an exclusive random-ID
		// container. SFTP v3 directory Rename is not RENAME_NOREPLACE; the
		// cooperative remote-account boundary is explicit in the report.
		if _, err = c.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("归档目标已存在，未覆盖")
		}
		if err = c.Rename(source, destination); err != nil {
			return nil, errors.New("远端归档迁移回执失败，保留原记录并显式恢复")
		}
	} else if len(children) != 1 || children[0].Name() != "files" || sourceExists {
		return nil, errors.New("原备份和归档位置状态不唯一，保留两处内容")
	}
	if err = remoteBackupSnapshotMatches(c, cfg, destination, r); err != nil {
		return nil, err
	}
	if _, err = c.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("归档后活动事务重现，未确认完成")
	}
	for _, dir := range []string{destination, container, base, path.Dir(source)} {
		if err = remoteSyncDirectory(c, dir); err != nil {
			return nil, err
		}
	}
	r.State = "committed"
	r.CompletedAt = core.Now()
	if err = moduleWrite(s.remoteBackupArchiveRecordPath(cfg.ID, in.ResourceID), r); err != nil {
		return nil, err
	}
	row := remoteBackupArchivePublic(r, cfg.Revision)
	row["content_verified"] = true
	return map[string]any{"backup_maintenance": row, "recovered": recover, "remote_files_changed": true, "scope": remoteBackupArchiveScope}, nil
}
