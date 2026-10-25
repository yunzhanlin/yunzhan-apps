//go:build linux

package executor

import (
	"errors"
	"local/panel/internal/core"
	"os"
	"path"
	"reflect"
	"sort"

	"github.com/pkg/sftp"
)

const remoteBackupTransactions = 512
const remoteBackupBytes int64 = 256 << 20
const remoteBackupReserve int64 = 16 << 20

func remoteBackupOwnedFile(st os.FileInfo, owner uint32) bool {
	a, ok := st.Sys().(*sftp.FileStat)
	return ok && a.UID == owner && st.Mode().IsRegular() && st.Mode()&os.ModeType == 0 && st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && st.Size() >= 0 && st.Size() <= 8<<20
}

type remoteBackupFile struct {
	Name string `json:"name"`
	Size int64  `json:"bytes"`
	Mode uint32 `json:"mode"`
}
type remoteBackupTransaction struct {
	ID       string             `json:"backup_transaction_id"`
	TargetID string             `json:"remote_target_id"`
	Revision int64              `json:"revision"`
	Bytes    int64              `json:"backup_bytes"`
	Files    []remoteBackupFile `json:"backup_files"`
	Pending  bool               `json:"pending_recovery"`
}

// Read-only inventory includes an exactly full namespace. Unlike admission,
// inspection must not fail merely because no further transaction fits. Unknown
// children, links and foreign owners are never silently omitted from the total.
func remoteBackupInventory(c *remoteSyncClient, cfg remoteSyncConfig, owner uint32) ([]remoteBackupTransaction, int64, error) {
	base := path.Join(cfg.Target.BackupRoot, "yunzhan-sync-"+cfg.ID)
	if _, err := c.Lstat(base); errors.Is(err, os.ErrNotExist) {
		return []remoteBackupTransaction{}, 0, nil
	} else if err != nil {
		return nil, 0, err
	}
	if err := remoteDirCheck(c, base, &owner, true); err != nil {
		return nil, 0, err
	}
	entries, err := c.ReadDir(base)
	if err != nil {
		return nil, 0, err
	}
	rows := make([]remoteBackupTransaction, 0, len(entries))
	var total int64
	for _, entry := range entries {
		attrs, ok := entry.Sys().(*sftp.FileStat)
		if !core.ValidID(entry.Name()) || !entry.IsDir() || entry.Mode().Perm() != 0700 || !ok || attrs.UID != owner {
			return nil, 0, errors.New("远端事务目录身份不可核对，未返回不完整容量")
		}
		dir := path.Join(base, entry.Name())
		if err := remoteDirCheck(c, dir, &owner, true); err != nil {
			return nil, 0, err
		}
		children, err := c.ReadDir(dir)
		if err != nil {
			return nil, 0, err
		}
		if len(children) > 2 {
			return nil, 0, errors.New("远端事务含未知条目，未返回不完整容量")
		}
		row := remoteBackupTransaction{ID: entry.Name(), TargetID: cfg.ID, Revision: cfg.Revision, Files: []remoteBackupFile{}}
		for _, child := range children {
			a, ok := child.Sys().(*sftp.FileStat)
			if (child.Name() != "staged" && child.Name() != "previous") || !child.Mode().IsRegular() || child.Mode()&os.ModeSymlink != 0 || child.Size() < 0 || child.Size() > 8<<20 || !ok || a.UID != owner || child.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
				return nil, 0, errors.New("远端备份文件身份、权限或容量异常")
			}
			if total > remoteBackupBytes-child.Size() {
				return nil, 0, errors.New("远端备份超过 256 MiB，保留全部证据")
			}
			total += child.Size()
			row.Bytes += child.Size()
			row.Files = append(row.Files, remoteBackupFile{child.Name(), child.Size(), uint32(child.Mode().Perm())})
		}
		sort.Slice(row.Files, func(i, j int) bool { return row.Files[i].Name < row.Files[j].Name })
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, total, nil
}

func remoteBackupInput(in core.AppModuleInput) error {
	rest := in
	rest.RemoteTargetID = ""
	rest.ExpectedRevision = 0
	rest.Limit = 0
	rest.Offset = 0
	if !reflect.DeepEqual(rest, core.AppModuleInput{}) || in.Limit < 0 || in.Limit > 32 || in.Offset < 0 || in.Offset > remoteBackupTransactions {
		return errors.New("容量查询只接受所选连接、当前修订号和有界分页，不接受认证材料、路径或同步策略")
	}
	return nil
}
func (s *Service) remoteBackupReport(c *remoteSyncClient, cfg remoteSyncConfig, in core.AppModuleInput) (any, error) {
	if err := remoteBackupInput(in); err != nil {
		return nil, err
	}
	if in.ExpectedRevision != cfg.Revision {
		return nil, errors.New("连接修订号改变，请重新选择连接")
	}
	owner, err := remoteRoots(c, cfg)
	if err != nil {
		return nil, err
	}
	cp, err := s.readRemoteCheckpoint(cfg, "")
	if err != nil {
		return nil, err
	}
	rows, total, err := remoteBackupInventory(c, cfg, owner)
	if err != nil {
		return nil, err
	}
	archivePending, err := s.remoteBackupArchivePending(cfg.ID)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].Pending = cp.Pending != nil && rows[i].ID == cp.Pending.ID
	}
	limit := in.Limit
	if limit == 0 {
		limit = 16
	}
	start := min(in.Offset, len(rows))
	end := min(start+limit, len(rows))
	return map[string]any{"remote_backups": rows[start:end], "remote_target_id": cfg.ID, "revision": cfg.Revision, "total": len(rows), "backup_bytes": total, "transaction_limit": remoteBackupTransactions, "byte_limit": remoteBackupBytes, "transaction_slots_available": remoteBackupTransactions - len(rows), "bytes_available": remoteBackupBytes - total, "next_transaction_capacity_available": len(rows) < remoteBackupTransactions && total <= remoteBackupBytes-remoteBackupReserve, "pending_recovery": cp.Pending != nil, "pending_archive_recovery": archivePending, "limit": limit, "offset": in.Offset, "remote_files_changed": false, "scope": "只读核对远端实际事务库存与容量，不执行同步、归档或删除，不返回文件内容、密码或私钥。最多 512 份事务、256 MiB；每次交接预留 16 MiB。正好满额仍可查询；未知条目、链接或异主目录拒绝返回不完整统计。容量是受限 SFTP 元数据查询，不是磁盘硬配额，也不保证并发外部写入后的容量。有容量不代表可以传输：文件交接或备份归档待恢复时仍安全暂停。受控归档须暂停计划、完整摘要核对与精确确认，归档库存单独查询，不自动删除。"}, nil
}
