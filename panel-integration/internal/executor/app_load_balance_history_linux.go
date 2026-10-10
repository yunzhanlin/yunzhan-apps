//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

const loadBalanceActiveTransactions = 512
const loadBalanceArchivedTransactions = 2048
const loadBalanceArchiveBytes int64 = 256 << 20

type loadBalanceHistoryRow struct {
	ID         string `json:"transaction_id"`
	Domain     string `json:"domain"`
	State      string `json:"transaction_state"`
	CreatedAt  string `json:"created_at"`
	Format     int    `json:"transaction_format"`
	Files      int    `json:"transaction_files"`
	SHA        string `json:"transaction_sha256"`
	Bytes      int64  `json:"transaction_bytes"`
	Archived   bool   `json:"transaction_archived"`
	Archivable bool   `json:"transaction_archivable"`
}

func (s *Service) loadBalanceArchiveDir() string {
	return filepath.Join(s.moduleDir("load-balance"), "transaction-archive")
}

func (s *Service) loadBalanceHistoryDirectory(path string, archive bool) (bool, error) {
	// Validate all ancestors before interpreting a missing leaf as absence.
	if err := s.wafOwnedDirectory(filepath.Dir(path), false); err != nil {
		return false, err
	}
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	a, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || !ok || a.Uid != uint32(os.Geteuid()) || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		(archive && st.Mode().Perm() != 0700) || (!archive && st.Mode().Perm() != 0700 && st.Mode().Perm() != 0750) {
		return false, errors.New("事务目录身份或权限异常；未接管、修复或返回部分库存")
	}
	return true, nil
}

// A completed archived identity is reserved forever. Also reject an unsafe
// archive parent or an unknown occupant; absence there cannot authorize reuse.
func (s *Service) loadBalanceArchivedIDReserved(id string) error {
	present, err := s.loadBalanceHistoryDirectory(s.loadBalanceArchiveDir(), true)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if _, err = os.Lstat(filepath.Join(s.loadBalanceArchiveDir(), id+".json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("原事务标识已归档或无法核对，不得重建或覆盖恢复内容")
	}
	return nil
}

func (s *Service) loadBalanceHistoryRecord(path, id string, archived bool) (loadBalanceHistoryRow, error) {
	var row loadBalanceHistoryRow
	b, err := loadBalancePrivateRead(path, 256<<10)
	if err != nil {
		return row, err
	}
	var tx loadBalanceTransaction
	if decodeFTPPrivateJSON(b, &tx) != nil || tx.ID != id || s.loadBalanceTransactionContract(tx) != nil {
		return row, errors.New("事务身份、完整内容或摘要不可核对；原证据保留")
	}
	terminal := tx.State == "committed" || tx.State == "recovered"
	if archived && !terminal {
		return row, errors.New("归档含未完成事务，保留并拒绝不完整库存")
	}
	return loadBalanceHistoryRow{ID: tx.ID, Domain: tx.Domain, State: tx.State, CreatedAt: tx.CreatedAt, Format: tx.Format,
		Files: len(tx.Changes), SHA: core.Hash(string(b)), Bytes: int64(len(b)), Archived: archived, Archivable: terminal && !archived}, nil
}

type loadBalanceHistoryInventory struct {
	Rows         []loadBalanceHistoryRow
	Active       int
	Archived     int
	ActiveBytes  int64
	ArchiveBytes int64
	Pending      bool
}

// Full content is validated one record at a time, not retained in memory or
// returned to the browser. Only a bounded page of non-secret metadata leaves
// the executor; exact raw bytes remain private and unchanged.
func (s *Service) loadBalanceHistoryInventory(ctx context.Context) (loadBalanceHistoryInventory, error) {
	out := loadBalanceHistoryInventory{Rows: []loadBalanceHistoryRow{}}
	seen := map[string]bool{}
	activeDir := filepath.Dir(s.loadBalancePendingPath())
	activePresent, err := s.loadBalanceHistoryDirectory(activeDir, false)
	if err != nil {
		return out, err
	}
	archivePresent, err := s.loadBalanceHistoryDirectory(s.loadBalanceArchiveDir(), true)
	if err != nil {
		return out, err
	}
	if archivePresent && !activePresent {
		return out, errors.New("归档存在但原事务目录缺失，保留原身份")
	}
	for _, spec := range []struct {
		path              string
		archived, present bool
		max               int
		budget            int64
	}{
		{activeDir, false, activePresent, loadBalanceActiveTransactions, 128 << 20},
		{s.loadBalanceArchiveDir(), true, archivePresent, loadBalanceArchivedTransactions, loadBalanceArchiveBytes},
	} {
		if !spec.present {
			continue
		}
		f, err := os.OpenFile(spec.path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return out, err
		}
		entries, err := f.ReadDir(spec.max + 2)
		f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return out, err
		}
		if len(entries) > spec.max+1 || (spec.archived && len(entries) > spec.max) {
			return out, errors.New("事务库存超过上限，未返回部分统计")
		}
		count := 0
		var size int64
		for _, entry := range entries {
			if err = ctx.Err(); err != nil {
				return out, err
			}
			name := entry.Name()
			if !spec.archived && name == "pending.json" {
				if _, err = s.readLoadBalanceTransaction(); err != nil {
					return out, err
				}
				out.Pending = true
				continue
			}
			id := strings.TrimSuffix(name, ".json")
			if entry.IsDir() || !entry.Type().IsRegular() || name != id+".json" || !core.ValidID(id) || seen[id] {
				return out, errors.New("事务库存含未知条目、非普通文件或重复身份；保留原记录")
			}
			st, err := os.Lstat(filepath.Join(spec.path, name))
			if err != nil {
				return out, err
			}
			if st.Size() < 0 || st.Size() > 256<<10 || size > spec.budget-st.Size() {
				return out, errors.New("事务库存字节超过预算，未返回部分统计")
			}
			row, err := s.loadBalanceHistoryRecord(filepath.Join(spec.path, name), id, spec.archived)
			if err != nil {
				return out, err
			}
			if row.Bytes != st.Size() {
				return out, errors.New("库存读取期间记录改变，未返回部分结果")
			}
			size += row.Bytes
			count++
			seen[id] = true
			out.Rows = append(out.Rows, row)
		}
		if count > spec.max {
			return out, errors.New("事务记录超过上限，未返回不完整库存")
		}
		if spec.archived {
			out.Archived = count
			out.ArchiveBytes = size
		} else {
			out.Active = count
			out.ActiveBytes = size
		}
	}
	if out.Pending {
		for i := range out.Rows {
			out.Rows[i].Archivable = false
		}
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339, out.Rows[i].CreatedAt)
		b, _ := time.Parse(time.RFC3339, out.Rows[j].CreatedAt)
		return a.After(b) || a.Equal(b) && out.Rows[i].ID > out.Rows[j].ID
	})
	return out, nil
}

func (s *Service) loadBalanceHistoryOperation(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
	if err := core.ValidateLoadBalanceHistoryInput(action, in); err != nil {
		return nil, err
	}
	var lock *os.File
	var err error
	if action == "transactions" {
		lock, err = s.lockWAFObservation()
	} else {
		lock, err = s.lockWAFConfiguration()
	}
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	inventory, err := s.loadBalanceHistoryInventory(ctx)
	if err != nil {
		return nil, err
	}
	if action == "transactions" {
		blocked := ""
		if s.loadBalanceHealthVersion() != "1.8.0" {
			blocked = "归档需要已核对的 1.8.0 安装记录"
		}
		if inventory.Pending {
			blocked = "负载均衡有待恢复事务"
		}
		if inventory.Archived >= loadBalanceArchivedTransactions || inventory.ArchiveBytes >= loadBalanceArchiveBytes {
			blocked = "归档容量已满；原归档仍可按同一标识核对"
		}
		for _, path := range []string{s.wafPendingPath(), s.analyticsHTMLTransactionService().wafPendingPath()} {
			if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
				blocked = "防火墙或 HTML 引擎有待恢复事务或状态不可核对"
			}
		}
		if blocked != "" {
			for i := range inventory.Rows {
				inventory.Rows[i].Archivable = false
			}
		}
		for i := range inventory.Rows {
			if inventory.Rows[i].Bytes > loadBalanceArchiveBytes-inventory.ArchiveBytes {
				inventory.Rows[i].Archivable = false
			}
		}
		limit := in.Limit
		if limit == 0 {
			limit = 16
		}
		start := min(in.Offset, len(inventory.Rows))
		end := min(start+limit, len(inventory.Rows))
		return map[string]any{"load_transactions": inventory.Rows[start:end], "total": len(inventory.Rows), "limit": limit, "offset": in.Offset,
			"transaction_active_count": inventory.Active, "transaction_archive_count": inventory.Archived, "transaction_active_bytes": inventory.ActiveBytes,
			"transaction_archive_bytes": inventory.ArchiveBytes, "pending": inventory.Pending, "records_retained": true, "configuration_changed": false,
			"transaction_archive_ready": blocked == "", "transaction_archive_blocked": blocked, "transaction_slots_available": loadBalanceActiveTransactions - inventory.Active,
			"scope": "完整核对本机私有事务后返回非敏感分页元数据。活动最多 512 份 / 128 MiB，归档最多 2048 份 / 256 MiB；这是逻辑预算，不是内核硬配额，不自动归档或删除证据。"}, nil
	}
	if s.loadBalanceHealthVersion() != "1.8.0" {
		return nil, errors.New("归档须已安装经过核验的 1.8.0 应用，不替旧版本开放新操作")
	}
	if inventory.Pending {
		return nil, errors.New("有待恢复事务，禁止归档；先核对完整恢复集合")
	}
	if _, err = os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("防火墙有未完成事务，禁止维护交接")
	}
	var selected *loadBalanceHistoryRow
	for i := range inventory.Rows {
		if inventory.Rows[i].ID == in.ResourceID {
			selected = &inventory.Rows[i]
			break
		}
	}
	if selected == nil || selected.SHA != in.ExpectedSHA || (selected.State != "committed" && selected.State != "recovered") {
		return nil, errors.New("所选事务已改变、缺失或未结束；没有移动或修改入口")
	}
	if !selected.Archived && (inventory.Archived >= loadBalanceArchivedTransactions || inventory.ArchiveBytes > loadBalanceArchiveBytes-selected.Bytes) {
		return nil, errors.New("归档达到 2048 份或 256 MiB；不自动删除证据")
	}
	return s.archiveLoadBalanceHistory(ctx, *selected)
}

func (s *Service) archiveLoadBalanceHistory(ctx context.Context, row loadBalanceHistoryRow) (any, error) {
	base := s.moduleDir("load-balance")
	if err := s.wafOwnedDirectory(base, false); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err = root.Mkdir("transaction-archive", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	openDir := func(name string, archive bool) (*os.File, error) {
		if ok, err := s.loadBalanceHistoryDirectory(filepath.Join(base, name), archive); err != nil || !ok {
			return nil, errors.New("事务目录不存在或身份不可核对")
		}
		f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		a, ok := st.Sys().(*syscall.Stat_t)
		if !st.IsDir() || !ok || a.Uid != uint32(os.Geteuid()) || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
			(archive && st.Mode().Perm() != 0700) || (!archive && st.Mode().Perm() != 0700 && st.Mode().Perm() != 0750) {
			f.Close()
			return nil, errors.New("打开后的事务目录身份改变")
		}
		return f, nil
	}
	active, err := openDir("transactions", false)
	if err != nil {
		return nil, err
	}
	defer active.Close()
	archive, err := openDir("transaction-archive", true)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	parent, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if !row.Archived {
		fresh, err := s.loadBalanceHistoryRecord(filepath.Join(base, "transactions", row.ID+".json"), row.ID, false)
		if err != nil || fresh != row {
			return nil, errors.New("所选完整事务改变，未归档")
		}
		f, err := root.OpenFile("transactions/"+row.ID+".json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			return nil, err
		}
		for _, dir := range []*os.File{archive, active, parent} {
			if err = dir.Sync(); err != nil {
				return nil, err
			}
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if err = unix.Renameat2(int(active.Fd()), row.ID+".json", int(archive.Fd()), row.ID+".json", unix.RENAME_NOREPLACE); err != nil {
			return nil, errors.New("归档目标已存在、跨文件系统或不支持无覆盖交接；未覆盖证据")
		}
	}
	// Finish durability even if the caller disconnected after rename. A lost
	// reply is resolved by the same ID and digest, never by a new transaction.
	for _, dir := range []*os.File{archive, active, parent} {
		if err = dir.Sync(); err != nil {
			return nil, errors.New("交接可能已完成但持久化未确认；核对原标识与摘要，不换键重复执行")
		}
	}
	final, err := s.loadBalanceHistoryRecord(filepath.Join(base, "transaction-archive", row.ID+".json"), row.ID, true)
	if err != nil || final.SHA != row.SHA || final.Bytes != row.Bytes {
		return nil, errors.New("归档可能已完成但完整原记录无法确认；保留证据并核对原标识")
	}
	return map[string]any{"load_transactions": []loadBalanceHistoryRow{final}, "archived": 1, "replayed": row.Archived, "records_retained": true, "configuration_changed": false,
		"scope": "仅将指定已结束事务无覆盖原子移动到本机私有归档，完整原字节、摘要与身份保留。没有重载 Nginx、修改入口或删除备份；同标识重试只返回原归档。"}, nil
}
