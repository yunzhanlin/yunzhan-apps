//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

const apacheWAFActiveTransactions = 100
const apacheWAFArchivedTransactions = 512
const apacheWAFActiveBytes int64 = 128 << 20
const apacheWAFArchiveBytes int64 = 256 << 20
const apacheWAFRecordBytes int64 = 16 << 20

type apacheWAFHistoryRow struct {
	ID         string `json:"transaction_id"`
	State      string `json:"transaction_state"`
	CreatedAt  string `json:"created_at"`
	Format     int    `json:"transaction_format"`
	Files      int    `json:"transaction_files"`
	SHA        string `json:"transaction_sha256"`
	Bytes      int64  `json:"transaction_bytes"`
	Archived   bool   `json:"transaction_archived"`
	Archivable bool   `json:"transaction_archivable"`
	owner      fileOwner
	device     uint64
	inode      uint64
}

type apacheWAFHistoryInventory struct {
	Rows                      []apacheWAFHistoryRow
	Active, Archived          int
	ActiveBytes, ArchiveBytes int64
	Pending                   bool
}

func (s *Service) apacheWAFArchiveDir() string {
	return filepath.Join(s.moduleDir("apache-waf"), "config-transaction-archive")
}

func (s *Service) apacheWAFHistoryDirectory(path string, archive bool) (bool, error) {
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
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || !ok || owner.Uid != uint32(os.Geteuid()) || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || archive && st.Mode().Perm() != 0700 || !archive && st.Mode().Perm() != 0700 && st.Mode().Perm() != 0750 {
		return false, errors.New("Apache 事务目录类型、身份或权限异常；未接管或返回部分库存")
	}
	return true, nil
}

// Strict private record decoding, including nested escaped duplicate keys.
// Byte arrays of absent files may be null; typed ownership/existence and the
// full three-file digest contract still must pass. No IDS state is accepted.
func decodeApacheWAFHistoryJSON(data []byte, out any) error {
	return decodeApacheWAFPrivateJSON(data, out, map[string]bool{"format": true, "id": true, "state": true, "created_at": true, "changes": true, "backup_sha256": true}, 512)
}

func decodeApacheWAFPrivateJSON(data []byte, out any, rootFields map[string]bool, maxNodes int) error {
	if int64(len(data)) > apacheWAFRecordBytes {
		return errors.New("Apache 私有事务超过容量")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	nodes := 0
	var value func(int) error
	value = func(depth int) error {
		nodes++
		if depth > 16 || nodes > maxNodes {
			return errors.New("Apache 私有事务结构超过容量")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					token, err := d.Token()
					key, ok := token.(string)
					if err != nil || !ok || seen[strings.ToLower(key)] {
						return errors.New("Apache 私有事务字段重复")
					}
					seen[strings.ToLower(key)] = true
					if depth == 0 && !rootFields[key] {
						return errors.New("Apache 私有事务字段未知")
					}
					if rootFields["format"] && depth == 2 && key != "path" && key != "old_data" && key != "old_exists" && key != "old_mode" && key != "next_data" && key != "next_exists" && key != "next_mode" && key != "old_owner" && key != "next_owner" {
						return errors.New("Apache 事务文件字段未知或大小写无效")
					}
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				if rootFields["format"] {
					required := []string{}
					if depth == 0 {
						required = []string{"format", "id", "state", "created_at", "changes", "backup_sha256"}
					}
					if depth == 2 {
						required = []string{"path", "old_data", "old_exists", "old_mode", "next_data", "next_exists", "next_mode"}
					}
					for _, key := range required {
						if !seen[key] {
							return errors.New("Apache 事务完整记录字段缺失")
						}
					}
				}
			case '[':
				if depth == 0 {
					return errors.New("Apache 私有事务须为对象")
				}
				for d.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("Apache 私有事务结构异常")
			}
			end, err := d.Token()
			if err != nil || delimiter == '{' && end != json.Delim('}') || delimiter == '[' && end != json.Delim(']') {
				return errors.New("Apache 私有事务结构不完整")
			}
		} else if depth == 0 {
			return errors.New("Apache 私有事务须为对象")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("Apache 私有事务有额外内容")
	}
	return decodeFTPPrivateJSON(data, out)
}

// All file descriptors are no-follow/nonblocking and fully revalidated after
// reading. The caller validates directory ancestry separately under the same
// Apache configuration flock; no backup bytes are returned to Core/browser.
func apacheWAFHistoryRead(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	a, ok := before.Sys().(*syscall.Stat_t)
	if !before.Mode().IsRegular() || before.Mode() != 0600 || !ok || a.Uid != uint32(os.Geteuid()) || a.Nlink != 1 || before.Size() < 0 || before.Size() > limit {
		return nil, errors.New("Apache 私有记录类型、权限、所有者、链接数或大小异常")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) != before.Size() || int64(len(data)) > limit {
		return nil, errors.New("Apache 私有记录读取失败或超限")
	}
	after, e1 := f.Stat()
	current, e2 := os.Lstat(path)
	if e1 != nil || e2 != nil || !os.SameFile(before, after) || !os.SameFile(before, current) || before.Mode() != after.Mode() || before.Mode() != current.Mode() || before.Size() != after.Size() || before.Size() != current.Size() || !before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(current.ModTime()) {
		return nil, errors.New("Apache 私有记录读取期间改变")
	}
	for _, st := range []os.FileInfo{after, current} {
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != a.Uid || owner.Gid != a.Gid || owner.Nlink != 1 || owner.Ctim != a.Ctim {
			return nil, errors.New("Apache 私有记录身份读取期间改变")
		}
	}
	return data, nil
}

func (s *Service) apacheWAFHistoryRecord(path, id string, archived bool) (apacheWAFHistoryRow, wafTransaction, error) {
	var row apacheWAFHistoryRow
	var tx wafTransaction
	before, err := os.Lstat(path)
	if err != nil {
		return row, tx, err
	}
	b, err := apacheWAFHistoryRead(path, apacheWAFRecordBytes)
	if err != nil {
		return row, tx, err
	}
	if decodeApacheWAFHistoryJSON(b, &tx) != nil || tx.ID != id || s.wafTransactionContract(tx) != nil {
		return row, tx, errors.New("Apache 事务身份、完整三文件内容或摘要不可核对；保留原证据")
	}
	terminal := tx.State == "committed" || tx.State == "recovered"
	if archived && !terminal {
		return row, tx, errors.New("Apache 归档含未结束事务")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return row, tx, errors.New("Apache 原记录在摘要核对期间改变")
	}
	owner, ok := after.Sys().(*syscall.Stat_t)
	if !ok {
		return row, tx, errors.New("Apache 原记录身份不可核对")
	}
	return apacheWAFHistoryRow{ID: tx.ID, State: tx.State, CreatedAt: tx.CreatedAt, Format: tx.Format, Files: len(tx.Changes), SHA: core.Hash(string(b)), Bytes: int64(len(b)), Archived: archived, Archivable: terminal && !archived, owner: fileOwner{UID: owner.Uid, GID: owner.Gid}, device: uint64(owner.Dev), inode: owner.Ino}, tx, nil
}

func (s *Service) apacheWAFHistoryInventory(ctx context.Context) (apacheWAFHistoryInventory, error) {
	out := apacheWAFHistoryInventory{Rows: []apacheWAFHistoryRow{}}
	activeDir := filepath.Dir(s.wafPendingPath())
	active, err := s.apacheWAFHistoryDirectory(activeDir, false)
	if err != nil {
		return out, err
	}
	archive, err := s.apacheWAFHistoryDirectory(s.apacheWAFArchiveDir(), true)
	if err != nil {
		return out, err
	}
	if archive && !active {
		return out, errors.New("Apache 归档存在但活动目录缺失，保留原身份")
	}
	seen := map[string]bool{}
	var pending *wafTransaction
	var pendingRecord *wafTransaction
	for _, spec := range []struct {
		path             string
		archive, present bool
		max              int
		budget           int64
	}{{activeDir, false, active, apacheWAFActiveTransactions, apacheWAFActiveBytes}, {s.apacheWAFArchiveDir(), true, archive, apacheWAFArchivedTransactions, apacheWAFArchiveBytes}} {
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
		if len(entries) > spec.max+1 || spec.archive && len(entries) > spec.max {
			return out, errors.New("Apache 事务库存超过条数上限；未返回部分统计")
		}
		count := 0
		var size int64
		for _, entry := range entries {
			if err = ctx.Err(); err != nil {
				return out, err
			}
			name := entry.Name()
			path := filepath.Join(spec.path, name)
			id := strings.TrimSuffix(name, ".json")
			if !spec.archive && name == "pending.json" {
				b, err := apacheWAFHistoryRead(path, apacheWAFRecordBytes)
				if err != nil {
					return out, err
				}
				var tx wafTransaction
				if decodeApacheWAFHistoryJSON(b, &tx) != nil || s.wafTransactionContract(tx) != nil {
					return out, errors.New("Apache 待恢复事务不可核对")
				}
				pending = &tx
				out.Pending = true
				if size > spec.budget-int64(len(b)) {
					return out, errors.New("Apache 活动事务字节超过预算")
				}
				size += int64(len(b))
				continue
			}
			if entry.IsDir() || !entry.Type().IsRegular() || name != id+".json" || !core.ValidID(id) || seen[id] {
				return out, errors.New("Apache 事务含未知条目、链接或重复身份；保留原记录")
			}
			st, err := os.Lstat(path)
			if err != nil {
				return out, err
			}
			if st.Size() < 0 || st.Size() > apacheWAFRecordBytes || size > spec.budget-st.Size() {
				return out, errors.New("Apache 事务库存字节超过预算，未返回部分统计")
			}
			row, tx, err := s.apacheWAFHistoryRecord(path, id, spec.archive)
			if err != nil {
				return out, err
			}
			if row.Bytes != st.Size() {
				return out, errors.New("Apache 库存核对期间改变")
			}
			if !spec.archive && tx.State == "applying" {
				out.Pending = true
			}
			if !spec.archive {
				// The pending entry may sort after its original record.
				if pending != nil && pending.ID == id {
					copy := tx
					pendingRecord = &copy
				}
			}
			seen[id] = true
			size += row.Bytes
			count++
			out.Rows = append(out.Rows, row)
		}
		if count > spec.max {
			return out, errors.New("Apache 事务条数超过上限")
		}
		if spec.archive {
			out.Archived = count
			out.ArchiveBytes = size
		} else {
			out.Active = count
			out.ActiveBytes = size
		}
	}
	if pending != nil {
		if pendingRecord == nil {
			_, tx, err := s.apacheWAFHistoryRecord(filepath.Join(activeDir, pending.ID+".json"), pending.ID, false)
			if err != nil {
				return out, errors.New("Apache 待恢复事务缺少完整原记录")
			}
			pendingRecord = &tx
		}
		left, right := *pending, *pendingRecord
		left.State = "applying"
		right.State = "applying"
		a, _ := json.Marshal(left)
		b, _ := json.Marshal(right)
		if !bytes.Equal(a, b) {
			return out, errors.New("Apache 待恢复标记与完整原记录不一致；保留并拒绝维护")
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

func (s *Service) apacheWAFHistoryVersion() (string, error) {
	if err := s.wafOwnedDirectory(s.moduleDir("apache-waf"), false); err != nil {
		return "", err
	}
	b, err := apacheWAFHistoryRead(filepath.Join(s.moduleDir("apache-waf"), "installed.json"), 512<<10)
	if err != nil {
		return "", err
	}
	var manifest struct {
		ID          string         `json:"id"`
		Version     string         `json:"version"`
		Settings    map[string]any `json:"settings"`
		InstalledAt string         `json:"installed_at"`
		UpdatedAt   string         `json:"updated_at"`
	}
	// The typed decoder rejects unknown fields; settings retain their own strict
	// versioned parser. Installation metadata cannot authorize a future version.
	if decodeApacheWAFPrivateJSON(b, &manifest, map[string]bool{"id": true, "version": true, "settings": true, "installed_at": true, "updated_at": true}, 32768) != nil || manifest.ID != "apache-waf" || !core.ApacheWAFHistoryVersion(manifest.Version) {
		return "", errors.New("Apache 安装身份或版本未核对")
	}
	if _, err = core.DecodeApacheWAFConfig(manifest.Settings); err != nil {
		return "", err
	}
	return manifest.Version, nil
}

func (s *Service) apacheWAFHistoryOperation(ctx context.Context, action string, in core.ApacheWAFHistoryInput) (any, error) {
	if err := core.ValidateApacheWAFHistoryInput(action, in); err != nil {
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
	version, err := s.apacheWAFHistoryVersion()
	if err != nil {
		return nil, errors.New("须先安装并核对已知 Apache WAF，未创建或接管安装记录")
	}
	inv, err := s.apacheWAFHistoryInventory(ctx)
	if err != nil {
		return nil, err
	}
	blocked := ""
	if version != core.ApacheWAFVersion {
		blocked = "请通过应用商店签名升级到 Apache WAF 2.3.0，旧版仅查看库存"
	}
	if inv.Pending {
		blocked = "Apache 有待恢复或未结束事务；原证据保留，禁止归档和重放"
	}
	if action == "transactions" {
		if inv.Archived >= apacheWAFArchivedTransactions || inv.ArchiveBytes >= apacheWAFArchiveBytes {
			blocked = "归档容量已满，原标识仍可核对；不自动删除证据"
		}
		for i := range inv.Rows {
			if blocked != "" || inv.Rows[i].Bytes > apacheWAFArchiveBytes-inv.ArchiveBytes {
				inv.Rows[i].Archivable = false
			}
		}
		start := min(in.Offset, len(inv.Rows))
		end := min(start+in.Limit, len(inv.Rows))
		return map[string]any{"apache_transactions": inv.Rows[start:end], "limit": in.Limit, "offset": in.Offset, "total": len(inv.Rows), "transaction_active_count": inv.Active, "transaction_archive_count": inv.Archived, "transaction_active_bytes": inv.ActiveBytes, "transaction_archive_bytes": inv.ArchiveBytes, "transaction_slots_available": apacheWAFActiveTransactions - inv.Active, "pending": inv.Pending, "records_retained": true, "configuration_changed": false, "transaction_archive_ready": blocked == "", "transaction_replay_ready": version == core.ApacheWAFVersion && !inv.Pending, "transaction_archive_blocked": blocked, "scope": "完整三文件事务核对后返回非敏感分页。活动最多 100 份 / 128 MiB（含待恢复标记），归档最多 512 份 / 256 MiB；逻辑预算不是内核配额。旧 config-backups 原样保留，不在此库存或新事务写入范围。"}, nil
	}
	if blocked != "" {
		return nil, errors.New(blocked)
	}
	var row *apacheWAFHistoryRow
	for i := range inv.Rows {
		if inv.Rows[i].ID == in.ID {
			row = &inv.Rows[i]
			break
		}
	}
	if row == nil || row.SHA != in.SHA || row.State != "committed" && row.State != "recovered" {
		return nil, errors.New("所选完整事务缺失、改变或未结束；没有归档")
	}
	if !row.Archived && (inv.Archived >= apacheWAFArchivedTransactions || inv.ArchiveBytes > apacheWAFArchiveBytes-row.Bytes) {
		return nil, errors.New("Apache 归档容量已满；未自动删除原证据")
	}
	return s.archiveApacheWAFHistory(ctx, *row)
}

func (s *Service) archiveApacheWAFHistory(ctx context.Context, row apacheWAFHistoryRow) (any, error) {
	base := s.moduleDir("apache-waf")
	if err := s.wafOwnedDirectory(base, false); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err = root.Mkdir("config-transaction-archive", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	openDir := func(name string, archived bool) (*os.File, error) {
		ok, err := s.apacheWAFHistoryDirectory(filepath.Join(base, name), archived)
		if err != nil || !ok {
			return nil, errors.New("Apache 事务目录缺失或身份异常")
		}
		f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		current, e := os.Lstat(filepath.Join(base, name))
		if err != nil || e != nil || !os.SameFile(st, current) {
			f.Close()
			return nil, errors.New("Apache 事务目录打开期间改变")
		}
		return f, nil
	}
	active, err := openDir("config-transactions", false)
	if err != nil {
		return nil, err
	}
	defer active.Close()
	archive, err := openDir("config-transaction-archive", true)
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
		fresh, _, err := s.apacheWAFHistoryRecord(filepath.Join(base, "config-transactions", row.ID+".json"), row.ID, false)
		if err != nil || fresh != row {
			return nil, errors.New("所选完整 Apache 事务已改变，未归档")
		}
		f, err := root.OpenFile("config-transactions/"+row.ID+".json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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
			return nil, errors.New("Apache 归档目标存在、跨文件系统或不支持无覆盖交接；未覆盖证据")
		}
	}
	// Finish persistence even when the client disconnected after rename. A
	// lost acknowledgment is only replayed with the original ID and full SHA.
	for _, dir := range []*os.File{archive, active, parent} {
		if err = dir.Sync(); err != nil {
			return nil, errors.New("Apache 归档可能已交接但持久化未确认；按原标识和摘要核对")
		}
	}
	final, _, err := s.apacheWAFHistoryRecord(filepath.Join(base, "config-transaction-archive", row.ID+".json"), row.ID, true)
	if err != nil || final.SHA != row.SHA || final.Bytes != row.Bytes || final.owner != row.owner || final.device != row.device || final.inode != row.inode {
		return nil, errors.New("Apache 原归档完整内容未确认；保留原证据")
	}
	return map[string]any{"apache_transactions": []apacheWAFHistoryRow{final}, "archived": 1, "replayed": row.Archived, "records_retained": true, "configuration_changed": false, "scope": "仅无覆盖移动已结束的完整原事务，字节、权限和所有者不变。不重载 Apache 或 Nginx，不修改网站、不删除备份。同标识和摘要重试只核对原归档。"}, nil
}

func (s *Service) apacheWAFReserveTransaction(ctx context.Context, tx wafTransaction) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	inv, err := s.apacheWAFHistoryInventory(ctx)
	if err != nil {
		return err
	}
	if inv.Pending {
		return errors.New("Apache 有未结束事务，未开始新配置")
	}
	for _, row := range inv.Rows {
		if row.ID == tx.ID {
			return errors.New("Apache 原事务标识永久保留，不得重建或覆盖")
		}
	}
	b, err := json.MarshalIndent(tx, "", "  ")
	if err != nil || inv.Active >= apacheWAFActiveTransactions || inv.ActiveBytes > apacheWAFActiveBytes-2*int64(len(b)+1) {
		return errors.New("Apache 活动事务达到 100 份或 128 MiB，请先归档已结束事务；未修改配置")
	}
	return nil
}

func (s *Service) apacheWAFHistoryRoutes(m *http.ServeMux) {
	for _, action := range []string{"transactions", "archive-transaction"} {
		method := "GET"
		if action == "archive-transaction" {
			method = "POST"
		}
		m.HandleFunc(method+" /v1/software/apache-waf/"+action, func(w http.ResponseWriter, r *http.Request) {
			var in core.ApacheWAFHistoryInput
			var err error
			if action == "transactions" {
				in, err = core.ApacheWAFHistoryQuery(r.URL.RawQuery)
			} else {
				if r.URL.RawQuery != "" {
					respond(w, 400, map[string]string{"error": "归档不接受查询参数"})
					return
				}
				var raw []byte
				raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
				if err == nil {
					in, err = core.DecodeApacheWAFHistoryArchive(raw)
				}
			}
			if err != nil {
				respond(w, 400, map[string]string{"error": err.Error()})
				return
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			out, err := s.apacheWAFTransactionService().apacheWAFHistoryOperation(r.Context(), action, in)
			if err != nil {
				respond(w, 409, map[string]string{"error": err.Error()})
				return
			}
			w.Header().Set("Cache-Control", "no-store, private")
			respond(w, 200, out)
		})
	}
}
