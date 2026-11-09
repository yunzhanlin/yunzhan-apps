//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

const wafBackupInventoryBytes int64 = 128 << 20
const wafBackupIndexBytes int64 = 1 << 20
const wafBackupFileSlots = 4096

type wafBackupIndexFile struct {
	Source  string     `json:"source"`
	File    string     `json:"file"`
	Existed bool       `json:"existed"`
	Mode    uint32     `json:"mode"`
	Owner   *fileOwner `json:"owner"`
	SHA     string     `json:"sha256"`
}
type wafBackupIndex struct {
	CreatedAt string               `json:"created_at"`
	Files     []wafBackupIndexFile `json:"files"`
}
type wafBackupInventoryRow struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	Files     int    `json:"files"`
	Bytes     int64  `json:"bytes"`
	SHA       string `json:"sha256"`
}
type wafBackupInventory struct {
	Available bool                    `json:"available"`
	Entries   []wafBackupInventoryRow `json:"entries"`
	Bytes     int64                   `json:"bytes"`
	CountMax  int                     `json:"count_max"`
	ScanMax   int64                   `json:"scan_max_bytes"`
	ReadOnly  bool                    `json:"read_only"`
	Message   string                  `json:"message"`
}

func wafBackupPrivateDirectory(path string) (os.FileInfo, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || st.Mode() != os.ModeDir|0700 || !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("WAF 备份目录身份、类型或私有权限异常")
	}
	return st, nil
}

func wafBackupDirectoryUnchanged(path string, before os.FileInfo) error {
	after, err := wafBackupPrivateDirectory(path)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return errors.New("WAF 备份目录核对期间改变，未返回部分库存")
	}
	a, aok := before.Sys().(*syscall.Stat_t)
	b, bok := after.Sys().(*syscall.Stat_t)
	if !aok || !bok || a.Uid != b.Uid || a.Gid != b.Gid || a.Ctim != b.Ctim || a.Nlink != b.Nlink {
		return errors.New("WAF 备份目录身份核对期间改变")
	}
	return nil
}

func wafBackupDirectoryEntries(path string, limit int) ([]os.DirEntry, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > limit {
		return nil, errors.New("WAF 私有备份目录条目超过读取上限或不可读取")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func decodeWAFBackupIndex(raw []byte, out *wafBackupIndex) error {
	if int64(len(raw)) > wafBackupIndexBytes || decodeApacheWAFPrivateJSON(raw, out, map[string]bool{"created_at": true, "files": true}, 32768) != nil {
		return errors.New("WAF 备份索引损坏、重复字段、未知内容或超限")
	}
	var shape struct {
		Files []map[string]json.RawMessage `json:"files"`
	}
	if json.Unmarshal(raw, &shape) != nil || len(out.Files) == 0 || len(out.Files) > wafBackupFileSlots || len(shape.Files) != len(out.Files) {
		return errors.New("WAF 备份文件索引数量异常")
	}
	for _, row := range shape.Files {
		if len(row) != 6 {
			return errors.New("WAF 备份文件索引不完整")
		}
		for _, field := range []string{"source", "file", "existed", "mode", "owner", "sha256"} {
			if row[field] == nil || field != "owner" && bytes.Equal(bytes.TrimSpace(row[field]), []byte("null")) {
				return errors.New("WAF 备份文件字段缺失或大小写无效")
			}
		}
		if !bytes.Equal(bytes.TrimSpace(row["owner"]), []byte("null")) {
			var owner map[string]json.RawMessage
			if json.Unmarshal(row["owner"], &owner) != nil || len(owner) != 2 || owner["uid"] == nil || owner["gid"] == nil || bytes.Equal(bytes.TrimSpace(owner["uid"]), []byte("null")) || bytes.Equal(bytes.TrimSpace(owner["gid"]), []byte("null")) {
				return errors.New("WAF 原配置所有者字段不可核对")
			}
		}
	}
	at, err := time.Parse(time.RFC3339, out.CreatedAt)
	if err != nil || at.IsZero() || len(out.CreatedAt) > 40 {
		return errors.New("WAF 备份时间无效")
	}
	return nil
}

func wafBackupLockUnchanged(lock *os.File, path string, before os.FileInfo) error {
	for _, read := range []func() (os.FileInfo, error){lock.Stat, func() (os.FileInfo, error) { return os.Lstat(path) }} {
		after, err := read()
		a, aok := before.Sys().(*syscall.Stat_t)
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !aok {
			return errors.New("WAF 原配置锁已改变")
		}
		b, bok := after.Sys().(*syscall.Stat_t)
		if !bok || a.Uid != b.Uid || a.Gid != b.Gid || a.Nlink != b.Nlink || a.Ctim != b.Ctim {
			return errors.New("WAF 原配置锁身份已改变")
		}
	}
	return nil
}

// Existing lock only; even exclusive metadata maintenance must never create
// or take over a missing/private lock implicitly.
func (s *Service) openExistingWAFBackupLock(ctx context.Context, operation int) (*os.File, os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if operation != syscall.LOCK_SH && operation != syscall.LOCK_EX {
		return nil, nil, errors.New("原快照锁操作无效")
	}
	path := filepath.Join(s.Config.SecurityDir, "waf-configuration.lock")
	if _, err := os.Lstat(path); err != nil {
		return nil, nil, err
	}
	if err := s.wafOwnedDirectory(s.Config.SecurityDir, false); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	refuse := func(err error) (*os.File, os.FileInfo, error) { f.Close(); return nil, nil, err }
	st, err := f.Stat()
	if err != nil {
		return refuse(err)
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode() != 0600 || st.Size() != 0 || !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return refuse(errors.New("原配置锁身份或私有权限异常"))
	}
	if err = syscall.Flock(int(f.Fd()), operation|syscall.LOCK_NB); err != nil {
		return refuse(errWAFConfigurationBusy)
	}
	if err = wafBackupLockUnchanged(f, path, st); err != nil {
		return refuse(err)
	}
	return f, st, nil
}

// Read an existing lock only. Inventory observation cannot create a security
// directory/lock, install software, repair a snapshot or prune any evidence.
func (s *Service) readWAFBackupInventory(ctx context.Context) (wafBackupInventory, error) {
	return s.readWAFBackupSelection(ctx, "")
}

// A single complete snapshot is independently readable even when the full
// inventory scan exceeds its byte budget. This does not certify other rows or
// turn the selected row into a successful full-inventory response.
func (s *Service) readWAFBackupSnapshot(ctx context.Context, id string) (wafBackupInventoryRow, error) {
	if !core.ValidID(id) {
		return wafBackupInventoryRow{}, errors.New("WAF 原快照标识无效")
	}
	out, err := s.readWAFBackupSelection(ctx, id)
	if err != nil {
		return wafBackupInventoryRow{}, err
	}
	if !out.Available || len(out.Entries) != 1 || out.Entries[0].ID != id {
		return wafBackupInventoryRow{}, os.ErrNotExist
	}
	return out.Entries[0], nil
}

func (s *Service) readWAFBackupSelection(ctx context.Context, selected string) (wafBackupInventory, error) {
	return s.readWAFBackupNamespace(ctx, "waf-backups", selected)
}

func (s *Service) readWAFBackupNamespace(ctx context.Context, namespace, selected string) (out wafBackupInventory, failure error) {
	empty := wafBackupInventory{Entries: []wafBackupInventoryRow{}, CountMax: 100, ScanMax: wafBackupInventoryBytes, ReadOnly: true}
	out = empty
	defer func() {
		if failure != nil {
			out = empty
		}
	}()
	if err := ctx.Err(); err != nil {
		return out, err
	}
	lockPath := filepath.Join(s.Config.SecurityDir, "waf-configuration.lock")
	lock, st, err := s.openExistingWAFBackupLock(ctx, syscall.LOCK_SH)
	if errors.Is(err, os.ErrNotExist) {
		out.Message = "尚无可核对的原配置锁；未创建目录或备份，也未宣称库存为空"
		return out, nil
	}
	if err != nil {
		return out, err
	}
	defer lock.Close()
	out, err = s.scanWAFBackupSelection(ctx, namespace, selected)
	if err != nil {
		return out, err
	}
	if err := wafBackupLockUnchanged(lock, lockPath, st); err != nil {
		return out, err
	}
	return out, nil
}

// Caller holds the unchanged original configuration flock. Bases are closed
// internal namespaces, never a path supplied by an API request.
func (s *Service) scanWAFBackupSelection(ctx context.Context, namespace, selected string) (out wafBackupInventory, failure error) {
	empty := wafBackupInventory{Entries: []wafBackupInventoryRow{}, CountMax: 100, ScanMax: wafBackupInventoryBytes, ReadOnly: true}
	out = empty
	defer func() {
		if failure != nil {
			out = empty
		}
	}()
	if namespace != "waf-backups" && namespace != "waf-backup-archive" || selected != "" && !core.ValidID(selected) {
		return out, errors.New("原快照私有命名空间或标识无效")
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	base := filepath.Join(s.Config.SecurityDir, namespace)
	parent, err := wafBackupPrivateDirectory(base)
	if errors.Is(err, os.ErrNotExist) {
		out.Available, out.Message = true, "原配置锁下未发现备份目录；只读核对，未创建目录"
		return out, nil
	}
	if err != nil {
		return out, err
	}
	entries, err := wafBackupDirectoryEntries(base, out.CountMax)
	if err != nil || len(entries) > out.CountMax {
		return out, errors.New("WAF 原备份数量超过 100 或目录不可读取；未返回部分库存")
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if !entry.IsDir() || !core.ValidID(entry.Name()) {
			return out, errors.New("WAF 备份根目录含未知条目或链接；未返回部分库存")
		}
		if selected != "" && entry.Name() != selected {
			continue
		}
		path := filepath.Join(base, entry.Name())
		before, err := wafBackupPrivateDirectory(path)
		if err != nil {
			return out, err
		}
		remaining := wafBackupInventoryBytes - out.Bytes
		raw, err := apacheWAFHistoryRead(filepath.Join(path, "index.json"), min(wafBackupIndexBytes, remaining))
		if err != nil {
			return out, err
		}
		var index wafBackupIndex
		if err := decodeWAFBackupIndex(raw, &index); err != nil {
			return out, err
		}
		h, v := wafFiles(s)
		fixed := []string{s.Config.NginxConf, s.softwareManifestPath("nginx-waf"), h, v, s.systemPath("/etc/panel/waf/http.d/20-panel-native-waf.conf")}
		if len(index.Files) < len(fixed) {
			return out, errors.New("WAF 备份缺少固定原配置集合")
		}
		for i, source := range fixed {
			if index.Files[i].Source != source {
				return out, errors.New("WAF 备份固定原配置集合不匹配")
			}
		}
		row := wafBackupInventoryRow{ID: entry.Name(), CreatedAt: index.CreatedAt, Files: len(index.Files), Bytes: int64(len(raw))}
		manifest := map[string]any{"index_sha256": core.Hash(string(raw)), "files": []string{}}
		digests := []string{}
		known := map[string]bool{"index.json": true}
		sources := map[string]bool{}
		configurationBytes := int64(0)
		for i, file := range index.Files {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			if file.File != fmt.Sprintf("%03d.conf", i) || sources[file.Source] || !s.wafChangePathAllowed(file.Source) || file.Mode > 0777 || len(file.SHA) != 64 {
				return out, errors.New("WAF 备份文件标识、原路径、权限或摘要不可核对")
			}
			sources[file.Source] = true
			if !file.Existed {
				if file.Owner != nil || file.Mode != 0644 || file.SHA != core.Hash("") {
					return out, errors.New("WAF 原不存在文件的索引异常")
				}
				continue
			}
			if file.Owner == nil {
				return out, errors.New("WAF 原文件所有者记录缺失")
			}
			data, err := apacheWAFHistoryRead(filepath.Join(path, file.File), min((8<<20)-configurationBytes, remaining-row.Bytes))
			if err != nil || core.Hash(string(data)) != file.SHA {
				return out, errors.New("WAF 原备份完整内容或摘要不可核对")
			}
			known[file.File] = true
			configurationBytes += int64(len(data))
			row.Bytes += int64(len(data))
			digests = append(digests, file.SHA)
		}
		files, err := wafBackupDirectoryEntries(path, len(known))
		if err != nil || len(files) != len(known) {
			return out, errors.New("WAF 备份目录含缺失或额外文件")
		}
		for _, file := range files {
			if file.IsDir() || !file.Type().IsRegular() || !known[file.Name()] {
				return out, errors.New("WAF 备份含未知文件、子目录或链接")
			}
		}
		if err := wafBackupDirectoryUnchanged(path, before); err != nil {
			return out, err
		}
		manifest["files"] = digests
		encoded, _ := json.Marshal(manifest)
		hash := sha256.Sum256(encoded)
		row.SHA = hex.EncodeToString(hash[:])
		if out.Bytes > wafBackupInventoryBytes-row.Bytes {
			return out, errors.New("WAF 完整备份库存超过 128 MiB 只读扫描上限；未返回部分库存，也未删除证据")
		}
		out.Bytes += row.Bytes
		out.Entries = append(out.Entries, row)
	}
	if err := wafBackupDirectoryUnchanged(base, parent); err != nil {
		return out, err
	}
	out.Available, out.Message = true, "完整核对原备份索引及全部内容；只返回元数据，不修改、归档或删除备份，不重载网站"
	if selected != "" {
		out.Message = "只完整核验所选快照；不宣称已核验整个库存，也不返回部分库存统计"
	}
	return out, nil
}

// Directory identities only, never a content-verified inventory. This gives
// administrators fixed IDs to individually verify when the full scan fails.
func (s *Service) readWAFBackupSlots(ctx context.Context) (core.WAFBackupSlots, error) {
	empty := core.WAFBackupSlots{IDs: []string{}, CountMax: 100, ReadOnly: true, ContentsVerified: false}
	out := empty
	f, st, err := s.openExistingWAFBackupLock(ctx, syscall.LOCK_SH)
	if errors.Is(err, os.ErrNotExist) {
		out.Message = "原配置锁不可核对；目录标识未知，不代表没有快照"
		return out, nil
	}
	if err != nil {
		return empty, err
	}
	defer f.Close()
	base := filepath.Join(s.Config.SecurityDir, "waf-backups")
	parent, err := wafBackupPrivateDirectory(base)
	if err == nil {
		entries, err := wafBackupDirectoryEntries(base, 100)
		if err != nil {
			return empty, err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return empty, err
			}
			if !entry.IsDir() || !core.ValidID(entry.Name()) {
				return empty, errors.New("原快照目录含未知条目")
			}
			if _, err := wafBackupPrivateDirectory(filepath.Join(base, entry.Name())); err != nil {
				return empty, err
			}
			out.IDs = append(out.IDs, entry.Name())
		}
		if err := wafBackupDirectoryUnchanged(base, parent); err != nil {
			return empty, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	if err := wafBackupLockUnchanged(f, filepath.Join(s.Config.SecurityDir, "waf-configuration.lock"), st); err != nil {
		return empty, err
	}
	out.Available = true
	out.Message = "只核对受限目录身份；索引及内容尚未核验，不宣称完整备份库存通过"
	return out, nil
}

func (s *Service) wafBackupInventoryRoutes(m *http.ServeMux) {
	s.wafBackupArchiveRoutes(m)
	m.HandleFunc("GET /v1/software/nginx-waf/config-backup-slots", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			respond(w, 400, map[string]string{"error": "原快照目录标识不接受查询字段"})
			return
		}
		out, err := s.readWAFBackupSlots(r.Context())
		if err != nil {
			respond(w, 409, map[string]string{"error": "原快照目录身份不可完整核对；未返回部分标识或执行维护"})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/software/nginx-waf/config-backups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			respond(w, 400, map[string]string{"error": "WAF 备份库存不接受查询字段"})
			return
		}
		out, err := s.readWAFBackupInventory(r.Context())
		if err != nil {
			respond(w, 409, map[string]string{"error": "WAF 原配置备份未完整核验；保留全部证据，未返回部分库存或执行维护"})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/software/nginx-waf/config-backups/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !core.ValidID(r.PathValue("id")) || r.URL.RawQuery != "" || r.URL.ForceQuery {
			respond(w, 400, map[string]string{"error": "WAF 原快照标识或查询字段无效"})
			return
		}
		row, err := s.readWAFBackupSnapshot(r.Context(), r.PathValue("id"))
		if errors.Is(err, os.ErrNotExist) {
			respond(w, 404, map[string]string{"error": "所选原快照不可核对；未创建、修复或归档证据"})
			return
		}
		if err != nil {
			respond(w, 409, map[string]string{"error": "所选原快照未完整核验；未返回配置正文或执行维护"})
			return
		}
		respond(w, 200, row)
	})
}
