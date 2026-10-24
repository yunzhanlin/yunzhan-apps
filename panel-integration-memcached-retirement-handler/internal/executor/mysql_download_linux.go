//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func privateBackupEntry(info os.FileInfo, dir bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0077 != 0 || info.IsDir() != dir || (!dir && (!info.Mode().IsRegular() || stat.Nlink != 1)) {
		return errors.New("备份路径归属、类型或私有权限异常")
	}
	return nil
}
func openVerifiedBackup(ctx context.Context, base string, expected core.DatabaseBackup) (*os.File, core.DatabaseBackup, error) {
	var empty core.DatabaseBackup
	if !core.ValidID(expected.ID) || !core.ValidID(expected.ServerID) || !core.ValidID(expected.DatabaseID) || expected.Bytes < 0 || expected.Bytes > 4*1024*1024*1024 || len(expected.SHA256) != 64 {
		return nil, empty, errors.New("备份标识、大小或摘要无效")
	}
	if err := ownedRuntimePath(base, true); err != nil {
		return nil, empty, err
	}
	info, err := os.Stat(base)
	if err != nil {
		return nil, empty, err
	}
	if err = privateBackupEntry(info, true); err != nil {
		return nil, empty, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, empty, err
	}
	defer root.Close()
	info, err = root.Lstat(expected.ServerID)
	if err != nil {
		return nil, empty, err
	}
	if err = privateBackupEntry(info, true); err != nil {
		return nil, empty, err
	}
	dir, err := root.OpenRoot(expected.ServerID)
	if err != nil {
		return nil, empty, err
	}
	defer dir.Close()
	open := func(name string) (*os.File, error) {
		f, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		info, err := f.Stat()
		if err == nil {
			err = privateBackupEntry(info, false)
		}
		if err != nil {
			f.Close()
			return nil, err
		}
		return f, nil
	}
	meta, err := open(expected.ID + ".json")
	if err != nil {
		return nil, empty, err
	}
	b, err := io.ReadAll(io.LimitReader(meta, 16385))
	meta.Close()
	if err != nil {
		return nil, empty, err
	}
	if len(b) > 16384 {
		return nil, empty, errors.New("备份清单过大")
	}
	var actual core.DatabaseBackup
	if err = json.Unmarshal(b, &actual); err != nil {
		return nil, empty, errors.New("备份清单无效")
	}
	if actual.ID != expected.ID || actual.ServerID != expected.ServerID || actual.DatabaseID != expected.DatabaseID || actual.Bytes != expected.Bytes || actual.SHA256 != expected.SHA256 || actual.Version != expected.Version {
		return nil, empty, errors.New("备份清单与面板记录不一致")
	}
	file, err := open(expected.ID + ".sql")
	if err != nil {
		return nil, empty, err
	}
	ok := false
	defer func() {
		if !ok {
			file.Close()
		}
	}()
	info, err = file.Stat()
	if err != nil {
		return nil, empty, err
	}
	if info.Size() != actual.Bytes {
		return nil, empty, errors.New("备份大小不一致")
	}
	h := sha256.New()
	buf := make([]byte, 256*1024)
	for {
		if err = ctx.Err(); err != nil {
			return nil, empty, err
		}
		n, readErr := file.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, empty, readErr
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != actual.SHA256 {
		return nil, empty, errors.New("备份 SHA-256 不匹配，拒绝下载")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return nil, empty, err
	}
	ok = true
	return file, actual, nil
}
func mysqlBackupDownloadRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/databases/backups/{server}/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		size, err := strconv.ParseInt(q.Get("bytes"), 10, 64)
		if err != nil {
			respond(w, 400, map[string]string{"error": "备份大小无效"})
			return
		}
		expected := core.DatabaseBackup{ID: r.PathValue("id"), ServerID: r.PathValue("server"), DatabaseID: q.Get("database_id"), Bytes: size, SHA256: q.Get("sha256"), Version: q.Get("version")}
		file, backup, err := openVerifiedBackup(r.Context(), mysqlBackups, expected)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		defer file.Close()
		manifest, err := readMySQL(backup.ServerID)
		if err != nil {
			respond(w, 409, map[string]string{"error": "所属实例记录不可读取"})
			return
		}
		db, err := readOwnedDatabase(manifest.Server, backup.DatabaseID)
		if err != nil {
			respond(w, 409, map[string]string{"error": "所属数据库记录不可读取"})
			return
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
		w.Header().Set("Content-Type", "application/sql")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": db.Name + "-" + backup.ID[:8] + ".sql"}))
		w.Header().Set("Content-Length", strconv.FormatInt(backup.Bytes, 10))
		w.Header().Set("X-Content-SHA256", backup.SHA256)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = io.CopyN(w, file, backup.Bytes)
	})
	m.HandleFunc("DELETE /v1/databases/backups/{server}/{id}", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		size, err := strconv.ParseInt(q.Get("bytes"), 10, 64)
		if err != nil {
			respond(w, 400, map[string]string{"error": "备份大小无效"})
			return
		}
		expected := core.DatabaseBackup{ID: r.PathValue("id"), ServerID: r.PathValue("server"), DatabaseID: q.Get("database_id"), Bytes: size, SHA256: q.Get("sha256"), Version: q.Get("version")}
		if err = deleteVerifiedBackup(r.Context(), mysqlBackups, expected); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]bool{"deleted": true})
	})
}

type backupDeletionReceipt struct {
	Backup core.DatabaseBackup `json:"backup"`
	State  string              `json:"state"`
}

func validBackupIdentity(v core.DatabaseBackup) bool {
	return core.ValidID(v.ID) && core.ValidID(v.ServerID) && core.ValidID(v.DatabaseID) && v.Bytes >= 0 && v.Bytes <= 4*1024*1024*1024 && len(v.SHA256) == 64 && v.Version != ""
}

func deleteVerifiedBackup(ctx context.Context, base string, expected core.DatabaseBackup) error {
	if !validBackupIdentity(expected) {
		return errors.New("备份标识、大小或摘要无效")
	}
	if e := ownedRuntimePath(base, true); e != nil {
		return e
	}
	serverDir := filepath.Join(base, expected.ServerID)
	if info, e := os.Stat(serverDir); e != nil || privateBackupEntry(info, true) != nil {
		return errors.New("备份实例目录异常")
	}
	receiptPath := filepath.Join(serverDir, ".deleted-"+expected.ID+".json")
	var receipt backupDeletionReceipt
	if info, e := os.Lstat(receiptPath); e == nil {
		if e = privateBackupEntry(info, false); e != nil {
			return e
		}
		raw, e := os.ReadFile(receiptPath)
		if e != nil {
			return e
		}
		if json.Unmarshal(raw, &receipt) != nil || receipt.Backup != expected || (receipt.State != "pending" && receipt.State != "deleted") {
			return errors.New("备份清理回执与请求不一致")
		}
		if receipt.State == "deleted" {
			return nil
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	file, _, e := openVerifiedBackup(ctx, base, expected)
	if e != nil {
		if receipt.State == "pending" && errors.Is(e, os.ErrNotExist) {
			if e = removeBackupPair(serverDir, expected.ID); e != nil {
				return e
			}
			receipt.State = "deleted"
			raw, _ := json.Marshal(receipt)
			return atomicWrite(receiptPath, raw, 0600)
		}
		return e
	}
	file.Close()
	receipt = backupDeletionReceipt{Backup: expected, State: "pending"}
	raw, _ := json.Marshal(receipt)
	if e = atomicWrite(receiptPath, raw, 0600); e != nil {
		return e
	}
	if e = removeBackupPair(serverDir, expected.ID); e != nil {
		return e
	}
	receipt.State = "deleted"
	raw, _ = json.Marshal(receipt)
	return atomicWrite(receiptPath, raw, 0600)
}

func removeBackupPair(serverDir, id string) error {
	root, e := os.OpenRoot(serverDir)
	if e != nil {
		return e
	}
	defer root.Close()
	if e = root.Remove(id + ".sql"); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = root.Remove(id + ".json"); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	dir, e := os.Open(serverDir)
	if e == nil {
		e = dir.Sync()
		dir.Close()
	}
	if e != nil {
		return e
	}
	return nil
}
