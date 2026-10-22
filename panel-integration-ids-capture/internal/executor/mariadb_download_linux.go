//go:build linux

package executor

import (
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

func privateMariaDBBackupFile(path string) (*os.File, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || stat.Uid != 0 || stat.Nlink != 1 {
		return nil, errors.New("MariaDB 备份类型、归属或私有权限异常")
	}
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

func mariaDBBackupDownloadRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/mariadb/backups/{instance}/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		size, e := strconv.ParseInt(q.Get("bytes"), 10, 64)
		if e != nil {
			respond(w, 400, map[string]string{"error": "MariaDB 备份大小无效"})
			return
		}
		expected := core.MariaDBBackup{ID: r.PathValue("id"), InstanceID: r.PathValue("instance"), DatabaseID: q.Get("database_id"), DatabaseName: q.Get("database_name"), Version: q.Get("version"), Bytes: size, SHA256: q.Get("sha256")}
		actual, e := readMariaDBBackup(expected.InstanceID, expected.ID)
		if e != nil || actual.DatabaseID != expected.DatabaseID || actual.DatabaseName != expected.DatabaseName || actual.Version != expected.Version || actual.Bytes != expected.Bytes || actual.SHA256 != expected.SHA256 {
			respond(w, 409, map[string]string{"error": "MariaDB 备份清单与下载请求不匹配"})
			return
		}
		if e = verifyMariaDBBackup(actual); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		file, e := privateMariaDBBackupFile(filepath.Join(mariaDBBackupDir(actual.InstanceID), actual.ID+".sql"))
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		defer file.Close()
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
		w.Header().Set("Content-Type", "application/sql")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": actual.DatabaseName + "-" + actual.ID[:8] + ".sql"}))
		w.Header().Set("Content-Length", strconv.FormatInt(actual.Bytes, 10))
		w.Header().Set("X-Content-SHA256", actual.SHA256)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = io.CopyN(w, file, actual.Bytes)
	})
}
