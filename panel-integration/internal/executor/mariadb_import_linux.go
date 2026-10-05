//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

func importMariaDBSQL(ctx context.Context, databaseID, confirm string, size int64, input io.Reader) (safety core.MariaDBBackup, sha string, ret error) {
	manifest, instance, e := findMariaDBDatabase(databaseID)
	if e != nil {
		return safety, "", e
	}
	if confirm != manifest.Database.Name {
		return safety, "", errors.New("请输入完整数据库名称确认导入")
	}
	if size < 1 || size > 4*1024*1024*1024 {
		return safety, "", errors.New("MariaDB SQL 文件大小无效")
	}
	dir := mariaDBBackupDir(instance.ID)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return safety, "", e
	}
	var disk syscall.Statfs_t
	if e = syscall.Statfs(dir, &disk); e != nil {
		return safety, "", e
	}
	if uint64(disk.Bavail)*uint64(disk.Bsize) < uint64(size)+512*1024*1024 {
		return safety, "", errors.New("SQL 上传后需保留至少 512 MiB 可用空间")
	}
	lock, e := os.OpenFile(filepath.Join(dir, "import.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return safety, "", e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return safety, "", errors.New("该 MariaDB 实例已有导入正在执行")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	temp, e := os.CreateTemp(dir, "import-*.sql.part")
	if e != nil {
		return safety, "", e
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if e = temp.Chmod(0600); e != nil {
		temp.Close()
		return safety, "", e
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(temp, h), &contextReader{ctx: ctx, r: io.LimitReader(input, size+1)})
	if e == nil {
		e = temp.Sync()
	}
	closeErr := temp.Close()
	if e != nil {
		return safety, "", errors.New("MariaDB SQL 上传中断，在线数据库未改变")
	}
	if closeErr != nil {
		return safety, "", closeErr
	}
	if n != size {
		return safety, "", errors.New("MariaDB SQL 上传长度不符，在线数据库未改变")
	}
	sha = hex.EncodeToString(h.Sum(nil))
	safety, e = createMariaDBBackupFor(ctx, manifest, instance, "")
	if e != nil {
		return safety, sha, errors.New("导入前安全备份失败，在线数据库未改变")
	}
	recreate := func(callCtx context.Context) error {
		_, er := mariaDBSQL(callCtx, instance, "DROP DATABASE `"+manifest.Database.Name+"`; CREATE DATABASE `"+manifest.Database.Name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
		return er
	}
	if e = recreate(ctx); e == nil {
		e = importMariaDBDump(ctx, instance, manifest.Database.Name, tempPath)
	}
	if e == nil {
		return safety, sha, nil
	}
	failed := e
	rollback := recreate(context.Background())
	if rollback == nil {
		rollback = importMariaDBDump(context.Background(), instance, manifest.Database.Name, filepath.Join(mariaDBBackupDir(instance.ID), safety.ID+".sql"))
	}
	if rollback == nil {
		return safety, sha, fmt.Errorf("MariaDB SQL 导入失败，已用安全备份回滚: %w", failed)
	}
	return safety, sha, fmt.Errorf("MariaDB SQL 导入失败且安全备份回滚失败: %v；回滚错误: %w", failed, rollback)
}

func mariaDBImportRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/mariadb/databases/{id}/import", func(w http.ResponseWriter, r *http.Request) {
		size, e := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if e != nil || r.ContentLength != size {
			respond(w, 400, map[string]string{"error": "MariaDB SQL 文件长度无效"})
			return
		}
		safety, sha, e := importMariaDBSQL(r.Context(), r.PathValue("id"), r.URL.Query().Get("confirm_name"), size, r.Body)
		if e != nil {
			respond(w, 409, map[string]any{"error": e.Error(), "safety_backup": safety, "sha256": sha})
			return
		}
		respond(w, 200, map[string]any{"ok": true, "safety_backup": safety, "sha256": sha, "bytes": size})
	})
}
