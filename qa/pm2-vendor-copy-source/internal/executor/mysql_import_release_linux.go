//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func readImportRelease(root *os.Root, id string) (core.DatabaseImportRelease, error) {
	var v core.DatabaseImportRelease
	if !core.ValidID(id) {
		return v, errors.New("无效上传标识")
	}
	f, e := openImportFile(root, id+".release.json")
	if e != nil {
		return v, e
	}
	defer f.Close()
	if e = json.NewDecoder(io.LimitReader(f, 32768)).Decode(&v); e != nil {
		return v, e
	}
	if !core.ValidDatabaseImport(v.Import, true) || v.Import.ID != id || !core.ValidID(v.Import.JobID) || !core.ValidID(v.DatabaseID) {
		return v, errors.New("SQL 清理标记归属无效")
	}
	if v.Completed {
		if _, e := time.Parse(time.RFC3339, v.ReleasedAt); e != nil {
			return v, errors.New("SQL 清理完成时间无效")
		}
	}
	return v, nil
}
func validImportReleaseJob(v core.DatabaseImport, j mysqlJob) bool {
	op := j.Operation
	identity := core.ValidDatabaseImport(v, true) && core.ValidID(v.JobID) && j.Result.State == "succeeded" && op.JobID == v.JobID && op.Import != nil && core.SameDatabaseImportIdentity(*op.Import, v) && core.ValidDatabaseServer(op.Server) && op.Server.ID == v.ServerID && core.ValidID(op.Database.ID) && op.Database.Name == v.Name && op.Database.ServerID == v.ServerID && op.Database.Username == "db_"+op.Database.ID[:20]
	if !identity {
		return false
	}
	if op.Action == "overwrite_database" {
		return validDatabaseOverwriteOperation(op) && j.Result.DatabaseStatus == "ready"
	}
	return op.Action == "import_database" && v.TargetDatabaseID == ""
}
func syncImportDirectory(base string) error {
	f, e := os.Open(base)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func releaseSQLImport(ctx context.Context, base string, v core.DatabaseImport, j mysqlJob) (core.DatabaseImportRelease, error) {
	var out core.DatabaseImportRelease
	op := j.Operation
	if !validImportReleaseJob(v, j) {
		return out, errors.New("只可清理原成功导入任务的 SQL 文件")
	}
	if op.Action == "overwrite_database" {
		journal, e := readOverwriteJournal(mysqlOverwrites, op.JobID)
		if e != nil || journal.Phase != "completed" || !sameOverwriteOperation(journal.Operation, op) {
			return out, errors.New("覆盖导入尚未确认交付，原上传继续保留")
		}
	}
	root, e := importRoot(base)
	if e != nil {
		return out, e
	}
	defer root.Close()
	lock, e := root.OpenFile("upload.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return out, e
	}
	defer lock.Close()
	info, e := lock.Stat()
	if e != nil {
		return out, e
	}
	if e = privateBackupEntry(info, false); e != nil {
		return out, e
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return out, errors.New("上传或清理正在进行，请稍后重试")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	claim, e := openImportFile(root, v.ID+".claim.json")
	if e != nil {
		return out, e
	}
	var bound struct {
		JobID      string
		DatabaseID string
	}
	e = json.NewDecoder(io.LimitReader(claim, 4096)).Decode(&bound)
	claim.Close()
	if e != nil || bound.JobID != v.JobID || bound.DatabaseID != op.Database.ID {
		return out, errors.New("SQL 任务认领不匹配")
	}
	meta, e := openImportFile(root, v.ID+".json")
	if e != nil {
		return out, e
	}
	var original core.DatabaseImport
	e = json.NewDecoder(io.LimitReader(meta, 16384)).Decode(&original)
	meta.Close()
	if e != nil || !core.SameDatabaseImportIdentity(original, v) {
		return out, errors.New("SQL 原上传清单不匹配")
	}
	out, e = readImportRelease(root, v.ID)
	if e == nil {
		if !core.SameDatabaseImportIdentity(out.Import, v) || out.Import.JobID != v.JobID || out.DatabaseID != op.Database.ID {
			return out, errors.New("SQL 清理标记已属于其他任务")
		}
		if out.Completed {
			if _, e = root.Lstat(v.ID + ".sql"); !errors.Is(e, os.ErrNotExist) {
				return out, errors.New("已清理 SQL 文件重新出现，拒绝覆盖或删除")
			}
			return out, syncImportDirectory(base)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return out, e
	} else {
		f, e := openSQLImport(ctx, base, v)
		if e != nil {
			return out, e
		}
		f.Close()
		out = core.DatabaseImportRelease{Import: v, DatabaseID: op.Database.ID}
		if e = writeJSON(filepath.Join(base, v.ID+".release.json"), out); e != nil {
			return out, e
		}
	}
	if _, e = root.Lstat(v.ID + ".sql"); e == nil {
		f, e := openSQLImport(ctx, base, v)
		if e != nil {
			return out, e
		}
		f.Close()
		if e = root.Remove(v.ID + ".sql"); e != nil {
			return out, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return out, e
	}
	if e = syncImportDirectory(base); e != nil {
		return out, e
	}
	out.Completed = true
	out.ReleasedAt = core.Now()
	if e = writeJSON(filepath.Join(base, v.ID+".release.json"), out); e != nil {
		return out, e
	}
	return out, nil
}
func releasedImportAlreadyDelivered(base string, op core.DatabaseOperation) (bool, error) {
	if op.Import == nil {
		return false, nil
	}
	root, e := importRoot(base)
	if e != nil {
		return false, e
	}
	defer root.Close()
	release, e := readImportRelease(root, op.Import.ID)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if !release.Completed {
		return false, errors.New("原导入已交付，上传清理尚未完成，请先核对清理记录")
	}
	if !core.SameDatabaseImportIdentity(release.Import, *op.Import) || release.Import.JobID != op.JobID || release.DatabaseID != op.Database.ID {
		return false, errors.New("已清理上传与导入任务归属不匹配")
	}
	if _, e = root.Lstat(op.Import.ID + ".sql"); !errors.Is(e, os.ErrNotExist) {
		return false, errors.New("已清理上传文件状态异常")
	}
	d, e := readLifecycleDatabase(op.Server, op.Database.ID)
	if e != nil {
		return false, e
	}
	if d.Name != op.Database.Name || d.Username != op.Database.Username || (d.Status != "ready" && d.Status != "quarantined") {
		return false, errors.New("原导入目标状态已变化，拒绝重新执行 SQL")
	}
	return true, nil
}
func mysqlImportReleaseRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/databases/imports/{id}/release", func(w http.ResponseWriter, r *http.Request) {
		var v core.DatabaseImport
		if !readJSON(w, r, &v) {
			return
		}
		if v.ID != r.PathValue("id") || !core.ValidDatabaseImport(v, true) || !core.ValidID(v.JobID) {
			respond(w, 400, map[string]string{"error": "清理对象无效"})
			return
		}
		// Read the successful executor journal through its private directory, rather
		// than trusting a claimed completion state from the HTTP caller.
		root, e := importRoot(mysqlJobs)
		if e != nil {
			respond(w, 409, map[string]string{"error": "任务目录不可核对"})
			return
		}
		defer root.Close()
		f, e := openImportFile(root, v.JobID+".json")
		if e != nil {
			respond(w, 409, map[string]string{"error": "原任务不可读取"})
			return
		}
		var j mysqlJob
		e = json.NewDecoder(io.LimitReader(f, 1024*1024)).Decode(&j)
		f.Close()
		if e != nil || !validImportReleaseJob(v, j) {
			respond(w, 409, map[string]string{"error": "原任务记录无效"})
			return
		}
		d, e := readLifecycleDatabase(j.Operation.Server, j.Operation.Database.ID)
		if e != nil || d.Name != v.Name || (d.Status != "ready" && d.Status != "quarantined") {
			respond(w, 409, map[string]string{"error": "原导入数据库尚未交付或状态已变化"})
			return
		}
		out, e := releaseSQLImport(r.Context(), mysqlImports, v, j)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
}
