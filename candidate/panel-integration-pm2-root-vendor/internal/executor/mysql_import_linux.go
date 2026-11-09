//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const mysqlImports = "/var/lib/panel-executor/mysql-imports"

func importRoot(base string) (*os.Root, error) {
	if e := ownedRuntimePath(base, true); e != nil {
		return nil, e
	}
	info, e := os.Lstat(base)
	if e != nil {
		return nil, e
	}
	if e = privateBackupEntry(info, true); e != nil {
		return nil, e
	}
	return os.OpenRoot(base)
}
func openImportFile(root *os.Root, name string) (*os.File, error) {
	f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e == nil {
		e = privateBackupEntry(info, false)
	}
	if e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func openSQLImport(ctx context.Context, base string, v core.DatabaseImport) (*os.File, error) {
	if !core.ValidDatabaseImport(v, true) {
		return nil, errors.New("导入文件参数无效")
	}
	root, e := importRoot(base)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	meta, e := openImportFile(root, v.ID+".json")
	if e != nil {
		return nil, e
	}
	raw, e := io.ReadAll(io.LimitReader(meta, 16385))
	meta.Close()
	if e != nil {
		return nil, e
	}
	var old core.DatabaseImport
	if len(raw) > 16384 || json.Unmarshal(raw, &old) != nil || !core.SameDatabaseImportIdentity(old, v) {
		return nil, errors.New("导入清单与任务不一致")
	}
	f, e := openImportFile(root, v.ID+".sql")
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	h := sha256.New()
	n, e := io.Copy(h, &contextReader{ctx: ctx, r: io.LimitReader(f, core.MaxSQLImport+1)})
	if e != nil {
		return nil, e
	}
	if n != v.Bytes || hex.EncodeToString(h.Sum(nil)) != v.SHA256 {
		return nil, errors.New("导入 SQL 长度或 SHA-256 不符")
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return nil, e
	}
	ok = true
	return f, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(b []byte) (int, error) {
	if e := c.ctx.Err(); e != nil {
		return 0, e
	}
	return c.r.Read(b)
}

func stageSQLImport(ctx context.Context, base string, v core.DatabaseImport, input io.Reader) (core.DatabaseImport, error) {
	if !core.ValidDatabaseImport(v, false) {
		return v, errors.New("导入文件归属或大小无效")
	}
	if e := os.MkdirAll(base, 0700); e != nil {
		return v, e
	}
	root, e := importRoot(base)
	if e != nil {
		return v, e
	}
	defer root.Close()
	lock, e := root.OpenFile("upload.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return v, e
	}
	defer lock.Close()
	info, e := lock.Stat()
	if e != nil {
		return v, e
	}
	if e = privateBackupEntry(info, false); e != nil {
		return v, e
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return v, errors.New("另一个 SQL 文件正在上传，请稍后重试")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if _, e = root.Lstat(v.ID + ".release.json"); e == nil {
		return v, errors.New("该 SQL 上传已进入清理流程，不能重新上传此 ID")
	}
	if !errors.Is(e, os.ErrNotExist) {
		return v, e
	}
	var disk syscall.Statfs_t
	if e = syscall.Statfs(base, &disk); e != nil {
		return v, e
	}
	if uint64(disk.Bavail)*uint64(disk.Bsize) < uint64(v.Bytes)+512*1024*1024 {
		return v, errors.New("SQL 上传后需保留至少 512 MiB 可用空间")
	}
	entries, e := os.ReadDir(base)
	if e != nil {
		return v, e
	}
	var total int64
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sql") {
			info, e := entry.Info()
			if e != nil {
				return v, e
			}
			total += info.Size()
		}
	}
	if total+v.Bytes > 4*1024*1024*1024 {
		return v, errors.New("SQL 暂存文件已达 4 GiB 上限")
	}
	part := v.ID + ".part"
	if e = root.Remove(part); e != nil && !errors.Is(e, os.ErrNotExist) {
		return v, e
	}
	f, e := root.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return v, e
	}
	defer f.Close()
	defer root.Remove(part)
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), &contextReader{ctx: ctx, r: io.LimitReader(input, v.Bytes+1)})
	if e != nil {
		return v, errors.New("SQL 上传中断，可重传同一文件")
	}
	if n != v.Bytes {
		return v, errors.New("SQL 上传长度不符")
	}
	if e = f.Sync(); e != nil {
		return v, e
	}
	if e = f.Close(); e != nil {
		return v, e
	}
	v.SHA256 = hex.EncodeToString(h.Sum(nil))
	v.State = "staged"
	if old, e := openImportFile(root, v.ID+".sql"); e == nil {
		defer old.Close()
		h2 := sha256.New()
		n, e := io.Copy(h2, io.LimitReader(old, core.MaxSQLImport+1))
		if e != nil {
			return v, e
		}
		if n != v.Bytes || hex.EncodeToString(h2.Sum(nil)) != v.SHA256 {
			return v, errors.New("此上传记录已经保存不同内容，请新建导入")
		}
		if meta, e := openImportFile(root, v.ID+".json"); e == nil {
			var prior core.DatabaseImport
			err := json.NewDecoder(io.LimitReader(meta, 16384)).Decode(&prior)
			meta.Close()
			if err != nil || !core.SameDatabaseImportIdentity(prior, v) {
				return v, errors.New("上传记录已绑定其他目标")
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return v, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return v, e
	} else {
		if e = root.Rename(part, v.ID+".sql"); e != nil {
			return v, e
		}
	}
	if e = writeJSON(filepath.Join(base, v.ID+".json"), v); e != nil {
		return v, e
	}
	dir, e := os.Open(base)
	if e != nil {
		return v, e
	}
	defer dir.Close()
	return v, dir.Sync()
}
func mysqlImportRoutes(m *http.ServeMux) {
	mysqlImportReleaseRoutes(m)
	m.HandleFunc("DELETE /v1/databases/imports/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !core.ValidID(id) {
			respond(w, 400, map[string]string{"error": "导入标识无效"})
			return
		}
		if e := removeSQLImport(mysqlImports, id); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]bool{"removed": true})
	})

	m.HandleFunc("POST /v1/databases/imports/{id}/upload", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		size, e := strconv.ParseInt(q.Get("bytes"), 10, 64)
		v := core.DatabaseImport{ID: r.PathValue("id"), ServerID: q.Get("server_id"), Name: q.Get("name"), Bytes: size}
		if q.Get("target_database_id") != "" || q.Get("target_revision") != "" {
			v.TargetDatabaseID = q.Get("target_database_id")
			revision, er := strconv.ParseInt(q.Get("target_revision"), 10, 64)
			if er != nil {
				respond(w, 400, map[string]string{"error": "覆盖目标修订无效"})
				return
			}
			v.TargetRevision = revision
		}
		if e != nil || !core.ValidDatabaseImport(v, false) || r.ContentLength != size {
			respond(w, 400, map[string]string{"error": "SQL 上传参数或长度无效"})
			return
		}
		if _, e = readMySQL(v.ServerID); e != nil {
			respond(w, 409, map[string]string{"error": "实例不存在"})
			return
		}
		deadline := time.Now().Add(30 * time.Minute)
		ctrl := http.NewResponseController(w)
		_ = ctrl.SetReadDeadline(deadline)
		_ = ctrl.SetWriteDeadline(deadline)
		v, e = stageSQLImport(r.Context(), mysqlImports, v, http.MaxBytesReader(w, r.Body, core.MaxSQLImport))
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, v)
	})
}

// An anonymous sealed descriptor supplies credentials without a password in argv,
// a readable credential path, shell expansion, or a root SQL client process.
func importClient(ctx context.Context, s core.DatabaseServer, db core.Database, cred mysqlCredential, input io.Reader, output io.Writer) error {
	u, e := user.Lookup("panel-import")
	if e != nil || u.Name != "panel-sql-import" {
		return errors.New("缺少受限 SQL 导入系统用户，或现有用户归属不符")
	}
	uid, e := strconv.ParseUint(u.Uid, 10, 32)
	if e != nil || uid == 0 {
		return errors.New("导入用户 UID 无效")
	}
	gid, e := strconv.ParseUint(u.Gid, 10, 32)
	if e != nil || gid == 0 {
		return errors.New("导入用户 GID 无效")
	}
	if cred.Username != db.Username || len(cred.Password) != 64 || !core.ValidID(cred.Password[:32]) || !core.ValidID(cred.Password[32:]) {
		return errors.New("导入凭据无效")
	}
	fd, e := unix.MemfdCreate("panel-sql-client", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "panel-sql-client")
	defer f.Close()
	cfg := fmt.Sprintf("[client]\nuser=%s\npassword=%s\nprotocol=TCP\nhost=127.0.0.1\nport=%d\n", cred.Username, cred.Password, s.Port)
	if _, e = f.WriteString(cfg); e != nil {
		return e
	}
	if e = f.Chown(int(uid), int(gid)); e != nil {
		return e
	}
	if e = f.Chmod(0400); e != nil {
		return e
	}
	if _, e = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK); e != nil {
		return e
	}
	r, ok := runtimecatalog.Find(s.ReleaseID)
	if !ok || r.Family != "mysql" {
		return errors.New("无效 MySQL 版本")
	}
	args := []string{"--defaults-file=/proc/self/fd/3", "--binary-mode", "--local-infile=0", "--skip-reconnect", "--batch", "--skip-column-names", "--connect-timeout=10", "--default-character-set=utf8mb4", "--database=" + db.Name}
	cmd := exec.CommandContext(ctx, r.CLI(), args...)
	cmd.Env = mysqlEnv(r)
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{f}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	cmd.Stdin = input
	cmd.Stdout = output
	errbuf := &boundedBuffer{max: 4096}
	cmd.Stderr = errbuf
	cmd.WaitDelay = 2 * time.Second
	if e = cmd.Run(); e != nil {
		var exited *exec.ExitError
		if !errors.As(e, &exited) && ctx.Err() == nil {
			return fmt.Errorf("无法启动受限 SQL 客户端: %w", e)
		}
		code := ""
		for _, line := range strings.Split(errbuf.String(), "\n") {
			if strings.HasPrefix(line, "ERROR ") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					if n, e := strconv.Atoi(fields[1]); e == nil {
						code = fmt.Sprintf(" (MySQL %d)", n)
					}
				}
				break
			}
		}
		if ctx.Err() != nil {
			return errors.New("SQL 导入超时或中断；目标尚未交付，可重试原任务")
		}
		return errors.New("SQL 导入或认证失败" + code + "；请检查语法、数据库名、DEFINER 和权限，目标尚未交付")
	}
	return nil
}
func importMySQL(ctx context.Context, op core.DatabaseOperation, add func(string)) error {
	if op.Import == nil || !core.ValidDatabaseImport(*op.Import, true) || op.Import.ServerID != op.Server.ID || op.Import.Name != op.Database.Name || op.Database.Status != "importing" || !core.ValidID(op.Database.ID) {
		return errors.New("导入任务归属无效")
	}
	if delivered, e := releasedImportAlreadyDelivered(mysqlImports, op); e != nil {
		return e
	} else if delivered {
		add("原导入任务已成功交付且上传文件已清理，保留数据库当前内容")
		return nil
	}
	f, e := openSQLImport(ctx, mysqlImports, *op.Import)
	if e != nil {
		return e
	}
	defer f.Close()
	claim := mysqlImports + "/" + op.Import.ID + ".claim.json"
	raw, _ := json.Marshal(struct {
		JobID      string
		DatabaseID string
	}{op.JobID, op.Database.ID})
	if prior, e := os.ReadFile(claim); e == nil {
		if string(prior) != string(raw) {
			return errors.New("SQL 文件已绑定另一导入任务")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	} else {
		if e = atomicWrite(claim, raw, 0600); e != nil {
			return e
		}
	}
	old, e := readOwnedDatabase(op.Server, op.Database.ID)
	if e == nil {
		if old.Name != op.Database.Name {
			return errors.New("导入目标名称已变化")
		}
		if old.Status == "ready" {
			add("原任务已经完成交付，保留数据库现有内容")
			return nil
		}
		if old.Status != "importing" {
			return errors.New("拒绝覆盖已经存在的数据库")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = createMySQLDatabase(ctx, op.Server, op.Database); e != nil {
		return e
	}
	add("已保留新数据库标识，应用凭据在任务成功后提供")
	// Only this task's unpublished database may be reset after a partial import.
	if _, e = mysqlQuery(ctx, op.Server, "DROP DATABASE `"+op.Database.Name+"`; CREATE DATABASE `"+op.Database.Name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;\n"); e != nil {
		return e
	}
	cred, e := ensureCredential(mysqlConfig(op.Server.ID)+"/databases/"+op.Database.ID+".credential.json", op.Database.Username)
	if e != nil {
		return e
	}
	sql := ""
	for _, host := range []string{"localhost", "127.0.0.1"} {
		sql += "ALTER USER '" + cred.Username + "'@'" + host + "' IDENTIFIED BY '" + cred.Password + "' ACCOUNT UNLOCK;\n"
	}
	if _, e = mysqlQuery(ctx, op.Server, sql); e != nil {
		return e
	}
	add("使用目标库专属账号及非 root 系统用户执行 SQL；本地文件加载和客户端系统命令已关闭")
	if e = importClient(ctx, op.Server, op.Database, cred, f, io.Discard); e != nil {
		return e
	}
	if e = importClient(ctx, op.Server, op.Database, cred, strings.NewReader("SELECT DATABASE();\n"), io.Discard); e != nil {
		return e
	}
	count, e := mysqlQuery(ctx, op.Server, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='"+op.Database.Name+"';\n")
	if e != nil {
		return e
	}
	db := op.Database
	db.Status = "ready"
	if e = writeJSON(mysqlConfig(op.Server.ID)+"/databases/"+db.ID+".json", db); e != nil {
		return e
	}
	add("SQL 执行和应用账号重新认证通过，已交付新数据库；表与视图数量：" + count)
	return nil
}

func removeSQLImport(base, id string) error {
	if !core.ValidID(id) {
		return errors.New("无效导入标识")
	}
	root, e := importRoot(base)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	defer root.Close()
	lock, e := root.OpenFile("upload.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	info, e := lock.Stat()
	if e != nil {
		return e
	}
	if e = privateBackupEntry(info, false); e != nil {
		return e
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("上传正在写入，请稍后移除")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if _, e = root.Lstat(id + ".claim.json"); e == nil {
		return errors.New("导入已被任务引用，不能移除")
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	for _, suffix := range []string{".part", ".sql", ".json"} {
		if e = root.Remove(id + suffix); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	return nil
}
