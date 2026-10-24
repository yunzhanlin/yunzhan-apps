//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const mariadbRoot = "/etc/panel/mariadb"

func mariadbConfig(id string) string { return filepath.Join(mariadbRoot, id) }
func mariadbData(id string) string   { return filepath.Join("/srv/panel/mariadb", id) }
func mariadbUnit(id string) string   { return "panel-mariadb@" + id + ".service" }

func readMariaDB(id string) (core.MariaDBInstance, error) {
	var instance core.MariaDBInstance
	if !core.ValidID(id) {
		return instance, errors.New("MariaDB 实例标识无效")
	}
	b, e := os.ReadFile(filepath.Join(mariadbConfig(id), "instance.json"))
	if e == nil {
		e = json.Unmarshal(b, &instance)
	}
	if e == nil && (instance.ID != id || core.ValidateMariaDBInstance(instance) != nil) {
		e = errors.New("MariaDB 实例清单不匹配")
	}
	return instance, e
}

func ServeMariaDB(id string) error {
	lock, e := runtimeUseLock()
	if e != nil {
		return e
	}
	defer lock.Close()
	instance, e := readMariaDB(id)
	if e != nil {
		return e
	}
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "mariadb" {
		return errors.New("MariaDB 版本不在固定目录")
	}
	if _, e = LoadRuntime(release.ID); e != nil {
		return e
	}
	u, e := user.Lookup("panel-mariadb")
	if e != nil {
		return e
	}
	uid, e := strconv.Atoi(u.Uid)
	if e != nil {
		return e
	}
	gid, e := strconv.Atoi(u.Gid)
	if e != nil {
		return e
	}
	if e = os.Chown("/run/panel-mariadb-"+id, uid, gid); e != nil {
		return e
	}
	if e = syscall.Setgroups([]int{gid}); e != nil {
		return e
	}
	if e = syscall.Setgid(gid); e != nil {
		return e
	}
	if e = syscall.Setuid(uid); e != nil {
		return e
	}
	binary := release.Prefix() + "/bin/mariadbd"
	return syscall.Exec(binary, []string{binary, "--defaults-file=" + filepath.Join(mariadbConfig(id), "my.cnf")}, []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent", "LD_LIBRARY_PATH=" + release.Prefix() + "/lib:" + release.Prefix() + "/lib64"})
}

func InitMariaDB(id string) error {
	instance, e := readMariaDB(id)
	if e != nil {
		return e
	}
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "mariadb" {
		return errors.New("MariaDB 版本不在固定目录")
	}
	if _, e = LoadRuntime(release.ID); e != nil {
		return e
	}
	u, e := user.Current()
	if e != nil || u.Username != "panel-mariadb" {
		return errors.New("MariaDB 初始化账户不正确")
	}
	data := mariadbData(instance.ID)
	init := exec.Command(release.Prefix()+"/scripts/mariadb-install-db", "--no-defaults", "--basedir="+release.Prefix(), "--datadir="+data, "--auth-root-authentication-method=socket", "--skip-test-db")
	init.Env = mariadbEnv(release)
	if out, er := init.CombinedOutput(); er != nil {
		return fmt.Errorf("MariaDB 初始化失败: %v: %s", er, string(out))
	}
	return ordinary(filepath.Join(data, "mysql"), true)
}

func mariadbPing(ctx context.Context, instance core.MariaDBInstance) error {
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok {
		return errors.New("MariaDB 版本不存在")
	}
	// First boot creates and opens several InnoDB files. Under emulated x86 this
	// can take around a minute, while subsequent starts are much faster.
	for i := 0; i < 300; i++ {
		cmd := exec.CommandContext(ctx, release.Prefix()+"/bin/mariadb-admin", "--no-defaults", "--socket="+filepath.Join("/run/panel-mariadb-"+instance.ID, "mariadb.sock"), "--user=root", "ping")
		cmd.Env = mariadbEnv(release)
		out, e := cmd.CombinedOutput()
		if e == nil && strings.Contains(string(out), "mysqld is alive") {
			query := exec.CommandContext(ctx, release.Prefix()+"/bin/mariadb", "--no-defaults", "--socket="+filepath.Join("/run/panel-mariadb-"+instance.ID, "mariadb.sock"), "--user=root", "--batch", "--skip-column-names", "-e", "SELECT VERSION()")
			query.Env = mariadbEnv(release)
			info, er := query.CombinedOutput()
			if er == nil && strings.HasPrefix(strings.TrimSpace(string(info)), release.Version) {
				return nil
			}
			if er == nil {
				return errors.New("MariaDB 实际版本与实例清单不匹配")
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.New("MariaDB 未在期限内通过 PING 与版本检查")
}

func mariadbEnv(release runtimecatalog.Release) []string {
	return []string{"PATH=" + release.Prefix() + "/bin:/usr/bin:/bin", "LANG=C", "HOME=/nonexistent", "LD_LIBRARY_PATH=" + release.Prefix() + "/lib:" + release.Prefix() + "/lib64"}
}

func createMariaDB(ctx context.Context, instance core.MariaDBInstance) (ret error) {
	if e := core.ValidateMariaDBInstance(instance); e != nil {
		return e
	}
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "mariadb" {
		return errors.New("MariaDB 版本不在固定目录")
	}
	if _, e := LoadRuntime(release.ID); e != nil {
		return errors.New("请先安装所选 MariaDB 版本")
	}
	entries, e := os.ReadDir(mariadbRoot)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		other, er := readMariaDB(entry.Name())
		if er != nil {
			continue
		}
		count++
		if other.Name == instance.Name {
			return errors.New("MariaDB 实例名称已被使用")
		}
		if other.Port == instance.Port {
			return errors.New("MariaDB 实例端口已被使用")
		}
	}
	if count >= 32 {
		return errors.New("MariaDB 实例数量已达到 32 个上限")
	}
	listener, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", instance.Port))
	if e != nil {
		return errors.New("MariaDB 实例端口已被其他服务使用")
	}
	listener.Close()
	u, e := user.Lookup("panel-mariadb")
	if e != nil {
		return errors.New("MariaDB 服务账户不存在，请重新运行安装程序")
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	cfg, data := mariadbConfig(instance.ID), mariadbData(instance.ID)
	if _, e = os.Lstat(cfg); !errors.Is(e, os.ErrNotExist) {
		return errors.New("MariaDB 实例目录已存在")
	}
	if _, e = os.Lstat(data); !errors.Is(e, os.ErrNotExist) {
		return errors.New("MariaDB 数据目录已存在")
	}
	created := false
	defer func() {
		if ret != nil && !created {
			_, _ = RunCommand(context.Background(), "/usr/bin/systemctl", "disable", "--now", mariadbUnit(instance.ID))
			_ = os.RemoveAll(cfg)
			_ = os.RemoveAll(data)
		}
	}()
	if e = os.MkdirAll(cfg, 0750); e != nil {
		return e
	}
	if e = os.Chown(cfg, 0, gid); e != nil {
		return e
	}
	if e = os.MkdirAll(data, 0700); e != nil {
		return e
	}
	if e = os.Chown(data, uid, gid); e != nil {
		return e
	}
	config := fmt.Sprintf("[mariadbd]\nbasedir=%s\ndatadir=%s\nsocket=/run/panel-mariadb-%s/mariadb.sock\npid-file=/run/panel-mariadb-%s/mariadb.pid\nport=%d\nbind-address=127.0.0.1\nskip-name-resolve\nlocal-infile=0\nmax-connections=100\ninnodb-buffer-pool-size=%dM\nperformance-schema=OFF\nskip-log-bin\ncharacter-set-server=utf8mb4\ncollation-server=utf8mb4_unicode_ci\nplugin-dir=%s/lib/plugin\n", release.Prefix(), data, instance.ID, instance.ID, instance.Port, instance.MemoryMB, release.Prefix())
	if e = atomicWrite(filepath.Join(cfg, "my.cnf"), []byte(config), 0640); e != nil {
		return e
	}
	if e = os.Chown(filepath.Join(cfg, "my.cnf"), 0, gid); e != nil {
		return e
	}
	b, _ := json.Marshal(instance)
	if e = atomicWrite(filepath.Join(cfg, "instance.json"), b, 0640); e != nil {
		return e
	}
	if e = os.Chown(filepath.Join(cfg, "instance.json"), 0, gid); e != nil {
		return e
	}
	if _, e = RunCommand(ctx, "/usr/bin/systemctl", "start", mariadbInitUnit(instance.ID)); e != nil {
		return e
	}
	if _, e = RunCommand(ctx, "/usr/bin/systemctl", "enable", "--now", mariadbUnit(instance.ID)); e != nil {
		return e
	}
	if e = mariadbPing(ctx, instance); e != nil {
		return e
	}
	created = true
	return nil
}

func mariadbInitUnit(id string) string { return "panel-mariadb-init@" + id + ".service" }

func inspectMariaDB(ctx context.Context, instance core.MariaDBInstance) core.MariaDBInstance {
	instance.Status = "stopped"
	state, _ := RunCommand(ctx, "/usr/bin/systemctl", "is-active", mariadbUnit(instance.ID))
	if strings.TrimSpace(state) != "active" {
		return instance
	}
	instance.Status = "running"
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok {
		instance.Status = "needs_attention"
		return instance
	}
	query := exec.CommandContext(ctx, release.Prefix()+"/bin/mariadb", "--no-defaults", "--socket=/run/panel-mariadb-"+instance.ID+"/mariadb.sock", "--user=root", "--batch", "--skip-column-names", "-e", "SELECT COUNT(*) FROM information_schema.PROCESSLIST; SELECT COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH),0) FROM information_schema.TABLES")
	query.Env = mariadbEnv(release)
	info, e := query.CombinedOutput()
	if e != nil {
		instance.Status = "starting"
		return instance
	}
	lines := strings.Fields(string(info))
	if len(lines) >= 2 {
		instance.Connections, _ = strconv.Atoi(lines[0])
		instance.DataBytes, _ = strconv.ParseInt(lines[1], 10, 64)
	}
	return instance
}

func listMariaDB(ctx context.Context) ([]core.MariaDBInstance, error) {
	entries, e := os.ReadDir(mariadbRoot)
	if errors.Is(e, os.ErrNotExist) {
		return []core.MariaDBInstance{}, nil
	}
	if e != nil {
		return nil, e
	}
	out := []core.MariaDBInstance{}
	for _, entry := range entries {
		if !entry.IsDir() || !core.ValidID(entry.Name()) {
			continue
		}
		instance, er := readMariaDB(entry.Name())
		if er == nil {
			out = append(out, inspectMariaDB(ctx, instance))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (s *Service) mariadbRoutes(m *http.ServeMux) {
	mariaDBBackupDownloadRoutes(m)
	mariaDBImportRoutes(m)
	m.HandleFunc("GET /v1/mariadb/backups", func(w http.ResponseWriter, r *http.Request) {
		items, e := listMariaDBBackups()
		if e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]any{"backups": items})
	})
	m.HandleFunc("POST /v1/mariadb/databases/{id}/backup", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ID string `json:"id"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		backup, e := createMariaDBBackup(r.Context(), r.PathValue("id"), in.ID)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 201, backup)
	})
	m.HandleFunc("POST /v1/mariadb/databases/{id}/restore", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			BackupID    string `json:"backup_id"`
			ConfirmName string `json:"confirm_name"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		safety, e := restoreMariaDBBackup(r.Context(), r.PathValue("id"), in.BackupID, in.ConfirmName)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]any{"ok": true, "safety_backup": safety})
	})
	m.HandleFunc("DELETE /v1/mariadb/backups/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if e := deleteMariaDBBackup(r.PathValue("id"), in.ConfirmName); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	m.HandleFunc("DELETE /v1/mariadb/backups/{id}/scheduled", func(w http.ResponseWriter, r *http.Request) {
		backup, e := findMariaDBBackup(r.PathValue("id"))
		bytes, bytesErr := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if e != nil || bytesErr != nil || backup.DatabaseID != r.URL.Query().Get("database_id") || backup.InstanceID != r.URL.Query().Get("instance_id") || backup.Bytes != bytes || backup.SHA256 != r.URL.Query().Get("sha256") {
			respond(w, 409, map[string]string{"error": "MariaDB 计划备份清理身份或摘要不匹配"})
			return
		}
		if e = verifyMariaDBBackup(backup); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		for _, ext := range []string{".sql", ".json"} {
			if e = os.Remove(filepath.Join(mariaDBBackupDir(backup.InstanceID), backup.ID+ext)); e != nil && !errors.Is(e, os.ErrNotExist) {
				respond(w, 409, map[string]string{"error": e.Error()})
				return
			}
		}
		respond(w, 200, map[string]bool{"deleted": true})
	})
	m.HandleFunc("POST /v1/mariadb/migrations/mysql", func(w http.ResponseWriter, r *http.Request) {
		var in core.MySQLToMariaDBMigration
		if !readJSON(w, r, &in) {
			return
		}
		out, e := migrateMySQLToMariaDB(r.Context(), in)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 201, out)
	})
	m.HandleFunc("GET /v1/mariadb/databases", func(w http.ResponseWriter, r *http.Request) {
		items, e := listMariaDBDatabases()
		if e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]any{"databases": items})
	})
	m.HandleFunc("POST /v1/mariadb/instances/{id}/databases", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name string `json:"name"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		instance, e := readMariaDB(r.PathValue("id"))
		if e != nil || !core.ValidDatabaseName(in.Name) {
			respond(w, 400, map[string]string{"error": "MariaDB 实例或数据库名称无效"})
			return
		}
		database, e := createMariaDBDatabase(r.Context(), instance, in.Name)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 201, database)
	})
	m.HandleFunc("POST /v1/mariadb/databases/{id}/credentials", func(w http.ResponseWriter, r *http.Request) {
		manifest, instance, e := findMariaDBDatabase(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": "MariaDB 数据库不存在"})
			return
		}
		respond(w, 200, map[string]any{"host": "127.0.0.1", "port": instance.Port, "database": manifest.Database.Name, "username": manifest.Database.Username, "password": manifest.Password})
	})
	m.HandleFunc("POST /v1/mariadb/databases/{id}/credentials/rotate", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		out, e := rotateMariaDBCredential(r.Context(), r.PathValue("id"), in.ConfirmName)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("DELETE /v1/mariadb/databases/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if e := deleteMariaDBDatabase(r.Context(), r.PathValue("id"), in.ConfirmName); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	m.HandleFunc("GET /v1/mariadb/instances", func(w http.ResponseWriter, r *http.Request) {
		items, e := listMariaDB(r.Context())
		if e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]any{"instances": items})
	})
	m.HandleFunc("POST /v1/mariadb/instances", func(w http.ResponseWriter, r *http.Request) {
		var in core.MariaDBInstance
		if !readJSON(w, r, &in) {
			return
		}
		if e := createMariaDB(r.Context(), in); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 201, inspectMariaDB(r.Context(), in))
	})
	m.HandleFunc("POST /v1/mariadb/instances/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		instance, e := readMariaDB(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": "MariaDB 实例不存在"})
			return
		}
		action := r.PathValue("action")
		if action != "start" && action != "stop" && action != "restart" {
			respond(w, 400, map[string]string{"error": "MariaDB 操作无效"})
			return
		}
		if _, e = RunCommand(r.Context(), "/usr/bin/systemctl", action, mariadbUnit(instance.ID)); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		if action != "stop" {
			if e = mariadbPing(r.Context(), instance); e != nil {
				respond(w, 409, map[string]string{"error": e.Error()})
				return
			}
		}
		respond(w, 200, inspectMariaDB(r.Context(), instance))
	})
	m.HandleFunc("GET /v1/mariadb/instances/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		if _, e := readMariaDB(r.PathValue("id")); e != nil {
			respond(w, 404, map[string]string{"error": "MariaDB 实例不存在"})
			return
		}
		out, e := RunCommand(r.Context(), "/usr/bin/journalctl", "-u", mariadbUnit(r.PathValue("id")), "-n", "200", "--no-pager", "--output=short-iso")
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]string{"content": out})
	})
	m.HandleFunc("DELETE /v1/mariadb/instances/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		instance, e := readMariaDB(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": "MariaDB 实例不存在"})
			return
		}
		if in.ConfirmName != instance.Name {
			respond(w, 409, map[string]string{"error": "请输入实例名称确认删除"})
			return
		}
		if entries, er := os.ReadDir(mariaDBDatabasesDir(instance.ID)); er == nil && len(entries) > 0 {
			respond(w, 409, map[string]string{"error": "实例仍有受管数据库，请先逐库删除"})
			return
		} else if er != nil && !errors.Is(er, os.ErrNotExist) {
			respond(w, 409, map[string]string{"error": er.Error()})
			return
		}
		if entries, er := os.ReadDir(mariaDBBackupDir(instance.ID)); er == nil {
			for _, entry := range entries {
				if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
					respond(w, 409, map[string]string{"error": "实例仍有 MariaDB 备份，请先删除备份"})
					return
				}
			}
		} else if er != nil && !errors.Is(er, os.ErrNotExist) {
			respond(w, 409, map[string]string{"error": er.Error()})
			return
		}
		if _, e = RunCommand(r.Context(), "/usr/bin/systemctl", "disable", "--now", mariadbUnit(instance.ID)); e != nil && !strings.Contains(e.Error(), "not loaded") {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		for _, dir := range []string{mariadbConfig(instance.ID), mariadbData(instance.ID)} {
			if e = ordinary(dir, true); e != nil {
				respond(w, 409, map[string]string{"error": e.Error()})
				return
			}
		}
		if e = os.RemoveAll(mariadbConfig(instance.ID)); e == nil {
			e = os.RemoveAll(mariadbData(instance.ID))
		}
		if e == nil {
			e = os.RemoveAll(mariaDBBackupDir(instance.ID))
		}
		if e != nil {
			respond(w, 500, map[string]string{"error": "删除 MariaDB 实例目录失败"})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
}
