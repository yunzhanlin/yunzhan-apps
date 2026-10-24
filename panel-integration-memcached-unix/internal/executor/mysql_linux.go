//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const mysqlRoot = "/etc/panel/mysql"
const mysqlJobs = "/var/lib/panel-executor/mysql-jobs"
const mysqlBackups = "/var/backups/panel/mysql"

type mysqlManifest struct {
	Server core.DatabaseServer `json:"server"`
	Ready  bool                `json:"ready"`
}
type mysqlJob struct {
	Operation core.DatabaseOperation `json:"operation"`
	Result    core.DatabaseResult    `json:"result"`
}
type mysqlCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func mysqlUser(id string) string   { return "ms" + id[:24] }
func mysqlDir(id string) string    { return "/srv/panel/mysql/" + id }
func mysqlConfig(id string) string { return mysqlRoot + "/" + id }
func mysqlSocket(id string) string { return "/run/panel-mysql-" + id + "/mysql.sock" }
func mysqlUnit(id string) string   { return "panel-mysql@" + id + ".service" }
func writeJSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return atomicWrite(path, b, 0600)
}
func readMySQL(id string) (mysqlManifest, error) {
	var m mysqlManifest
	if !core.ValidID(id) {
		return m, errors.New("无效实例标识")
	}
	b, e := os.ReadFile(mysqlConfig(id) + "/instance.json")
	if e == nil {
		e = json.Unmarshal(b, &m)
	}
	if e == nil && (!core.ValidDatabaseServer(m.Server) || m.Server.ID != id) {
		e = errors.New("实例清单不匹配")
	}
	return m, e
}
func PrepareMySQLUser(id string) error {
	if !core.ValidID(id) {
		return errors.New("无效实例标识")
	}
	name := mysqlUser(id)
	if u, e := user.Lookup(name); e == nil {
		if u.Name != "panel-mysql-"+id {
			return errors.New("系统用户不属于该实例")
		}
		return nil
	}
	_, e := RunCommand(context.Background(), "/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", mysqlDir(id), "--shell", "/usr/sbin/nologin", "--comment", "panel-mysql-"+id, name)
	return e
}
func ServeMySQL(id string) error {
	lock, lockErr := runtimeUseLock()
	if lockErr != nil {
		return lockErr
	}
	defer lock.Close()
	m, e := readMySQL(id)
	if e != nil {
		return e
	}
	r, _ := runtimecatalog.Find(m.Server.ReleaseID)
	if _, e = LoadRuntime(r.ID); e != nil {
		return e
	}
	u, e := user.Lookup(mysqlUser(id))
	if e != nil {
		return e
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if e = os.Chown("/run/panel-mysql-"+id, uid, gid); e != nil {
		return e
	}
	binary := r.Prefix() + "/bin/mysqld"
	args := []string{binary, "--defaults-file=" + mysqlConfig(id) + "/my.cnf", "--user=" + mysqlUser(id)}
	if !m.Ready {
		args = append(args, "--skip-networking", "--init-file="+mysqlConfig(id)+"/bootstrap.sql")
	}
	return syscall.Exec(binary, args, []string{"PATH=/usr/bin:/bin", "LANG=C", "LD_LIBRARY_PATH=" + r.Prefix() + "/lib/private:" + r.Prefix() + "/lib"})
}

// This CLI is only available to the local root administrator, never as HTTP SQL.
func DatabaseCLI(id string, args []string) error {
	lock, lockErr := runtimeUseLock()
	if lockErr != nil {
		return lockErr
	}
	defer lock.Close()
	m, e := readMySQL(id)
	if e != nil {
		return e
	}
	r, _ := runtimecatalog.Find(m.Server.ReleaseID)
	cmd := exec.Command(r.CLI(), append([]string{"--defaults-file=" + mysqlConfig(id) + "/root.cnf"}, args...)...)
	cmd.Env = mysqlEnv(r)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if e := cmd.Start(); e != nil {
		return e
	}
	lock.Close()
	return cmd.Wait()
}
func mysqlEnv(r runtimecatalog.Release) []string {
	return []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent", "MYSQL_HISTFILE=/dev/null", "LD_LIBRARY_PATH=" + r.Prefix() + "/lib/private:" + r.Prefix() + "/lib"}
}
func mysqlCommand(ctx context.Context, s core.DatabaseServer, program string, args []string, input io.Reader, output io.Writer) error {
	r, ok := runtimecatalog.Find(s.ReleaseID)
	if !ok || r.Family != "mysql" {
		return errors.New("无效 MySQL 版本")
	}
	if program != "mysql" && program != "mysqldump" {
		return errors.New("不允许的客户端")
	}
	argv := append([]string{"--defaults-file=" + mysqlConfig(s.ID) + "/root.cnf"}, args...)
	cmd := exec.CommandContext(ctx, r.Prefix()+"/bin/"+program, argv...)
	cmd.Env = mysqlEnv(r)
	cmd.Stdin = input
	cmd.Stdout = output
	// SQL and passwords never enter task logs, argv or audit messages. MySQL may
	// quote input in stderr, so retain only the error number in API-facing errors.
	errbuf := &boundedBuffer{max: 2048}
	cmd.Stderr = errbuf
	cmd.WaitDelay = 2 * time.Second
	if e := cmd.Run(); e != nil {
		detail := ""
		for _, line := range strings.Split(errbuf.String(), "\n") {
			if strings.HasPrefix(line, "ERROR ") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					detail = " (MySQL " + fields[1] + ")"
				}
				break
			}
		}
		return fmt.Errorf("MySQL %s 执行失败%s: %w", program, detail, e)
	}
	return nil
}
func mysqlQuery(ctx context.Context, s core.DatabaseServer, sql string) (string, error) {
	out := &boundedBuffer{max: 65536}
	e := mysqlCommand(ctx, s, "mysql", []string{"--batch", "--skip-column-names", "--raw", "--binary-mode"}, strings.NewReader(sql), out)
	if out.truncated && e == nil {
		e = errors.New("MySQL 查询输出超过核对限制")
	}
	return strings.TrimSpace(out.String()), e
}
func waitMySQL(ctx context.Context, s core.DatabaseServer) error {
	r, _ := runtimecatalog.Find(s.ReleaseID)
	for i := 0; i < 60; i++ {
		out, e := mysqlQuery(ctx, s, "SELECT @@version,@@port,@@datadir,@@socket;\n")
		if e == nil {
			fields := strings.Split(out, "\t")
			if len(fields) != 4 || fields[0] != r.Version || fields[2] != mysqlDir(s.ID)+"/data/" || fields[3] != mysqlSocket(s.ID) {
				return errors.New("实际 MySQL 版本、目录或 socket 不匹配")
			}
			m, er := readMySQL(s.ID)
			if er != nil {
				return er
			}
			if m.Ready && fields[1] != strconv.Itoa(s.Port) {
				return errors.New("实际 MySQL 端口不匹配")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("MySQL 未在期限内通过认证和实例参数检查，请核对实例日志")
}
func ensureCredential(path, username string) (mysqlCredential, error) {
	var c mysqlCredential
	b, e := os.ReadFile(path)
	if e == nil {
		e = json.Unmarshal(b, &c)
		if c.Username != username || len(c.Password) != 64 {
			return c, errors.New("私有凭据格式异常")
		}
		return c, e
	}
	if !errors.Is(e, os.ErrNotExist) {
		return c, e
	}
	c = mysqlCredential{Username: username, Password: core.ID() + core.ID()}
	return c, writeJSON(path, c)
}
func prepareMySQL(ctx context.Context, s core.DatabaseServer, add func(string)) error {
	if !core.ValidDatabaseServer(s) {
		return errors.New("无效实例参数")
	}
	if _, e := LoadRuntime(s.ReleaseID); e != nil {
		return e
	}
	if e := os.MkdirAll(mysqlConfig(s.ID), 0700); e != nil {
		return e
	}
	m, e := readMySQL(s.ID)
	if e == nil {
		if m.Server.ReleaseID != s.ReleaseID || m.Server.Port != s.Port || m.Server.Name != s.Name {
			return errors.New("禁止修改既有实例版本或复用其他数据目录")
		}
		if m.Ready {
			if _, e = RunCommand(ctx, "/usr/bin/systemctl", "enable", "--now", mysqlUnit(s.ID)); e != nil {
				return e
			}
			return waitMySQL(ctx, s)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	} else {
		m = mysqlManifest{Server: s}
		if e = writeJSON(mysqlConfig(s.ID)+"/instance.json", m); e != nil {
			return e
		}
	}
	listener, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.Port))
	if e != nil {
		return errors.New("目标 MySQL 端口已被使用")
	}
	listener.Close()
	if _, e = RunCommand(ctx, "/usr/bin/systemctl", "start", "panel-mysql-user@"+s.ID+".service"); e != nil {
		return e
	}
	u, e := user.Lookup(mysqlUser(s.ID))
	if e != nil {
		return e
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	for _, dir := range []string{mysqlDir(s.ID), mysqlDir(s.ID) + "/data", mysqlDir(s.ID) + "/logs", mysqlDir(s.ID) + "/tmp"} {
		if e = os.MkdirAll(dir, 0700); e != nil {
			return e
		}
		if e = ordinary(dir, true); e != nil {
			return e
		}
		if e = os.Chown(dir, uid, gid); e != nil {
			return e
		}
	}
	cfg := mysqlConfig(s.ID)
	if e = os.Chown(cfg, 0, gid); e != nil {
		return e
	}
	if e = os.Chmod(cfg, 0750); e != nil {
		return e
	}
	cred, e := ensureCredential(cfg+"/root.json", "root")
	if e != nil {
		return e
	}
	client := fmt.Sprintf("[client]\nuser=root\npassword=%s\nprotocol=SOCKET\nsocket=%s\n", cred.Password, mysqlSocket(s.ID))
	if e = atomicWrite(cfg+"/root.cnf", []byte(client), 0600); e != nil {
		return e
	}
	r, _ := runtimecatalog.Find(s.ReleaseID)
	config := fmt.Sprintf("[mysqld]\nbasedir=%s\ndatadir=%s/data\nsocket=%s\npid-file=/run/panel-mysql-%s/mysql.pid\nport=%d\nbind-address=127.0.0.1\nmysqlx=OFF\nlog-error=%s/logs/error.log\ntmpdir=%s/tmp\nsecure-file-priv=NULL\nlocal-infile=OFF\npartial-revokes=ON\nskip-name-resolve\ninnodb-buffer-pool-size=128M\ninnodb-redo-log-capacity=64M\nmax-connections=20\ntable-open-cache=128\nperformance-schema=OFF\nskip-log-bin\ncharacter-set-server=utf8mb4\ncollation-server=utf8mb4_0900_ai_ci\n", r.Prefix(), mysqlDir(s.ID), mysqlSocket(s.ID), s.ID, s.Port, mysqlDir(s.ID), mysqlDir(s.ID))
	if e = atomicWrite(cfg+"/my.cnf", []byte(config), 0640); e != nil {
		return e
	}
	if e = os.Chown(cfg+"/my.cnf", 0, gid); e != nil {
		return e
	}
	initSQL := "ALTER USER 'root'@'localhost' IDENTIFIED BY '" + cred.Password + "';\n"
	if e = atomicWrite(cfg+"/bootstrap.sql", []byte(initSQL), 0400); e != nil {
		return e
	}
	if e = os.Chown(cfg+"/bootstrap.sql", uid, gid); e != nil {
		return e
	}
	if _, e = os.Stat(mysqlDir(s.ID) + "/data/auto.cnf"); errors.Is(e, os.ErrNotExist) {
		entries, er := os.ReadDir(mysqlDir(s.ID) + "/data")
		if er != nil {
			return er
		}
		if len(entries) > 0 {
			return errors.New("数据目录非空且初始化未完成，拒绝覆盖，请核对恢复")
		}
		add("以独立系统用户初始化全新数据目录；初始化阶段不监听 TCP")
		cmd := exec.CommandContext(ctx, r.Prefix()+"/bin/mysqld", "--defaults-file="+cfg+"/my.cnf", "--initialize-insecure", "--user="+mysqlUser(s.ID))
		cmd.Env = mysqlEnv(r)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		cmd.WaitDelay = 2 * time.Second
		if e = cmd.Run(); e != nil {
			return fmt.Errorf("MySQL 初始化失败，请查看实例 error.log: %w", e)
		}
	} else if e != nil {
		return e
	}
	add("通过仅本机私有 socket 设置随机 root 密码并核对精确版本")
	if _, e = RunCommand(ctx, "/usr/bin/systemctl", "start", mysqlUnit(s.ID)); e != nil {
		return e
	}
	if e = waitMySQL(ctx, s); e != nil {
		return e
	}
	if _, e = RunCommand(ctx, "/usr/bin/systemctl", "stop", mysqlUnit(s.ID)); e != nil {
		return e
	}
	m.Ready = true
	if e = writeJSON(cfg+"/instance.json", m); e != nil {
		return e
	}
	if e = os.Remove(cfg + "/bootstrap.sql"); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if _, e = RunCommand(ctx, "/usr/bin/systemctl", "enable", "--now", mysqlUnit(s.ID)); e != nil {
		return e
	}
	return waitMySQL(ctx, s)
}
func readOwnedDatabase(s core.DatabaseServer, id string) (core.Database, error) {
	var db core.Database
	if !core.ValidID(id) {
		return db, errors.New("无效数据库标识")
	}
	b, e := os.ReadFile(mysqlConfig(s.ID) + "/databases/" + id + ".json")
	if e == nil {
		e = json.Unmarshal(b, &db)
	}
	if e == nil && (db.ID != id || db.ServerID != s.ID || !core.ValidDatabaseName(db.Name) || db.Username != "db_"+id[:20]) {
		e = errors.New("数据库归属不匹配")
	}
	return db, e
}
func createMySQLDatabase(ctx context.Context, s core.DatabaseServer, db core.Database) error {
	if !core.ValidID(db.ID) || db.ServerID != s.ID || !core.ValidDatabaseName(db.Name) || db.Username != "db_"+db.ID[:20] {
		return errors.New("无效数据库参数")
	}
	dir := mysqlConfig(s.ID) + "/databases"
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	old, e := readOwnedDatabase(s, db.ID)
	if e == nil {
		if old.Name != db.Name || old.Username != db.Username {
			return errors.New("数据库标识已被使用")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	} else {
		count, e := mysqlQuery(ctx, s, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+db.Name+"';\n")
		if e != nil {
			return e
		}
		if count != "0" {
			return errors.New("实例已有未由该任务创建的同名数据库")
		}
		if e = writeJSON(dir+"/"+db.ID+".json", db); e != nil {
			return e
		}
	}
	cred, e := ensureCredential(dir+"/"+db.ID+".credential.json", db.Username)
	if e != nil {
		return e
	}
	sql := "CREATE DATABASE IF NOT EXISTS `" + db.Name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;\n"
	for _, host := range []string{"localhost", "127.0.0.1"} {
		sql += "CREATE USER IF NOT EXISTS '" + db.Username + "'@'" + host + "' IDENTIFIED BY '" + cred.Password + "';\nGRANT ALL PRIVILEGES ON `" + db.Name + "`.* TO '" + db.Username + "'@'" + host + "';\n"
	}
	_, e = mysqlQuery(ctx, s, sql)
	return e
}
func backupMySQL(ctx context.Context, s core.DatabaseServer, db core.Database, b core.DatabaseBackup) (core.DatabaseBackup, error) {
	if !core.ValidID(b.ID) || b.DatabaseID != db.ID || b.ServerID != s.ID {
		return b, errors.New("无效备份归属")
	}
	dir := mysqlBackups + "/" + s.ID
	if e := os.MkdirAll(dir, 0700); e != nil {
		return b, e
	}
	meta := dir + "/" + b.ID + ".json"
	path := dir + "/" + b.ID + ".sql"
	if raw, e := os.ReadFile(meta); e == nil {
		var old core.DatabaseBackup
		if e = json.Unmarshal(raw, &old); e != nil {
			return b, e
		}
		if old.DatabaseID != db.ID || old.ServerID != s.ID {
			return b, errors.New("备份记录不匹配")
		}
		return old, verifyMySQLBackup(old)
	}
	f, e := os.OpenFile(path+".part", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return b, e
	}
	defer os.Remove(path + ".part")
	h := sha256.New()
	out := &limitBackupWriter{w: io.MultiWriter(f, h), remaining: 4 * 1024 * 1024 * 1024}
	e = mysqlCommand(ctx, s, "mysqldump", []string{"--single-transaction", "--routines", "--triggers", "--events", "--set-gtid-purged=OFF", "--no-tablespaces", "--column-statistics=0", db.Name}, nil, out)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return b, e
	}
	if ce != nil {
		return b, ce
	}
	if e = os.Rename(path+".part", path); e != nil {
		return b, e
	}
	b.Bytes = 4*1024*1024*1024 - out.remaining
	b.SHA256 = hex.EncodeToString(h.Sum(nil))
	r, _ := runtimecatalog.Find(s.ReleaseID)
	b.Version = r.Version
	if b.CreatedAt == "" {
		b.CreatedAt = core.Now()
	}
	return b, writeJSON(meta, b)
}

type limitBackupWriter struct {
	w         io.Writer
	remaining int64
}

func (w *limitBackupWriter) Write(b []byte) (int, error) {
	if int64(len(b)) > w.remaining {
		return 0, errors.New("备份超过当前 4 GiB 限制")
	}
	n, e := w.w.Write(b)
	w.remaining -= int64(n)
	return n, e
}
func verifyMySQLBackup(b core.DatabaseBackup) error {
	if !core.ValidID(b.ID) || !core.ValidID(b.ServerID) {
		return errors.New("无效备份标识")
	}
	path := mysqlBackups + "/" + b.ServerID + "/" + b.ID + ".sql"
	if e := ordinary(path, false); e != nil {
		return e
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 4*1024*1024*1024+1))
	if e != nil {
		return e
	}
	if n != b.Bytes || hex.EncodeToString(h.Sum(nil)) != b.SHA256 {
		return errors.New("备份大小或 SHA-256 不匹配，拒绝恢复")
	}
	return nil
}
func restoreMySQL(ctx context.Context, s core.DatabaseServer, db core.Database, b core.DatabaseBackup) error {
	r, _ := runtimecatalog.Find(s.ReleaseID)
	if b.DatabaseID != db.ID || b.ServerID != s.ID || b.Version != r.Version {
		return errors.New("备份不属于该数据库和精确版本；跨版本请走迁移")
	}
	if e := verifyMySQLBackup(b); e != nil {
		return e
	}
	_, e := mysqlQuery(ctx, s, "DROP DATABASE `"+db.Name+"`; CREATE DATABASE `"+db.Name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;\n")
	if e != nil {
		return e
	}
	f, e := os.Open(mysqlBackups + "/" + s.ID + "/" + b.ID + ".sql")
	if e != nil {
		return e
	}
	defer f.Close()
	return mysqlCommand(ctx, s, "mysql", []string{"--binary-mode", "--database=" + db.Name}, f, io.Discard)
}
func readMySQLJob(id string) (mysqlJob, error) {
	var j mysqlJob
	if !core.ValidID(id) {
		return j, errors.New("无效任务标识")
	}
	root, e := importRoot(mysqlJobs)
	if e != nil {
		return j, e
	}
	defer root.Close()
	f, e := openImportFile(root, id+".json")
	if e != nil {
		return j, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 2*1024*1024+1))
	if e != nil {
		return j, e
	}
	if len(b) > 2*1024*1024 {
		return j, errors.New("数据库任务记录超过限制")
	}
	e = json.Unmarshal(b, &j)
	return j, e
}
func RunDatabaseJob(id string) (ret error) {
	j, e := readMySQLJob(id)
	if e != nil {
		return e
	}
	op := j.Operation
	if op.JobID != id || !core.ValidDatabaseServer(op.Server) {
		return errors.New("任务参数无效")
	}
	if e = os.MkdirAll(mysqlRoot, 0755); e != nil {
		return e
	}
	ids := []string{op.Server.ID}
	if op.Action == "migrate_database" {
		if !core.ValidDatabaseServer(op.TargetServer) || op.TargetServer.ID == op.Server.ID {
			return errors.New("无效迁移目标")
		}
		ids = append(ids, op.TargetServer.ID)
	}
	sort.Strings(ids)
	for _, serverID := range ids {
		lock, er := os.OpenFile(mysqlJobs+"/"+serverID+".lock", os.O_CREATE|os.O_RDWR, 0600)
		if er != nil {
			return er
		}
		defer lock.Close()
		if er = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); er != nil {
			return er
		}
		defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	}

	j.Result = core.DatabaseResult{State: "running", Steps: []core.Step{}}
	add := func(msg string) {
		j.Result.Steps = append(j.Result.Steps, core.Step{Time: core.Now(), Message: msg})
		_ = writeJSON(mysqlJobs+"/"+id+".json", j)
	}
	defer func() {
		if ret != nil {
			j.Result.State = "failed"
			j.Result.Error = ret.Error()
			add(ret.Error())
		} else {
			j.Result.State = "succeeded"
		}
		if e := writeJSON(mysqlJobs+"/"+id+".json", j); ret == nil {
			ret = e
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	add("核对实例、精确版本、任务归属与独立执行锁")
	if op.Action == "create_instance" {
		if e = prepareMySQL(ctx, op.Server, add); e != nil {
			return e
		}
		j.Result.ServerStatus = "running"
		add("实际 SQL 认证、版本、端口、socket 和数据目录检查通过")
		return nil
	}
	m, e := readMySQL(op.Server.ID)
	if e != nil {
		return e
	}
	if !m.Ready || m.Server.ReleaseID != op.Server.ReleaseID || m.Server.Port != op.Server.Port {
		return errors.New("实例清单不匹配或初始化未完成")
	}
	switch op.Action {
	case "start_instance", "stop_instance", "restart_instance":
		action := strings.TrimSuffix(op.Action, "_instance")
		args := []string{action, mysqlUnit(op.Server.ID)}
		if action == "start" {
			args = []string{"enable", "--now", mysqlUnit(op.Server.ID)}
		} else if action == "stop" {
			args = []string{"disable", "--now", mysqlUnit(op.Server.ID)}
		}
		if _, e = RunCommand(ctx, "/usr/bin/systemctl", args...); e != nil {
			return e
		}
		if action == "stop" {
			active, _ := RunCommand(ctx, "/usr/bin/systemctl", "is-active", mysqlUnit(op.Server.ID))
			if strings.TrimSpace(active) == "active" {
				return errors.New("实例未停止")
			}
			j.Result.ServerStatus = "stopped"
		} else {
			if e = waitMySQL(ctx, op.Server); e != nil {
				return e
			}
			j.Result.ServerStatus = "running"
		}
		add("实例服务操作与实际状态核对完成")
	case "quarantine_database", "recover_database":
		if e = runDatabaseLifecycle(ctx, op, add); e != nil {
			return e
		}
	case "migrate_database":
		backup, er := migrateMySQL(ctx, op, add)
		j.Result.Backup = backup
		if er != nil {
			return er
		}
	case "migrate_mariadb_database":
		if e = migrateMariaDBToMySQL(ctx, op, add); e != nil {
			return e
		}
	case "create_account", "update_account", "rotate_account", "enable_account", "disable_account", "quarantine_account", "restore_account":
		if e = runMySQLAccountJob(ctx, op, add); e != nil {
			return e
		}
	case "import_database":
		if e = importMySQL(ctx, op, add); e != nil {
			return e
		}
	case "overwrite_database":
		j.Result.Backup, j.Result.DatabaseStatus, e = runDatabaseOverwrite(ctx, op, add)
		if e != nil {
			return e
		}
	case "create_database":
		if e = createMySQLDatabase(ctx, op.Server, op.Database); e != nil {
			return e
		}
		add("数据库与独立应用账号创建完成，权限限定于该数据库")
	case "backup_database", "restore_database":
		db, e := readOwnedDatabase(op.Server, op.Database.ID)
		if e != nil {
			return e
		}
		if db.Name != op.Database.Name {
			return errors.New("数据库名称不匹配")
		}
		if op.Action == "backup_database" {
			j.Result.Backup, e = backupMySQL(ctx, op.Server, db, op.Backup)
			if e != nil {
				return e
			}
			add("一致性逻辑备份完成，已记录大小、精确版本与 SHA-256")
		} else {
			if e = verifyMySQLBackup(op.Backup); e != nil {
				return e
			}
			before := core.DatabaseBackup{ID: id, DatabaseID: db.ID, ServerID: op.Server.ID, CreatedAt: core.Now()}
			before, e = backupMySQL(ctx, op.Server, db, before)
			if e != nil {
				return e
			}
			j.Result.Backup = before
			add("恢复前备份完成，开始在该数据库恢复；其他数据库不受影响")
			if e = restoreMySQL(ctx, op.Server, db, op.Backup); e != nil {
				add("目标备份恢复失败，正在恢复操作前副本")
				re := restoreMySQL(context.Background(), op.Server, db, before)
				if re != nil {
					return fmt.Errorf("恢复失败且自动恢复未完成；保留恢复前副本 %s", before.ID)
				}
				return errors.New("恢复失败，已恢复操作前数据")
			}
			add("备份恢复完成，操作前副本已保留")
		}
	default:
		return errors.New("不允许的数据库任务类型")
	}
	return nil
}
func mysqlRoutes(m *http.ServeMux) {
	mysqlOverwriteRoutes(m)
	mysqlBackupDownloadRoutes(m)
	mysqlImportRoutes(m)
	mysqlAccountRoutes(m)
	databaseLifecycleRoutes(m)
	m.HandleFunc("POST /v1/databases/jobs", func(w http.ResponseWriter, r *http.Request) {
		var op core.DatabaseOperation
		if !readJSON(w, r, &op) {
			return
		}
		if !core.ValidID(op.JobID) || !core.ValidDatabaseServer(op.Server) {
			respond(w, 400, map[string]string{"error": "数据库任务参数无效"})
			return
		}
		switch op.Action {
		case "create_instance", "start_instance", "stop_instance", "restart_instance", "create_database", "backup_database", "restore_database", "migrate_database", "migrate_mariadb_database", "import_database", "overwrite_database", "create_account", "update_account", "rotate_account", "enable_account", "disable_account", "quarantine_account", "restore_account", "quarantine_database", "recover_database":
		default:
			respond(w, 400, map[string]string{"error": "操作不允许"})
			return
		}
		lock, lockErr := runtimeUseLock()
		if lockErr != nil {
			respond(w, 409, map[string]string{"error": lockErr.Error()})
			return
		}
		defer lock.Close()
		releases := []string{op.Server.ReleaseID}
		if op.Action == "migrate_database" {
			releases = append(releases, op.TargetServer.ReleaseID)
		}
		if op.Action == "migrate_mariadb_database" && op.SourceMariaDB != nil {
			releases = append(releases, op.SourceMariaDB.Instance.ReleaseID)
		}
		for _, release := range releases {
			if _, e := LoadRuntime(release); e != nil {
				respond(w, 409, map[string]string{"error": "任务引用的运行环境未完整安装"})
				return
			}
		}
		if e := os.MkdirAll(mysqlJobs, 0700); e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		old, e := readMySQLJob(op.JobID)
		if e == nil {
			a, _ := json.Marshal(old.Operation)
			b, _ := json.Marshal(op)
			if string(a) != string(b) {
				respond(w, 409, map[string]string{"error": "任务参数已变化"})
				return
			}
			active, _ := RunCommand(r.Context(), "/usr/bin/systemctl", "show", "-p", "ActiveState", "--value", "panel-mysql-job@"+op.JobID+".service")
			if old.Result.State == "succeeded" || strings.TrimSpace(active) == "activating" || strings.TrimSpace(active) == "active" {
				respond(w, 202, old.Result)
				return
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		j := mysqlJob{Operation: op, Result: core.DatabaseResult{State: "queued", Steps: []core.Step{}}}
		if e = writeJSON(mysqlJobs+"/"+op.JobID+".json", j); e == nil {
			_, e = RunCommand(r.Context(), "/usr/bin/systemctl", "start", "--no-block", "panel-mysql-job@"+op.JobID+".service")
		}
		if e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 202, j.Result)
	})
	m.HandleFunc("GET /v1/databases/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		j, e := readMySQLJob(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": "任务不存在"})
			return
		}
		if j.Result.State == "running" || j.Result.State == "queued" {
			active, _ := RunCommand(r.Context(), "/usr/bin/systemctl", "show", "-p", "ActiveState", "--value", "panel-mysql-job@"+j.Operation.JobID+".service")
			if strings.TrimSpace(active) == "failed" || strings.TrimSpace(active) == "inactive" {
				// A oneshot can become inactive in the narrow interval between its
				// final atomic journal publish and this status read. Re-read the
				// journal before classifying the task as interrupted.
				for attempt := 0; attempt < 5; attempt++ {
					time.Sleep(100 * time.Millisecond)
					latest, er := readMySQLJob(j.Operation.JobID)
					if er == nil {
						j = latest
					}
					if j.Result.State == "succeeded" || j.Result.State == "failed" {
						break
					}
				}
				if j.Result.State == "running" || j.Result.State == "queued" {
					j.Result.State = "failed"
					j.Result.Error = "数据库执行进程已停止，可核对后重试"
				}
			}
		}
		respond(w, 200, j.Result)
	})
	m.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) {
		out := []map[string]any{}
		entries, _ := os.ReadDir(mysqlRoot)
		for _, entry := range entries {
			m, e := readMySQL(entry.Name())
			if e != nil {
				continue
			}
			status, _ := RunCommand(r.Context(), "/usr/bin/systemctl", "is-active", mysqlUnit(m.Server.ID))
			item := map[string]any{"id": m.Server.ID, "service_state": strings.TrimSpace(status), "port": m.Server.Port, "release_id": m.Server.ReleaseID, "data_dir": mysqlDir(m.Server.ID) + "/data", "socket": mysqlSocket(m.Server.ID), "system_user": mysqlUser(m.Server.ID)}
			if strings.TrimSpace(status) == "active" && m.Ready {
				q, e := mysqlQuery(r.Context(), m.Server, "SELECT @@version,@@port;\n")
				if e == nil {
					item["authenticated"] = true
					item["version"] = strings.Split(q, "\t")[0]
				} else {
					item["authenticated"] = false
				}
			}
			out = append(out, item)
		}
		respond(w, 200, map[string]any{"servers": out})
	})
	m.HandleFunc("POST /v1/databases/credentials", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ServerID   string `json:"server_id"`
			DatabaseID string `json:"database_id"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		m, e := readMySQL(in.ServerID)
		if e != nil {
			respond(w, 404, map[string]string{"error": "实例不存在"})
			return
		}
		db, e := readOwnedDatabase(m.Server, in.DatabaseID)
		if e != nil {
			respond(w, 404, map[string]string{"error": "数据库不存在"})
			return
		}
		if db.Status == "importing" || db.Status == "quarantined" {
			respond(w, 409, map[string]string{"error": "数据库导入尚未完成或已移入回收站"})
			return
		}
		var cred mysqlCredential
		b, e := os.ReadFile(mysqlConfig(m.Server.ID) + "/databases/" + db.ID + ".credential.json")
		if e == nil {
			e = json.Unmarshal(b, &cred)
		}
		if e != nil {
			respond(w, 500, map[string]string{"error": "读取私有凭据失败"})
			return
		}
		respond(w, 200, map[string]string{"username": cred.Username, "password": cred.Password, "host": "127.0.0.1", "port": strconv.Itoa(m.Server.Port), "database": db.Name, "socket": mysqlSocket(m.Server.ID)})
	})
}
