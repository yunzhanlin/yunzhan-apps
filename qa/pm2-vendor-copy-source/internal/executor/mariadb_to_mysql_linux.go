//go:build linux

package executor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func mariaDBReadLock(ctx context.Context, instance core.MariaDBInstance) (func(), error) {
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "mariadb" {
		return nil, errors.New("MariaDB 源运行环境不存在")
	}
	cmd := exec.CommandContext(ctx, release.Prefix()+"/bin/mariadb", "--no-defaults", "--socket=/run/panel-mariadb-"+instance.ID+"/mariadb.sock", "--user=root", "--batch", "--skip-column-names", "--unbuffered")
	cmd.Env = mariadbEnv(release)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 2 * time.Second
	stdin, e := cmd.StdinPipe()
	if e != nil {
		return nil, e
	}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return nil, e
	}
	cmd.Stderr = io.Discard
	if e = cmd.Start(); e != nil {
		return nil, e
	}
	releaseLock := func() {
		_, _ = io.WriteString(stdin, "UNLOCK TABLES;\n")
		_ = stdin.Close()
		_ = cmd.Wait()
	}
	if _, e = io.WriteString(stdin, "SET SESSION lock_wait_timeout=10; FLUSH TABLES WITH READ LOCK; SELECT 'panel-mariadb-lock-held';\n"); e != nil {
		_ = cmd.Process.Kill()
		releaseLock()
		return nil, e
	}
	ready := make(chan bool, 1)
	go func() {
		line, er := bufio.NewReader(stdout).ReadString('\n')
		ready <- er == nil && strings.TrimSpace(line) == "panel-mariadb-lock-held"
	}()
	select {
	case yes := <-ready:
		if yes {
			return releaseLock, nil
		}
	case <-ctx.Done():
	case <-time.After(15 * time.Second):
	}
	_ = cmd.Process.Kill()
	releaseLock()
	return nil, errors.New("未能及时取得 MariaDB 源实例读锁，迁移尚未改变目标数据")
}

func mariaDBToMySQLCompatible(ctx context.Context, instance core.MariaDBInstance, database string) (int, error) {
	query := "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + database + "' AND TABLE_TYPE<>'BASE TABLE';" +
		" SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='" + database + "';" +
		" SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='" + database + "';" +
		" SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA='" + database + "';" +
		" SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + database + "' AND TABLE_TYPE='BASE TABLE' AND ENGINE<>'InnoDB';" +
		" SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + database + "' AND TABLE_TYPE='BASE TABLE';"
	out, e := mariaDBSQL(ctx, instance, query)
	if e != nil {
		return 0, e
	}
	values := strings.Fields(out)
	if len(values) != 6 {
		return 0, errors.New("MariaDB 到 MySQL 兼容检查结果不完整")
	}
	for _, value := range values[:4] {
		if value != "0" {
			return 0, errors.New("首版反向迁移只接受基础表；请先移除或单独转换视图、过程、触发器和事件")
		}
	}
	if values[4] != "0" {
		return 0, errors.New("首版反向迁移只接受 InnoDB 基础表")
	}
	tables, e := strconv.Atoi(values[5])
	if e != nil {
		return 0, errors.New("MariaDB 源表数量无效")
	}
	return tables, nil
}

func dumpMariaDBForMySQL(ctx context.Context, instance core.MariaDBInstance, database, target string) error {
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "mariadb" {
		return errors.New("MariaDB 源运行环境不存在")
	}
	f, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	ok = false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(target)
		}
	}()
	limited := &limitBackupWriter{w: f, remaining: crossEngineDumpLimit}
	cmd := exec.CommandContext(ctx, release.Prefix()+"/bin/mariadb-dump", "--no-defaults", "--socket=/run/panel-mariadb-"+instance.ID+"/mariadb.sock", "--user=root", "--single-transaction", "--skip-lock-tables", "--skip-add-locks", "--skip-triggers", "--skip-extended-insert", "--hex-blob", "--skip-comments", database)
	cmd.Env = mariadbEnv(release)
	cmd.Stdout = limited
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if e = cmd.Run(); e != nil {
		return fmt.Errorf("MariaDB 导出失败: %w: %s", e, strings.TrimSpace(stderr.String()))
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	ok = true
	return nil
}

func cleanupMigratedMySQL(ctx context.Context, server core.DatabaseServer, database core.Database) error {
	_, sqlErr := mysqlQuery(ctx, server, "DROP DATABASE IF EXISTS `"+database.Name+"`; DROP USER IF EXISTS '"+database.Username+"'@'localhost','"+database.Username+"'@'127.0.0.1';")
	dir := filepath.Join(mysqlConfig(server.ID), "databases")
	manifestErr := os.Remove(filepath.Join(dir, database.ID+".json"))
	if errors.Is(manifestErr, os.ErrNotExist) {
		manifestErr = nil
	}
	credentialErr := os.Remove(filepath.Join(dir, database.ID+".credential.json"))
	if errors.Is(credentialErr, os.ErrNotExist) {
		credentialErr = nil
	}
	return errors.Join(sqlErr, manifestErr, credentialErr)
}

func migrateMariaDBToMySQL(ctx context.Context, op core.DatabaseOperation, add func(string)) (ret error) {
	if op.SourceMariaDB == nil || core.ValidateMariaDBInstance(op.SourceMariaDB.Instance) != nil || core.ValidateMariaDBDatabase(op.SourceMariaDB.Database) != nil || op.SourceMariaDB.Database.InstanceID != op.SourceMariaDB.Instance.ID || !core.ValidDatabaseServer(op.Server) || !core.ValidID(op.Database.ID) || op.Database.ServerID != op.Server.ID || !core.ValidDatabaseName(op.Database.Name) || op.Database.Username != "db_"+op.Database.ID[:20] {
		return errors.New("MariaDB 到 MySQL 迁移任务参数无效")
	}
	sourceManifest, e := readMariaDBDatabase(op.SourceMariaDB.Instance.ID, op.SourceMariaDB.Database.ID)
	if e != nil || sourceManifest.Database.Name != op.SourceMariaDB.Database.Name {
		return errors.New("MariaDB 源数据库归属不匹配")
	}
	actualInstance, e := readMariaDB(op.SourceMariaDB.Instance.ID)
	if e != nil || actualInstance.ReleaseID != op.SourceMariaDB.Instance.ReleaseID {
		return errors.New("MariaDB 源实例清单不匹配")
	}
	if e = mariadbPing(ctx, actualInstance); e != nil {
		return e
	}
	if e = waitMySQL(ctx, op.Server); e != nil {
		return e
	}
	tables, e := mariaDBToMySQLCompatible(ctx, actualInstance, sourceManifest.Database.Name)
	if e != nil {
		return e
	}
	add("源与目标精确版本、认证和基础表兼容检查通过；申请短期 MariaDB 读锁")
	unlock, e := mariaDBReadLock(ctx, actualInstance)
	if e != nil {
		return e
	}
	defer unlock()
	add("MariaDB 源实例写入已暂停；任务结束或进程中断会自动释放读锁")
	before, e := fingerprintMariaDB(ctx, actualInstance, sourceManifest.Database)
	if e != nil {
		return e
	}
	dir := filepath.Join(mysqlBackups, "cross-engine")
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	dump, e := os.CreateTemp(dir, "mariadb-mysql-*.sql")
	if e != nil {
		return e
	}
	dumpPath := dump.Name()
	_ = dump.Close()
	_ = os.Remove(dumpPath)
	defer os.Remove(dumpPath)
	if e = dumpMariaDBForMySQL(ctx, actualInstance, sourceManifest.Database.Name, dumpPath); e != nil {
		return e
	}
	add("MariaDB 一致性逻辑导出完成，已记录逐行指纹与基础表清单")
	if e = createMySQLDatabase(ctx, op.Server, op.Database); e != nil {
		return e
	}
	committed := false
	defer func() {
		if ret != nil && !committed {
			if cleanup := cleanupMigratedMySQL(context.Background(), op.Server, op.Database); cleanup != nil {
				ret = fmt.Errorf("%w；MySQL 目标清理失败: %v", ret, cleanup)
			}
		}
	}()
	f, e := os.Open(dumpPath)
	if e != nil {
		return e
	}
	e = mysqlCommand(ctx, op.Server, "mysql", []string{"--binary-mode", "--database=" + op.Database.Name}, f, io.Discard)
	_ = f.Close()
	if e != nil {
		return e
	}
	after, e := fingerprintMySQL(ctx, op.Server, op.Database)
	if e != nil {
		return e
	}
	if before.Rows != after.Rows || before.Sum != after.Sum || before.Objects != after.Objects {
		return errors.New("MariaDB 源与 MySQL 目标逐行数据指纹或基础表清单不一致")
	}
	committed = true
	add(fmt.Sprintf("反向迁移核对通过：%d 张基础表、%d 行数据与 SHA-256 多重集指纹一致", tables, before.Rows))
	add("MySQL 独立目标数据库已就绪；MariaDB 源库保持不变，应用核对新连接信息后再切换")
	return nil
}
