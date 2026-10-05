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
	"strconv"
	"strings"
)

const crossEngineDumpLimit = int64(1024 * 1024 * 1024)

func mysqlToMariaDBCompatible(ctx context.Context, s core.DatabaseServer, database string) (int, error) {
	query := "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + database + "' AND TABLE_TYPE<>'BASE TABLE';" +
		" SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='" + database + "';" +
		" SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='" + database + "';" +
		" SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA='" + database + "';" +
		" SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + database + "' AND TABLE_TYPE='BASE TABLE';"
	out, e := mysqlQuery(ctx, s, query)
	if e != nil {
		return 0, e
	}
	lines := strings.Fields(out)
	if len(lines) != 5 {
		return 0, errors.New("跨引擎兼容检查结果不完整")
	}
	for _, value := range lines[:4] {
		if value != "0" {
			return 0, errors.New("首版跨引擎迁移只接受基础表；请先移除或单独转换视图、过程、触发器和事件")
		}
	}
	tables, e := strconv.Atoi(lines[4])
	if e != nil {
		return 0, errors.New("跨引擎表数量无效")
	}
	return tables, nil
}

func transformMySQLDump(source, target string) error {
	in, e := os.Open(source)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(target)
		}
	}()
	reader := bufio.NewReaderSize(in, 128*1024)
	var written int64
	for {
		line, er := reader.ReadString('\n')
		if len(line) > 16*1024*1024 {
			return errors.New("SQL 单行超过跨引擎迁移的 16 MiB 限制")
		}
		line = strings.ReplaceAll(line, "utf8mb4_0900_ai_ci", "utf8mb4_unicode_ci")
		line = strings.ReplaceAll(line, "utf8mb4_0900_bin", "utf8mb4_bin")
		written += int64(len(line))
		if written > crossEngineDumpLimit {
			return errors.New("SQL 超过首版跨引擎迁移的 1 GiB 限制")
		}
		if _, e = io.WriteString(out, line); e != nil {
			return e
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				break
			}
			return er
		}
	}
	if e = out.Sync(); e != nil {
		return e
	}
	if e = out.Close(); e != nil {
		return e
	}
	ok = true
	return nil
}

func fingerprintMariaDB(ctx context.Context, instance core.MariaDBInstance, database core.MariaDBDatabase) (mysqlFingerprint, error) {
	var result mysqlFingerprint
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "mariadb" {
		return result, errors.New("MariaDB 目标运行环境不存在")
	}
	w := &rowFingerprintWriter{}
	cmd := exec.CommandContext(ctx, release.Prefix()+"/bin/mariadb-dump", "--no-defaults", "--socket=/run/panel-mariadb-"+instance.ID+"/mariadb.sock", "--user=root", "--compact", "--no-create-info", "--skip-triggers", "--skip-extended-insert", "--skip-add-locks", "--hex-blob", "--skip-comments", "--skip-lock-tables", database.Name)
	cmd.Env = mariadbEnv(release)
	cmd.Stdout = w
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if e := cmd.Run(); e != nil {
		return result, fmt.Errorf("MariaDB 数据指纹失败: %w: %s", e, strings.TrimSpace(stderr.String()))
	}
	if len(w.pending) > 0 {
		return result, errors.New("MariaDB 数据指纹输出不完整")
	}
	result.Rows = w.rows
	result.Sum = fmt.Sprintf("%064x", &w.sum)
	result.Objects, _ = mariaDBSQL(ctx, instance, "SELECT CONCAT('table:',TABLE_NAME,':',TABLE_TYPE) FROM information_schema.TABLES WHERE TABLE_SCHEMA='"+database.Name+"' ORDER BY 1;")
	return result, nil
}

func importMariaDBDump(ctx context.Context, instance core.MariaDBInstance, database, path string) error {
	release, ok := runtimecatalog.Find(instance.ReleaseID)
	if !ok || release.Family != "mariadb" {
		return errors.New("MariaDB 目标运行环境不存在")
	}
	file, e := os.Open(path)
	if e != nil {
		return e
	}
	defer file.Close()
	cmd := exec.CommandContext(ctx, release.Prefix()+"/bin/mariadb", "--no-defaults", "--socket=/run/panel-mariadb-"+instance.ID+"/mariadb.sock", "--user=root", "--binary-mode", "--database="+database)
	cmd.Env = mariadbEnv(release)
	cmd.Stdin = file
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if e = cmd.Run(); e != nil {
		return fmt.Errorf("MariaDB 导入失败: %w: %s", e, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func migrateMySQLToMariaDB(ctx context.Context, request core.MySQLToMariaDBMigration) (result core.CrossEngineMigrationResult, ret error) {
	if !core.ValidDatabaseServer(request.SourceServer) || !core.ValidID(request.SourceDatabase.ID) || request.SourceDatabase.ServerID != request.SourceServer.ID || request.SourceDatabase.Status != "ready" || !core.ValidID(request.TargetInstanceID) || !core.ValidDatabaseName(request.TargetName) {
		return result, errors.New("MySQL 到 MariaDB 迁移参数无效")
	}
	source, e := readOwnedDatabase(request.SourceServer, request.SourceDatabase.ID)
	if e != nil || source.Name != request.SourceDatabase.Name {
		return result, errors.New("MySQL 源数据库归属不匹配")
	}
	target, e := readMariaDB(request.TargetInstanceID)
	if e != nil {
		return result, errors.New("MariaDB 目标实例不存在")
	}
	if e = waitMySQL(ctx, request.SourceServer); e != nil {
		return result, e
	}
	if e = mariadbPing(ctx, target); e != nil {
		return result, e
	}
	tables, e := mysqlToMariaDBCompatible(ctx, request.SourceServer, source.Name)
	if e != nil {
		return result, e
	}
	dir := mysqlBackups + "/cross-engine"
	if e = os.MkdirAll(dir, 0700); e != nil {
		return result, e
	}
	raw, e := os.CreateTemp(dir, "mysql-mariadb-*.sql.part")
	if e != nil {
		return result, e
	}
	rawPath := raw.Name()
	convertedPath := rawPath + ".compatible"
	defer os.Remove(rawPath)
	defer os.Remove(convertedPath)
	if e = raw.Chmod(0600); e != nil {
		raw.Close()
		return result, e
	}
	limit := &limitBackupWriter{w: raw, remaining: crossEngineDumpLimit}
	unlock, e := mysqlReadLock(ctx, request.SourceServer)
	if e != nil {
		raw.Close()
		return result, e
	}
	before, e := fingerprintMySQL(ctx, request.SourceServer, source)
	if e == nil {
		e = mysqlCommand(ctx, request.SourceServer, "mysqldump", []string{"--single-transaction", "--skip-lock-tables", "--skip-add-locks", "--skip-triggers", "--set-gtid-purged=OFF", "--no-tablespaces", "--column-statistics=0", "--skip-extended-insert", "--hex-blob", source.Name}, nil, limit)
	}
	unlock()
	if e == nil {
		e = raw.Sync()
	}
	closeErr := raw.Close()
	if e != nil {
		return result, e
	}
	if closeErr != nil {
		return result, closeErr
	}
	if e = transformMySQLDump(rawPath, convertedPath); e != nil {
		return result, e
	}
	database, e := createMariaDBDatabase(ctx, target, request.TargetName)
	if e != nil {
		return result, e
	}
	committed := false
	defer func() {
		if ret != nil && !committed {
			if cleanup := deleteMariaDBDatabase(context.Background(), database.ID, database.Name); cleanup != nil {
				ret = fmt.Errorf("%w；目标清理失败: %v", ret, cleanup)
			}
		}
	}()
	if e = importMariaDBDump(ctx, target, database.Name, convertedPath); e != nil {
		return result, e
	}
	after, e := fingerprintMariaDB(ctx, target, database)
	if e != nil {
		return result, e
	}
	if before.Rows != after.Rows || before.Sum != after.Sum || before.Objects != after.Objects {
		return result, errors.New("源与目标逐行数据指纹或基础表清单不一致，目标已清理，源库保持不变")
	}
	committed = true
	result = core.CrossEngineMigrationResult{Database: database, Rows: before.Rows, Tables: tables, Source: request.SourceServer.ReleaseID, Target: target.ReleaseID}
	return result, nil
}
