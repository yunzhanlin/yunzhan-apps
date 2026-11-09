//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"slices"
	"sort"
	"strings"
	"time"
)

// Rebuild only the previously inspected, typed, local database privileges.
// EVENT is withheld during external SQL execution so a new scheduler event
// cannot keep writing outside the lifetime of the import client.
func overwriteAccessSQL(j mysqlOverwriteJournal, c mysqlCredential, restricted bool) (string, error) {
	if !validOverwriteJournal(j) || c.Username != j.Operation.Database.Username || len(c.Password) != 64 || !core.ValidID(c.Password[:32]) || !core.ValidID(c.Password[32:]) {
		return "", errors.New("覆盖认证或原权限记录无效")
	}
	var sql strings.Builder
	for _, host := range []string{"localhost", "127.0.0.1"} {
		identity := "'" + c.Username + "'@'" + host + "'"
		sql.WriteString("ALTER USER " + identity + " IDENTIFIED BY '" + c.Password + "' ACCOUNT LOCK;\n")
		sql.WriteString("ALTER USER " + identity + " DISCARD OLD PASSWORD;\n")
		sql.WriteString("REVOKE ALL PRIVILEGES, GRANT OPTION FROM " + identity + ";\n")
		ps := []string{}
		for _, p := range j.Grants[host] {
			if !restricted || p != "EVENT" {
				ps = append(ps, p)
			}
		}
		if len(ps) > 0 {
			sql.WriteString("GRANT " + strings.Join(ps, ", ") + " ON `" + j.Operation.Database.Name + "`.* TO " + identity + ";\n")
		}
	}
	return sql.String(), nil
}
func setOverwriteAccess(ctx context.Context, j mysqlOverwriteJournal, c mysqlCredential, restricted bool) error {
	sql, e := overwriteAccessSQL(j, c, restricted)
	if e != nil {
		return e
	}
	if _, e = mysqlQuery(ctx, j.Operation.Server, sql); e != nil {
		return e
	}
	return killMySQLAccountConnections(ctx, j.Operation.Server, databaseScopedIdentity(*j.Operation.PreviousDatabase))
}
func verifyOverwriteAccess(ctx context.Context, j mysqlOverwriteJournal, restricted, locked bool) error {
	d := *j.Operation.PreviousDatabase
	if e := verifyDatabaseIdentityBoundary(ctx, j.Operation.Server, d); e != nil {
		return e
	}
	for _, host := range []string{"localhost", "127.0.0.1"} {
		raw, e := mysqlQuery(ctx, j.Operation.Server, "SELECT PRIVILEGE_TYPE FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA='"+d.Name+"' AND GRANTEE=CONCAT(QUOTE('"+d.Username+"'),'@',QUOTE('"+host+"')) ORDER BY PRIVILEGE_TYPE;\n")
		if e != nil {
			return e
		}
		expected := []string{}
		for _, p := range j.Grants[host] {
			if !restricted || p != "EVENT" {
				expected = append(expected, p)
			}
		}
		sort.Strings(expected)
		actual := []string{}
		if raw != "" {
			actual = strings.Split(raw, "\n")
		}
		if !slices.Equal(expected, actual) {
			return errors.New("覆盖期间的实际数据库授权与保存范围不一致")
		}
		value, e := mysqlQuery(ctx, j.Operation.Server, "SELECT account_locked FROM mysql.user WHERE User='"+d.Username+"' AND Host='"+host+"';\n")
		if e != nil {
			return e
		}
		want := "N"
		if locked {
			want = "Y"
		}
		if value != want {
			return errors.New("覆盖期间账号锁定状态不一致")
		}
	}
	return nil
}
func restoreOverwriteAccess(ctx context.Context, j mysqlOverwriteJournal) (ret error) {
	a := databaseScopedIdentity(*j.Operation.PreviousDatabase)
	defer func() {
		if ret != nil {
			// A failure after unlocking one host must not leave that host accepting
			// traffic while the other host or actual permission check is unresolved.
			lockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = setMySQLAccountLock(lockCtx, j.Operation.Server, a, true)
			_ = killMySQLAccountConnections(lockCtx, j.Operation.Server, a)
		}
	}()
	c, e := readDatabaseLifecycleCredential(j.Operation.Server, *j.Operation.PreviousDatabase)
	if e != nil {
		return e
	}
	if e = setOverwriteAccess(ctx, j, c, false); e != nil {
		return e
	}
	if e = setMySQLAccountLock(ctx, j.Operation.Server, a, false); e != nil {
		return e
	}
	if e = importClient(ctx, j.Operation.Server, *j.Operation.PreviousDatabase, c, strings.NewReader("SELECT DATABASE();\n"), io.Discard); e != nil {
		return errors.New("原应用凭据恢复后认证失败，保持维护状态")
	}
	return verifyOverwriteAccess(ctx, j, false, false)
}
func overwriteResetSQL(j mysqlOverwriteJournal) (string, error) {
	if !validOverwriteJournal(j) {
		return "", errors.New("缺少有效覆盖恢复记录")
	}
	d := j.Operation.Database
	return "DROP DATABASE IF EXISTS `" + d.Name + "`; CREATE DATABASE `" + d.Name + "` CHARACTER SET " + j.Charset + " COLLATE " + j.Collation + ";\n", nil
}
func restoreOverwriteData(ctx context.Context, j mysqlOverwriteJournal) error {
	if !validOverwriteJournal(j) || j.Backup.ID == "" {
		return errors.New("缺少可核对的操作前副本")
	}
	// Hash and then consume the same root-private file descriptor before DROP.
	f, _, e := openVerifiedBackup(ctx, mysqlBackups, j.Backup)
	if e != nil {
		return e
	}
	defer f.Close()
	sql, e := overwriteResetSQL(j)
	if e != nil {
		return e
	}
	if _, e = mysqlQuery(ctx, j.Operation.Server, sql); e != nil {
		return e
	}
	if e = mysqlCommand(ctx, j.Operation.Server, "mysql", []string{"--binary-mode", "--local-infile=0", "--database=" + j.Operation.Database.Name}, f, io.Discard); e != nil {
		return e
	}
	actual, e := fingerprintMySQL(ctx, j.Operation.Server, j.Operation.Database)
	if e != nil {
		return e
	}
	if actual != j.Before {
		return errors.New("操作前副本已执行，但数据或对象指纹尚未匹配，保持维护状态")
	}
	raw, e := mysqlQuery(ctx, j.Operation.Server, "SELECT JSON_ARRAY(DEFAULT_CHARACTER_SET_NAME,DEFAULT_COLLATION_NAME) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+j.Operation.Database.Name+"';\n")
	if e != nil {
		return e
	}
	var options []string
	if json.Unmarshal([]byte(raw), &options) != nil || len(options) != 2 || options[0] != j.Charset || options[1] != j.Collation {
		return errors.New("恢复后的数据库字符集或排序规则不一致")
	}
	return nil
}
