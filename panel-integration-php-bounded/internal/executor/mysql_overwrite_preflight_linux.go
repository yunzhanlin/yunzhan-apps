//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func inspectOverwriteTarget(ctx context.Context, op core.DatabaseOperation, authenticate bool) (mysqlOverwriteJournal, error) {
	j := mysqlOverwriteJournal{Operation: op, Phase: "prepared", Grants: map[string][]string{}, UpdatedAt: core.Now()}
	if !validDatabaseOverwriteOperation(op) {
		return j, errors.New("覆盖导入目标身份、上传绑定或修订无效")
	}
	old, e := readLifecycleDatabase(op.Server, op.Database.ID)
	if e != nil {
		return j, e
	}
	if !sameLifecycleDatabase(old, *op.PreviousDatabase) {
		return j, errors.New("原数据库状态已变化，拒绝覆盖")
	}
	if e = requireDatabaseLifecycleClear(ctx, op.Server, old); e != nil {
		return j, e
	}
	// Existing events can write even when no interactive application is connected.
	// Cross-schema views and foreign keys are explicit dependencies of replacement.
	checks := []struct{ sql, message string }{
		{"SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA='" + old.Name + "';", "目标库仍有定时事件，请先导出并移除事件后再覆盖"},
		{"SELECT COUNT(*) FROM information_schema.VIEW_TABLE_USAGE WHERE TABLE_SCHEMA='" + old.Name + "' AND VIEW_SCHEMA<>'" + old.Name + "';", "其他数据库的视图引用此库，请先处理依赖"},
		{"SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE REFERENCED_TABLE_SCHEMA IS NOT NULL AND TABLE_SCHEMA<>REFERENCED_TABLE_SCHEMA AND (TABLE_SCHEMA='" + old.Name + "' OR REFERENCED_TABLE_SCHEMA='" + old.Name + "');", "目标库存在跨库外键，请先处理依赖"},
	}
	for _, check := range checks {
		n, e := mysqlQuery(ctx, op.Server, check.sql+"\n")
		if e != nil {
			return j, e
		}
		if n != "0" {
			return j, errors.New(check.message)
		}
	}
	raw, e := mysqlQuery(ctx, op.Server, "SELECT JSON_ARRAY(DEFAULT_CHARACTER_SET_NAME,DEFAULT_COLLATION_NAME) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+old.Name+"';\n")
	if e != nil {
		return j, e
	}
	var options []string
	if json.Unmarshal([]byte(raw), &options) != nil || len(options) != 2 {
		return j, errors.New("无法核对目标库字符集和排序规则")
	}
	j.Charset = options[0]
	j.Collation = options[1]
	for _, host := range []string{"localhost", "127.0.0.1"} {
		grantee := "CONCAT(QUOTE('" + old.Username + "'),'@',QUOTE('" + host + "'))"
		raw, e := mysqlQuery(ctx, op.Server, "SELECT PRIVILEGE_TYPE FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA='"+old.Name+"' AND GRANTEE="+grantee+" ORDER BY PRIVILEGE_TYPE;\n")
		if e != nil {
			return j, e
		}
		j.Grants[host] = strings.Split(raw, "\n")
		dual, e := mysqlQuery(ctx, op.Server, "SELECT COUNT(*) FROM mysql.user WHERE User='"+old.Username+"' AND Host='"+host+"' AND JSON_EXTRACT(User_attributes,'$.additional_password') IS NOT NULL;\n")
		if e != nil {
			return j, e
		}
		if dual != "0" {
			return j, errors.New("原应用账号存在额外密码，请先核对并移除双密码配置")
		}
		locked, e := mysqlQuery(ctx, op.Server, "SELECT account_locked FROM mysql.user WHERE User='"+old.Username+"' AND Host='"+host+"';\n")
		if e != nil {
			return j, e
		}
		if locked != "N" {
			return j, errors.New("每库应用账号当前已锁定，请先核对原状态")
		}
	}
	if !validOverwriteJournal(j) {
		return j, errors.New("目标库权限或字符集不在可恢复范围内")
	}
	credential, e := readDatabaseLifecycleCredential(op.Server, old)
	if e != nil {
		return j, e
	}
	// The HTTP service keeps its restricted capabilities. Credential switching
	// belongs to the independent database job, before any maintenance mutation.
	if authenticate {
		if e = importClient(ctx, op.Server, old, credential, strings.NewReader("SELECT DATABASE();\n"), io.Discard); e != nil {
			return j, errors.New("原应用凭据未通过实际认证，覆盖尚未开始：" + e.Error())
		}
	}
	return j, nil
}
func claimOverwriteSQL(ctx context.Context, base string, op core.DatabaseOperation) (*os.File, error) {
	if !validDatabaseOverwriteOperation(op) {
		return nil, errors.New("覆盖导入任务无效")
	}
	root, e := importRoot(base)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	lock, e := root.OpenFile("upload.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	info, e := lock.Stat()
	if e != nil {
		return nil, e
	}
	if e = privateBackupEntry(info, false); e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return nil, errors.New("上传或清理正在进行")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if _, e = root.Lstat(op.Import.ID + ".release.json"); !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("上传已进入清理，不能用于覆盖")
	}
	sql, e := openSQLImport(ctx, base, *op.Import)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			sql.Close()
		}
	}()
	expected := struct {
		JobID      string
		DatabaseID string
	}{op.JobID, op.Database.ID}
	name := op.Import.ID + ".claim.json"
	f, e := openImportFile(root, name)
	if e == nil {
		var old struct {
			JobID      string
			DatabaseID string
		}
		err := json.NewDecoder(io.LimitReader(f, 4096)).Decode(&old)
		f.Close()
		if err != nil || old != expected {
			return nil, errors.New("覆盖上传已被其他任务或数据库认领")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	} else if e = writeJSON(filepath.Join(base, name), expected); e != nil {
		return nil, e
	}
	success = true
	return sql, nil
}
