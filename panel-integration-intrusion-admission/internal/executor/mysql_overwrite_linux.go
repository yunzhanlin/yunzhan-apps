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
	"time"
)

func overwriteFinal(j mysqlOverwriteJournal) (core.DatabaseBackup, string, error) {
	switch j.Phase {
	case "completed":
		return j.Backup, "ready", nil
	case "rolled_back":
		return j.Backup, "ready", errors.New("覆盖导入未交付，已保留或恢复操作前数据及原应用密码；再次导入请新建上传")
	}
	return j.Backup, "needs_attention", errors.New("覆盖导入仍在维护状态，需要继续核对原恢复任务")
}
func recoverOverwrite(ctx context.Context, base string, j *mysqlOverwriteJournal, add func(string)) error {
	op := j.Operation
	if e := discoverOverwriteBackup(ctx, j); e != nil {
		if overwriteRecoveryAction(j.Phase) != "abort" {
			return e
		}
		add("操作前副本暂不可核对；数据替换尚未开始，将保留原数据库并恢复访问")
	}
	actual, e := readLifecycleDatabase(op.Server, op.Database.ID)
	if e != nil {
		return e
	}
	if !sameLifecycleDatabase(actual, *op.PreviousDatabase) && !sameLifecycleDatabase(actual, op.Database) {
		return errors.New("数据库身份或修订已被另一操作改变，拒绝自动恢复")
	}
	switch overwriteRecoveryAction(j.Phase) {
	case "none":
		return nil
	case "commit":
		return commitOverwrite(ctx, base, j, add)
	case "restore_access":
		if e = restoreOverwriteAccess(ctx, *j); e != nil {
			return e
		}
		return transitionOverwrite(base, j, "rolled_back")
	case "abort":
		if !sameLifecycleDatabase(actual, *op.PreviousDatabase) {
			return errors.New("原数据库清单已变化，不能按未开始覆盖处理")
		}
		if j.Phase != "aborting" {
			if e = transitionOverwrite(base, j, "aborting"); e != nil {
				return e
			}
		}
		if e = transitionOverwrite(base, j, "restored"); e != nil {
			return e
		}
		if e = recoverOverwrite(ctx, base, j, add); e != nil {
			return e
		}
		add("覆盖尚未进入数据替换，原数据库及应用访问已保留")
		return nil
	case "rollback":
		if !sameLifecycleDatabase(actual, *op.PreviousDatabase) {
			return errors.New("新数据库清单已经发布，拒绝用旧副本覆盖")
		}
		if j.Phase != "rolling_back" {
			if e = transitionOverwrite(base, j, "rolling_back"); e != nil {
				return e
			}
		}
		c, e := readDatabaseLifecycleCredential(op.Server, *op.PreviousDatabase)
		if e != nil {
			return e
		}
		if e = setOverwriteAccess(ctx, *j, c, true); e != nil {
			return e
		}
		add("正在用已经校验的操作前副本恢复数据库，应用连接保持隔离")
		if e = restoreOverwriteData(ctx, *j); e != nil {
			return e
		}
		// The original manifest has never been replaced on this path. Keeping its
		// exact bytes also permits rollback when publication failed on an immutable
		// original manifest; restoring data does not require rewriting that file.
		if e = syncImportDirectory(mysqlConfig(op.Server.ID) + "/databases"); e != nil {
			return e
		}
		// Record restoration before reopening application access. A process death
		// after unlock must never restore the backup over newly accepted writes.
		if e = transitionOverwrite(base, j, "restored"); e != nil {
			return e
		}
		if e = recoverOverwrite(ctx, base, j, add); e != nil {
			return e
		}
		add("操作前数据、对象、字符集和原应用密码已恢复并验证")
		return nil
	}
	return errors.New("未知覆盖恢复阶段")
}
func commitOverwrite(ctx context.Context, base string, j *mysqlOverwriteJournal, add func(string)) error {
	if j.Phase != "imported" {
		return errors.New("覆盖 SQL 尚未验证完成")
	}
	op := j.Operation
	actual, e := readLifecycleDatabase(op.Server, op.Database.ID)
	if e != nil {
		return e
	}
	if sameLifecycleDatabase(actual, *op.PreviousDatabase) {
		fingerprint, e := fingerprintMySQL(ctx, op.Server, op.Database)
		if e != nil {
			return e
		}
		if fingerprint != j.Imported {
			return errors.New("交付前目标数据已变化，保持维护状态")
		}
		path := mysqlConfig(op.Server.ID) + "/databases/" + op.Database.ID + ".json"
		if e = writeJSON(path, op.Database); e != nil {
			// A visible rename is a commit decision. Never restore old data after a
			// published new manifest; retry syncing and restoring application access.
			visible, readErr := readLifecycleDatabase(op.Server, op.Database.ID)
			if readErr != nil {
				return errors.New("目标清单发布结果无法核对，保持维护状态")
			}
			if sameLifecycleDatabase(visible, *op.PreviousDatabase) {
				if e = transitionOverwrite(base, j, "rolling_back"); e != nil {
					return e
				}
				return recoverOverwrite(ctx, base, j, add)
			}
			if !sameLifecycleDatabase(visible, op.Database) {
				return errors.New("目标清单归属已变化，保持维护状态")
			}
		}
	} else if !sameLifecycleDatabase(actual, op.Database) {
		return errors.New("目标数据库修订已变化，拒绝覆盖交付")
	}
	if e = syncImportDirectory(mysqlConfig(op.Server.ID) + "/databases"); e != nil {
		return e
	}
	if e = restoreOverwriteAccess(ctx, *j); e != nil {
		return e
	}
	if e = transitionOverwrite(base, j, "completed"); e != nil {
		return e
	}
	add("覆盖 SQL 已交付，目标身份保留、原应用密码可用，操作前副本已保留")
	return nil
}

// Caller owns the instance execution lock. Existing journals are recovery-only:
// an interrupted upload is never blindly executed a second time.
func runDatabaseOverwrite(ctx context.Context, op core.DatabaseOperation, add func(string)) (backup core.DatabaseBackup, status string, ret error) {
	status = "needs_attention"
	if !validDatabaseOverwriteOperation(op) {
		return backup, status, errors.New("覆盖任务参数无效")
	}
	if e := os.MkdirAll(mysqlOverwrites, 0700); e != nil {
		return backup, status, e
	}
	j, e := readOverwriteJournal(mysqlOverwrites, op.JobID)
	if e == nil {
		if !sameOverwriteOperation(j.Operation, op) {
			return backup, status, errors.New("原覆盖任务身份已变化")
		}
		if j.Phase == "completed" || j.Phase == "rolled_back" {
			return overwriteFinal(j)
		}
		if e = recoverOverwrite(ctx, mysqlOverwrites, &j, add); e != nil {
			return j.Backup, status, e
		}
		return overwriteFinal(j)
	}
	if !errors.Is(e, os.ErrNotExist) {
		return backup, status, e
	}
	j, e = inspectOverwriteTarget(ctx, op, true)
	if e != nil {
		return backup, "ready", e
	}
	input, e := claimOverwriteSQL(ctx, mysqlImports, op)
	if e != nil {
		return backup, "ready", e
	}
	defer input.Close()
	if e = saveOverwriteJournal(mysqlOverwrites, j); e != nil {
		return backup, status, e
	}
	// On ordinary failure recover using the state actually published to disk.
	// SIGKILL / boot recovery is handled by the independent instance-locked guard.
	defer func() {
		if ret == nil {
			return
		}
		add("覆盖执行未完成：" + ret.Error())
		saved, err := readOverwriteJournal(mysqlOverwrites, op.JobID)
		if err != nil || !sameOverwriteOperation(saved.Operation, op) {
			status = "needs_attention"
			return
		}
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		if err = recoverOverwrite(recoveryCtx, mysqlOverwrites, &saved, add); err != nil {
			backup = saved.Backup
			status = "needs_attention"
			ret = errors.New("覆盖未交付，自动恢复尚未完成；原 SQL 和操作前副本已保留：" + err.Error())
			return
		}
		backup, status, err = overwriteFinal(saved)
		if err != nil {
			ret = err
		} else {
			ret = nil
		}
	}()
	candidate, e := overwriteCredential(mysqlOverwrites, op)
	if e != nil {
		return backup, status, e
	}
	if e = setOverwriteAccess(ctx, j, candidate, true); e != nil {
		return backup, status, e
	}
	if e = verifyOverwriteAccess(ctx, j, true, true); e != nil {
		return backup, status, e
	}
	if e = transitionOverwrite(mysqlOverwrites, &j, "secured"); e != nil {
		return backup, status, e
	}
	add("目标应用连接已隔离，开始生成操作前一致性备份；快照期间短暂锁定同实例写入")
	if e = func() error {
		unlock, e := mysqlReadLock(ctx, op.Server)
		if e != nil {
			return e
		}
		defer unlock()
		j.Before, e = fingerprintMySQL(ctx, op.Server, op.Database)
		if e != nil {
			return e
		}
		// Preserve fingerprint before backup publication, so recovery can discover
		// a completed backup if interruption falls before the next phase update.
		if e = saveOverwriteJournal(mysqlOverwrites, j); e != nil {
			return e
		}
		j.Backup, e = backupMySQL(ctx, op.Server, op.Database, core.DatabaseBackup{ID: op.JobID, DatabaseID: op.Database.ID, ServerID: op.Server.ID, CreatedAt: core.Now()})
		if e != nil {
			return e
		}
		f, _, e := openVerifiedBackup(ctx, mysqlBackups, j.Backup)
		if e != nil {
			return e
		}
		f.Close()
		return transitionOverwrite(mysqlOverwrites, &j, "backup_ready")
	}(); e != nil {
		return j.Backup, status, e
	}
	backup = j.Backup
	add("操作前副本及数据指纹已持久保存，开始替换目标数据库")
	if e = transitionOverwrite(mysqlOverwrites, &j, "importing"); e != nil {
		return backup, status, e
	}
	sql, e := overwriteResetSQL(j)
	if e != nil {
		return backup, status, e
	}
	if _, e = mysqlQuery(ctx, op.Server, sql); e != nil {
		return backup, status, e
	}
	if e = setMySQLAccountLock(ctx, op.Server, databaseScopedIdentity(*op.PreviousDatabase), false); e != nil {
		return backup, status, e
	}
	if e = importClient(ctx, op.Server, op.Database, candidate, input, io.Discard); e != nil {
		return backup, status, e
	}
	if e = importClient(ctx, op.Server, op.Database, candidate, strings.NewReader("SELECT DATABASE();\n"), io.Discard); e != nil {
		return backup, status, e
	}
	if e = setMySQLAccountLock(ctx, op.Server, databaseScopedIdentity(*op.PreviousDatabase), true); e != nil {
		return backup, status, e
	}
	if e = killMySQLAccountConnections(ctx, op.Server, databaseScopedIdentity(*op.PreviousDatabase)); e != nil {
		return backup, status, e
	}
	if e = verifyOverwriteAccess(ctx, j, true, true); e != nil {
		return backup, status, e
	}
	if j.Imported, e = fingerprintMySQL(ctx, op.Server, op.Database); e != nil {
		return backup, status, e
	}
	if e = transitionOverwrite(mysqlOverwrites, &j, "imported"); e != nil {
		return backup, status, e
	}
	add("覆盖 SQL 执行与实际认证通过，正在交付数据库并恢复应用连接")
	if e = commitOverwrite(ctx, mysqlOverwrites, &j, add); e != nil {
		return backup, status, e
	}
	return overwriteFinal(j)
}

// Discover only this task's private backup. Used if backup publication completed
// just before its journal phase transition was interrupted.
func discoverOverwriteBackup(ctx context.Context, j *mysqlOverwriteJournal) error {
	if j.Backup.ID != "" || len(j.Before.Sum) != 64 {
		return nil
	}
	root, e := importRoot(filepath.Join(mysqlBackups, j.Operation.Server.ID))
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	defer root.Close()
	f, e := openImportFile(root, j.Operation.JobID+".json")
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	defer f.Close()
	var b core.DatabaseBackup
	if e = json.NewDecoder(io.LimitReader(f, 16384)).Decode(&b); e != nil {
		return e
	}
	copy := *j
	copy.Backup = b
	if !validOverwriteJournal(copy) {
		return errors.New("发现的操作前备份归属无效")
	}
	sql, _, e := openVerifiedBackup(ctx, mysqlBackups, b)
	if e != nil {
		return e
	}
	sql.Close()
	j.Backup = b
	return nil
}
