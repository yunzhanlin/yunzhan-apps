//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func RecoverDatabaseOverwrites() error {
	root, e := importRoot(mysqlOverwrites)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	root.Close()
	entries, e := os.ReadDir(mysqlOverwrites)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	failures := []error{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") || strings.HasSuffix(entry.Name(), ".credential.json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !core.ValidID(id) {
			failures = append(failures, errors.New("覆盖恢复目录存在未知日志"))
			continue
		}
		j, e := readOverwriteJournal(mysqlOverwrites, id)
		if e != nil {
			failures = append(failures, e)
			continue
		}
		if e = recoverIdleOverwrite(ctx, j); e != nil {
			failures = append(failures, errors.New("覆盖任务 "+id+" 尚未完成恢复："+e.Error()))
		}
		if ctx.Err() != nil {
			break
		}
	}
	return errors.Join(failures...)
}
func recoverIdleOverwrite(ctx context.Context, observed mysqlOverwriteJournal) error {
	root, e := importRoot(mysqlJobs)
	if e != nil {
		return e
	}
	defer root.Close()
	lock, e := root.OpenFile(observed.Operation.Server.ID+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
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
		if errors.Is(e, syscall.EWOULDBLOCK) {
			return nil
		}
		return e
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	j, e := readOverwriteJournal(mysqlOverwrites, observed.Operation.JobID)
	if e != nil {
		return e
	}
	if !sameOverwriteOperation(j.Operation, observed.Operation) {
		return errors.New("恢复日志身份已变化")
	}
	original, e := readMySQLJob(j.Operation.JobID)
	if e != nil {
		return e
	}
	if !sameOverwriteOperation(original.Operation, j.Operation) {
		return errors.New("原任务与恢复记录不一致")
	}
	// The durable data decision precedes the outer job-result write. A death in
	// between needs result reconciliation, even though SQL/access recovery is over.
	// Never touch database data or access on this path: later operations or new
	// application writes may already exist.
	if overwriteRecoveryAction(j.Phase) == "none" {
		return publishOverwriteDecision(j, original)
	}
	m, e := readMySQL(j.Operation.Server.ID)
	if e != nil {
		return e
	}
	if !m.Ready || m.Server.ReleaseID != j.Operation.Server.ReleaseID || m.Server.Port != j.Operation.Server.Port {
		return errors.New("原数据库实例不匹配")
	}
	// Do not start an instance that its owner stopped. The timer will retry when
	// the managed instance is available, without changing instance preferences.
	if _, e = mysqlQuery(ctx, m.Server, "SELECT 1;\n"); e != nil {
		return errors.New("目标实例当前不可用，恢复记录保留")
	}
	add := func(message string) {
		original.Result.Steps = append(original.Result.Steps, core.Step{Time: core.Now(), Message: message})
	}
	add("独立恢复服务取得实例锁，核对失去执行进程的覆盖任务")
	recoveryErr := recoverOverwrite(ctx, mysqlOverwrites, &j, add)
	original.Result.Backup = j.Backup
	if recoveryErr != nil {
		original.Result.State = "failed"
		original.Result.DatabaseStatus = "needs_attention"
		original.Result.Error = "覆盖恢复尚未完成，应用保持维护状态：" + recoveryErr.Error()
	} else {
		_, status, finalErr := overwriteFinal(j)
		original.Result.DatabaseStatus = status
		if finalErr == nil {
			original.Result.State = "succeeded"
			original.Result.Error = ""
		} else {
			original.Result.State = "failed"
			original.Result.Error = finalErr.Error()
		}
	}
	if e = writeJSON(filepath.Join(mysqlJobs, j.Operation.JobID+".json"), original); e != nil {
		return e
	}
	return recoveryErr
}

func publishOverwriteDecision(j mysqlOverwriteJournal, original mysqlJob) error {
	backup, status, finalErr := overwriteFinal(j)
	if status != "ready" {
		return errors.New("覆盖日志尚无最终数据决定")
	}
	state, message := "succeeded", ""
	if finalErr != nil {
		state, message = "failed", finalErr.Error()
	}
	if original.Result.State == state && original.Result.DatabaseStatus == status && original.Result.Backup == backup && original.Result.Error == message {
		return nil
	}
	original.Result.State = state
	original.Result.DatabaseStatus = status
	original.Result.Backup = backup
	original.Result.Error = message
	original.Result.Steps = append(original.Result.Steps, core.Step{Time: core.Now(), Message: "独立恢复服务补齐已完成的数据决定；未重新执行 SQL 或改变应用访问"})
	return writeJSON(filepath.Join(mysqlJobs, j.Operation.JobID+".json"), original)
}
