//go:build linux

package executor

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const siteLogLedgerBytes int64 = 128 << 20
const siteLogLedgerRequests = 1000000
const siteLogLedgerResultLimit = 128 << 10

type siteLogPlanEntry struct {
	Name       string `json:"name"`
	Target     string `json:"target,omitempty"`
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	Owner      uint32 `json:"owner"`
	Bytes      int64  `json:"bytes"`
	ModifiedAt string `json:"modified_at"`
}

type siteLogPlan struct {
	Rotate, Delete []siteLogPlanEntry
}

func encodeSiteLogPlan(active, expired []plannedSiteLog) ([]byte, error) {
	plan := siteLogPlan{[]siteLogPlanEntry{}, []siteLogPlanEntry{}}
	for i, items := range [][]plannedSiteLog{active, expired} {
		for _, item := range items {
			stat, ok := item.info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil, errors.New("日志文件身份不能持久核实")
			}
			entry := siteLogPlanEntry{item.name, item.target, uint64(stat.Dev), stat.Ino, stat.Uid, item.info.Size(), item.info.ModTime().UTC().Format(time.RFC3339Nano)}
			if i == 0 {
				plan.Rotate = append(plan.Rotate, entry)
			} else {
				plan.Delete = append(plan.Delete, entry)
			}
		}
	}
	encoded, err := json.Marshal(plan)
	if err != nil || len(encoded) > 512<<10 {
		return nil, errors.New("日志操作核实计划超过容量；未开始变更")
	}
	return encoded, nil
}

func privateSiteLogLedgerFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("日志操作记录不是私有单链接普通文件；保留并拒绝变更")
	}
	return nil
}

// Only executor-owned metadata goes here: never file contents, IPs or URLs.
// A filesystem lock serializes all signal/rotation operations across PIDs.
func (s *Service) openSiteLogLedger(ctx context.Context) (*sql.DB, func(), error) {
	return s.openSiteLogLedgerMode(ctx, true)
}

func (s *Service) openSiteLogLedgerMode(ctx context.Context, initialize bool) (*sql.DB, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	dir := filepath.Join(s.Config.StateDir, "log-cleanup")
	if !filepath.IsAbs(s.Config.StateDir) || ownedRuntimePath(s.Config.StateDir, true) != nil {
		return nil, nil, errors.New("日志操作状态目录不可核实")
	}
	if initialize {
		if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, nil, err
		}
	}
	if ownedRuntimePath(dir, true) != nil {
		return nil, nil, errors.New("日志操作目录归属异常")
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		return nil, nil, errors.New("日志操作目录必须为私有 0700；不自动接管")
	}
	lockPath := filepath.Join(dir, "operation.lock")
	flags := os.O_RDONLY | syscall.O_NOFOLLOW
	if initialize {
		flags = os.O_CREATE | os.O_EXCL | os.O_RDWR | syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(lockPath, flags, 0600)
	if errors.Is(err, os.ErrExist) {
		f, err = os.OpenFile(lockPath, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, nil, err
	}
	closeLock := func() { f.Close() }
	if err = privateSiteLogLedgerFile(lockPath); err != nil {
		closeLock()
		return nil, nil, err
	}
	fdInfo, err := f.Stat()
	pathInfo, pathErr := os.Lstat(lockPath)
	if err != nil || pathErr != nil || !os.SameFile(fdInfo, pathInfo) {
		closeLock()
		return nil, nil, errors.New("日志操作锁身份变化；未开始操作")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err = ctx.Err(); err != nil {
			closeLock()
			return nil, nil, err
		}
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			closeLock()
			return nil, nil, errors.New("日志轮转正在执行；本次尚未开始变更")
		}
		select {
		case <-ctx.Done():
			closeLock()
			return nil, nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	path := filepath.Join(dir, "operations.sqlite")
	if initialize {
		created, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
		if err == nil {
			err = created.Sync()
			created.Close()
		} else if errors.Is(err, os.ErrExist) {
			err = nil
		}
		if err != nil {
			closeLock()
			return nil, nil, err
		}
	}
	if err = privateSiteLogLedgerFile(path); err != nil {
		closeLock()
		return nil, nil, err
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, e := os.Lstat(path + suffix); errors.Is(e, os.ErrNotExist) {
			continue
		} else if e != nil || privateSiteLogLedgerFile(path+suffix) != nil {
			closeLock()
			return nil, nil, errors.New("日志记录恢复文件身份异常；保留且拒绝接管")
		}
	}
	info, err = os.Stat(path)
	if err != nil || info.Size() > siteLogLedgerBytes {
		closeLock()
		return nil, nil, errors.New("日志操作记录达到 128 MiB 或不可核实；不删除历史记录或继续变更")
	}
	dsn := (&url.URL{Scheme: "file", Path: path}).String() + "?_pragma=busy_timeout(1000)&_pragma=synchronous(FULL)"
	if !initialize {
		dsn += "&mode=ro"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		closeLock()
		return nil, nil, err
	}
	db.SetMaxOpenConns(1)
	closeAll := func() { db.Close(); closeLock() }
	var journal string
	var pageSize int64
	if err = db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journal); err == nil {
		err = db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize)
	}
	if err != nil || journal != "delete" || pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		closeAll()
		return nil, nil, errors.New("日志记录恢复模式或页大小异常；不转换或清除原记录")
	}
	if initialize {
		var maxPages int64
		if err = db.QueryRowContext(ctx, fmt.Sprintf("PRAGMA max_page_count=%d", siteLogLedgerBytes/pageSize)).Scan(&maxPages); err != nil || maxPages*pageSize > siteLogLedgerBytes {
			closeAll()
			return nil, nil, errors.New("无法约束日志操作记录容量；未开始变更")
		}
		_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS operations(request_id TEXT PRIMARY KEY,site_id TEXT NOT NULL,retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 1 AND 100),state TEXT NOT NULL CHECK(state IN ('running','completed','unknown')),result TEXT NOT NULL DEFAULT '',plan TEXT NOT NULL,started_at TEXT NOT NULL);CREATE INDEX IF NOT EXISTS site_operation_pending ON operations(site_id,state);`)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS operation_continuations(request_id TEXT PRIMARY KEY REFERENCES operations(request_id),plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64),verified_at TEXT NOT NULL,evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256)=64),evidence TEXT NOT NULL CHECK(length(evidence) BETWEEN 1 AND 524288));`)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		for _, parent := range []string{dir, s.Config.StateDir} {
			directory, e := os.Open(parent)
			if e == nil {
				e = directory.Sync()
				directory.Close()
			}
			if e != nil {
				closeAll()
				return nil, nil, errors.New("日志操作目录无法持久化；未开始变更")
			}
		}
	} else {
		rows, e := db.QueryContext(ctx, `SELECT request_id,site_id,retention_days,state,plan,started_at FROM operations LIMIT 0`)
		if e != nil {
			closeAll()
			return nil, nil, errors.New("日志记录结构不可核实；未修复或改写")
		}
		rows.Close()
	}
	return db, closeAll, nil
}

func decodeCompletedSiteLogResult(raw string, id string) (core.LogCleanupResult, error) {
	var out core.LogCleanupResult
	if len(raw) > siteLogLedgerResultLimit || validateWAFRotationJSONShape([]byte(raw)) != nil {
		return out, errors.New("已完成日志操作结果不可核实；不重新执行")
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Rotated < 0 || out.Rotated > 2 || out.Deleted < 0 || out.Deleted > siteLogExpiredLimit || out.DeletedBytes < 0 || out.Files == nil || len(out.Files) != out.Deleted {
		return out, errors.New("已完成日志结果格式异常；不重新执行")
	}
	seen := map[string]bool{}
	for _, name := range out.Files {
		if seen[name] || !siteLogArchiveName(id, name) {
			return out, errors.New("日志操作结果包含无归属文件；不重新执行")
		}
		seen[name] = true
	}
	return out, nil
}

// The same run ID survives reply loss and process restarts. No unknown result
// is treated as successful or automatically repeated, even with a new ID.
func (s *Service) guardedSiteLogCleanup(ctx context.Context, in core.LogCleanupRequest, now time.Time, reopen func(context.Context) error) (core.LogCleanupResult, error) {
	empty := core.LogCleanupResult{Files: []string{}}
	if !core.ValidID(in.RequestID) || !core.ValidID(in.SiteID) || in.RetentionDays < 1 || in.RetentionDays > 100 || in.Attempt < 0 || in.Attempt > 2 {
		return empty, errors.New("日志操作标识、网站、保留期或尝试次数无效")
	}
	db, closeDB, err := s.openSiteLogLedger(ctx)
	if err != nil {
		return empty, err
	}
	defer closeDB()
	var site, state, result string
	var days int
	err = db.QueryRowContext(ctx, `SELECT site_id,retention_days,state,result FROM operations WHERE request_id=?`, in.RequestID).Scan(&site, &days, &state, &result)
	if err == nil {
		if site != in.SiteID || days != in.RetentionDays {
			return empty, errors.New("日志操作标识已绑定其它参数；拒绝重新执行")
		}
		if state == "completed" {
			return decodeCompletedSiteLogResult(result, site)
		}
		return empty, errors.New("原日志操作结果未知或未完成；保留日志并停止自动重复执行，需人工核对")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return empty, err
	}
	if in.Attempt != 0 {
		return empty, errors.New("重试缺少原始持久操作记录；可能来自旧版本或记录丢失，不重复变更日志")
	}
	var pending, total int
	if pending, err = siteLogPendingOperations(ctx, db, in.SiteID); err != nil {
		return empty, err
	}
	if pending != 0 {
		return empty, errors.New("该网站存在结果未知的日志操作；不能用新标识绕过，需要人工核对")
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM operations`).Scan(&total); err != nil {
		return empty, err
	}
	if total >= siteLogLedgerRequests {
		return empty, errors.New("日志操作记录达到 1000000 项；不自动删除证据或继续变更")
	}
	started := false
	actualReopen := reopen
	var plannedExpired []plannedSiteLog
	verifyWriters := func() error {
		if reopen != nil {
			return nil
		} // Explicit fixture callback; production always uses nil.
		return siteLogExpiredOpenWriters(ctx, s.systemPath("/proc"), plannedExpired)
	}
	begin := func(active, expired []plannedSiteLog) error {
		plannedExpired = expired
		if e := verifyWriters(); e != nil {
			return e
		}
		if len(active) > 0 && actualReopen == nil {
			var e error
			actualReopen, e = s.prepareSiteLogReopen(ctx, active)
			if e != nil {
				return e
			}
		}
		plan, e := encodeSiteLogPlan(active, expired)
		if e != nil {
			return e
		}
		_, e = db.ExecContext(ctx, `INSERT INTO operations(request_id,site_id,retention_days,state,plan,started_at) VALUES(?,?,?,'running',?,?)`, in.RequestID, in.SiteID, in.RetentionDays, string(plan), now.UTC().Format(time.RFC3339Nano))
		started = e == nil
		return e
	}
	out, err := cleanupSiteLogsAtGuarded(ctx, s.systemPath("/var/log/nginx"), in.SiteID, in.RetentionDays, now, func(ctx context.Context) error { return actualReopen(ctx) }, begin, verifyWriters)
	if !started {
		return out, err
	}
	// Persist the outcome even if the HTTP caller disconnected. This only
	// writes private evidence; it never starts another signal or log mutation.
	finish, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err != nil {
		_, _ = db.ExecContext(finish, `UPDATE operations SET state='unknown' WHERE request_id=? AND state='running'`, in.RequestID)
		return out, err
	}
	encoded, e := json.Marshal(out)
	if e != nil || len(encoded) > siteLogLedgerResultLimit {
		return out, errors.New("日志操作已执行但无法保存有界结果；保留未知记录，不自动重试")
	}
	if _, e = decodeCompletedSiteLogResult(string(encoded), in.SiteID); e != nil {
		return out, e
	}
	updated, e := db.ExecContext(finish, `UPDATE operations SET state='completed',result=? WHERE request_id=? AND state='running'`, string(encoded), in.RequestID)
	if e == nil {
		count, countErr := updated.RowsAffected()
		if countErr != nil || count != 1 {
			e = errors.New("日志操作记录身份变化")
		}
	}
	if e != nil {
		return out, errors.New("日志操作可能已完成，但最终记录写入失败；不自动重新执行")
	}
	return out, nil
}
