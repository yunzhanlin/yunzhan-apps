//go:build linux

package executor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
)

const statisticsHistoryDays = 30
const statisticsHistoryRows = 250000
const statisticsHistoryStreams = 4096
const statisticsHistoryBatchBytes int64 = 4 << 20
const statisticsHistoryBatchRows = 10000

// This is deliberately separate from panel.db: root-private, no cookies,
// credentials, request query strings or raw user agents. FULL synchronous
// commits put accepted rows and their source cursor in the SAME transaction.
func (s *Service) openStatisticsHistory(ctx context.Context) (*sql.DB, error) {
	dir := s.moduleDir("website-statistics-v2")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	for _, p := range []string{s.Config.SecurityDir, filepath.Join(s.Config.SecurityDir, "modules"), dir} {
		st, err := os.Lstat(p)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return nil, errors.New("统计历史目录身份或权限异常，未接管")
		}
	}
	path := filepath.Join(dir, "access.sqlite")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDONLY|syscall.O_NOFOLLOW, 0600)
	if err == nil {
		err = f.Close()
	} else if errors.Is(err, os.ErrExist) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	for _, p := range []string{path, path + "-journal", path + "-wal", path + "-shm"} {
		st, e := os.Lstat(p)
		if errors.Is(e, os.ErrNotExist) && p != path {
			continue
		}
		if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || st.Sys().(*syscall.Stat_t).Nlink != 1 {
			return nil, errors.New("统计历史数据库路径、链接数或权限异常，未覆盖")
		}
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=rw"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	var version, pageSize int
	if err = db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil || pageSize != 4096 {
		db.Close()
		return nil, errors.New("统计历史页大小不支持，未放宽 512 MiB 预算")
	}
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 0 && version != 1 {
		db.Close()
		return nil, errors.New("统计历史损坏或版本不支持，保留原文件")
	}
	_, err = db.ExecContext(ctx, "PRAGMA busy_timeout=1500; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA max_page_count=131072; "+
		"CREATE TABLE IF NOT EXISTS access_rows(seq INTEGER PRIMARY KEY,site TEXT NOT NULL,stamp INTEGER NOT NULL,ip TEXT NOT NULL,path TEXT NOT NULL,status INTEGER NOT NULL,seconds REAL NOT NULL,bot INTEGER NOT NULL,payload TEXT NOT NULL); "+
		"CREATE INDEX IF NOT EXISTS access_site_time ON access_rows(site,stamp,seq); CREATE INDEX IF NOT EXISTS access_time ON access_rows(stamp); "+
		"CREATE TABLE IF NOT EXISTS access_streams(site TEXT NOT NULL,identity TEXT NOT NULL,name TEXT NOT NULL,offset INTEGER NOT NULL,anchor TEXT NOT NULL,size INTEGER NOT NULL,seen INTEGER NOT NULL,blocked INTEGER NOT NULL DEFAULT 0,invalid INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(site,identity)); "+
		"CREATE TABLE IF NOT EXISTS access_retention(site TEXT PRIMARY KEY,evicted INTEGER NOT NULL DEFAULT 0); PRAGMA user_version=1;")
	if err != nil {
		db.Close()
		return nil, errors.New("统计历史无法安全打开，保留原数据")
	}
	return db, nil
}

func statisticsLogAnchor(f *os.File, offset int64) (string, error) {
	if offset < 0 {
		return "", errors.New("统计读取进度无效")
	}
	n := min(offset, int64(256))
	b := make([]byte, n)
	if n > 0 {
		if _, err := f.ReadAt(b, offset-n); err != nil {
			return "", err
		}
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// Classification, not the original UA, is retained. Bot names deliberately
// collapse to a fixed label so attacker-controlled strings cannot persist
// arbitrary secrets in this second database.
func statisticsPrivateRow(raw []byte, now time.Time) (analyticsAccess, int64, bool) {
	var row analyticsAccess
	if json.Unmarshal(raw, &row) != nil || row.Status < 100 || row.Status > 599 || row.Bytes < 0 || row.Bytes > 1<<40 || math.IsNaN(row.Seconds) || math.IsInf(row.Seconds, 0) || row.Seconds < 0 || row.Seconds > 86400 || len(row.Path) > 8192 || len(row.Agent) > 16384 || len(row.Referer) > 16384 || len(row.Method) < 1 || len(row.Method) > 32 || row.Remote != "" && net.ParseIP(row.Remote) == nil {
		return row, 0, false
	}
	ts, err := time.Parse(time.RFC3339, row.Time)
	if err != nil || ts.After(now.Add(time.Minute)) {
		return row, 0, false
	}
	for _, c := range row.Method {
		if !(c >= 'A' && c <= 'Z' || c == '-') {
			return row, 0, false
		}
	}
	row.Time = ts.UTC().Format(time.RFC3339Nano)
	row.Path, _, _ = strings.Cut(row.Path, "?")
	row.Path, _, _ = strings.Cut(row.Path, "#")
	row.Referer = analyticsReferer(row.Referer)
	browser, device, bot := analyticsClient(row.Agent)
	agents := map[string]string{"Edge": "Edg/", "Chrome": "Chrome/", "Firefox": "Firefox/", "Safari": "Safari/", "curl": "curl/", "Other": "Other"}
	row.Agent = agents[browser]
	if bot {
		row.Agent = "Crawlerbot"
	} else if device == "Mobile" {
		row.Agent += " Mobile"
	} else if device == "Tablet" {
		row.Agent += " Tablet"
	}
	return row, ts.Unix(), true
}

type statisticsIngestion struct {
	Backlog    int64
	Invalid    int64
	Blocked    int
	Compressed int
	Missing    int
	Sources    int
	Updated    string
}

// Caller holds s.mu (the same lifecycle/rotation lock). Renamed files preserve
// dev/inode identity and progress. A changed checkpoint or shortened inode is
// NOT silently reset: doing so could duplicate a copied/truncated archive.
func (s *Service) ingestStatisticsHistory(ctx context.Context, db *sql.DB, id string, now time.Time) (statisticsIngestion, error) {
	result := statisticsIngestion{Updated: now.UTC().Format(time.RFC3339)}
	if !core.ValidID(id) {
		return result, errors.New("统计网站标识无效")
	}
	site, err := s.openFiles(id)
	if err != nil {
		return result, err
	}
	site.Close()
	base := s.systemPath("/var/log/nginx")
	if err = ownedRuntimePath(base, true); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			result.Missing = 1
			return result, nil
		}
		return result, errors.New("访问日志目录身份异常，未采集")
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return result, err
	}
	defer root.Close()
	d, err := root.Open(".")
	if err != nil {
		return result, err
	}
	entries, err := d.ReadDir(siteLogDirectoryLimit + 1)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return result, err
	}
	if len(entries) > siteLogDirectoryLimit {
		return result, errors.New("访问日志目录超限，原进度保留")
	}
	current := "panel-" + id + ".access.log"
	names := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if name != current && !(strings.HasPrefix(name, current+".") && core.ValidSiteLogArchiveName(id, name)) {
			continue
		}
		if strings.HasSuffix(name, ".gz") {
			result.Compressed++
			continue
		}
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i] == current {
			return false
		}
		if names[j] == current {
			return true
		}
		return names[i] < names[j]
	})
	if len(names) > 512 {
		return result, errors.New("单网站访问日志超过 512 份，未覆盖读取进度")
	}
	result.Sources = len(names)
	if len(names) == 0 {
		result.Missing = 1
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	// Retention is explicit and applies only to this application's derived
	// history, NEVER the original Nginx logs or another application's database.
	if _, err = tx.ExecContext(ctx, "DELETE FROM access_rows WHERE stamp<?", now.AddDate(0, 0, -statisticsHistoryDays).Unix()); err != nil {
		return result, err
	}
	var streamCount int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM access_streams").Scan(&streamCount); err != nil {
		return result, err
	}
	seen := map[string]bool{}
	budget := statisticsHistoryBatchBytes
	rowBudget := statisticsHistoryBatchRows
	for _, name := range names {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		f, e := regularFile(root, name)
		if e != nil {
			return result, errors.New("访问日志不是普通无链接文件，原进度保留")
		}
		info, e := f.Stat()
		if e != nil || privateLogEntry(info) != nil {
			f.Close()
			return result, errors.New("访问日志归属、权限或链接数异常，未读取")
		}
		stat := info.Sys().(*syscall.Stat_t)
		identity := fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
		seen[identity] = true
		offset, oldSize, invalid := int64(0), int64(0), int64(0)
		anchor := ""
		blocked := 0
		e = tx.QueryRowContext(ctx, "SELECT offset,anchor,size,blocked,invalid FROM access_streams WHERE site=? AND identity=?", id, identity).Scan(&offset, &anchor, &oldSize, &blocked, &invalid)
		if errors.Is(e, sql.ErrNoRows) {
			if streamCount >= statisticsHistoryStreams {
				f.Close()
				return result, errors.New("统计文件身份记录已满，保留数据并停止新增采集")
			}
			streamCount++
			anchor, e = statisticsLogAnchor(f, 0)
		}
		if e != nil {
			f.Close()
			return result, e
		}
		if offset < 0 || oldSize < 0 || invalid < 0 || len(anchor) != 64 || blocked < 0 || blocked > 1 {
			f.Close()
			return result, errors.New("统计文件进度记录损坏，未重置")
		}
		actual, e := statisticsLogAnchor(f, offset)
		if e != nil || offset > info.Size() || actual != anchor {
			blocked = 1
		}
		if blocked != 0 {
			result.Blocked++
		} else if budget > 0 && rowBudget > 0 {
			previousOffset, previousAnchor := offset, anchor
			batchDigest := sha256.New()
			if _, e = f.Seek(offset, io.SeekStart); e != nil {
				f.Close()
				return result, e
			}
			reader := bufio.NewReaderSize(io.LimitReader(f, min(info.Size()-offset, budget)), 65536)
			for budget > 0 && rowBudget > 0 {
				line, re := reader.ReadSlice('\n')
				if errors.Is(re, bufio.ErrBufferFull) {
					blocked = 1
					result.Blocked++
					break
				}
				if re != nil && !errors.Is(re, io.EOF) {
					f.Close()
					return result, re
				}
				// A partial last line is left unread until the writer completes it.
				if len(line) == 0 || line[len(line)-1] != '\n' {
					break
				}
				if _, e = batchDigest.Write(line); e != nil {
					f.Close()
					return result, e
				}
				row, stamp, valid := statisticsPrivateRow(line, now)
				if valid && stamp >= now.AddDate(0, 0, -statisticsHistoryDays).Unix() {
					payload, _ := json.Marshal(row)
					_, e = tx.ExecContext(ctx, "INSERT INTO access_rows(site,stamp,ip,path,status,seconds,bot,payload) VALUES(?,?,?,?,?,?,?,?)", id, stamp, row.Remote, row.Path, row.Status, row.Seconds, strings.Contains(row.Agent, "bot"), string(payload))
					if e != nil {
						f.Close()
						return result, errors.New("统计历史容量不足或写入失败，未提交新进度")
					}
				} else if !valid {
					invalid++
				}
				offset += int64(len(line))
				budget -= int64(len(line))
				rowBudget--
				if errors.Is(re, io.EOF) {
					break
				}
			}
			anchor, e = statisticsLogAnchor(f, offset)
			if e != nil {
				f.Close()
				return result, e
			}
			// Verify the start and end of this batch. Concurrent in-place rewrites
			// invalidate the entire transaction, never advance a false checkpoint.
			check, e := f.Stat()
			beforeDigest, e2 := statisticsLogAnchor(f, previousOffset)
			verified := sha256.New()
			_, e3 := io.Copy(verified, io.NewSectionReader(f, previousOffset, offset-previousOffset))
			currentInfo, e4 := root.Lstat(name)
			if e != nil || e2 != nil || e3 != nil || e4 != nil || privateLogEntry(currentInfo) != nil || !os.SameFile(info, currentInfo) || check.Size() < offset || beforeDigest != previousAnchor || !strings.EqualFold(hex.EncodeToString(verified.Sum(nil)), hex.EncodeToString(batchDigest.Sum(nil))) {
				f.Close()
				return result, errors.New("采集期间访问日志身份或内容改变，原进度保留")
			}
		}
		f.Close()
		result.Backlog += max(int64(0), info.Size()-offset)
		result.Invalid += invalid
		_, err = tx.ExecContext(ctx, "INSERT INTO access_streams(site,identity,name,offset,anchor,size,seen,blocked,invalid) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(site,identity) DO UPDATE SET name=excluded.name,offset=excluded.offset,anchor=excluded.anchor,size=excluded.size,seen=excluded.seen,blocked=excluded.blocked,invalid=excluded.invalid", id, identity, name, offset, anchor, info.Size(), now.Unix(), blocked, invalid)
		if err != nil {
			return result, err
		}
	}
	// Previously unread files removed by an external rotation cannot be
	// reconstructed. Keep their cursor and report the gap rather than zero.
	rows, err := tx.QueryContext(ctx, "SELECT identity,offset,size,blocked,invalid FROM access_streams WHERE site=?", id)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var identity string
		var offset, size, invalid int64
		var blocked int
		if err = rows.Scan(&identity, &offset, &size, &blocked, &invalid); err != nil {
			rows.Close()
			return result, err
		}
		if !seen[identity] {
			result.Invalid += invalid
			if size > offset || blocked != 0 {
				result.Blocked++
				result.Backlog += max(int64(0), size-offset)
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM access_rows").Scan(&count); err != nil {
		return result, err
	}
	if count > statisticsHistoryRows {
		// Account for per-site capacity evictions before deleting the oldest rows.
		_, err = tx.ExecContext(ctx, "INSERT INTO access_retention(site,evicted) SELECT site,count(*) FROM (SELECT site FROM access_rows ORDER BY seq LIMIT ?) GROUP BY site ON CONFLICT(site) DO UPDATE SET evicted=evicted+excluded.evicted", count-statisticsHistoryRows)
		if err == nil {
			_, err = tx.ExecContext(ctx, "DELETE FROM access_rows WHERE seq IN (SELECT seq FROM access_rows ORDER BY seq LIMIT ?)", count-statisticsHistoryRows)
		}
		if err != nil {
			return result, err
		}
	}
	return result, tx.Commit()
}

func (s *Service) moduleStatisticsHistory(ctx context.Context, in core.AppModuleInput) (any, error) {
	if _, _, err := analyticsWindow(in); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	db, err := s.openStatisticsHistory(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	state, err := s.ingestStatisticsHistory(ctx, db, in.SiteID, time.Now())
	if err != nil {
		return nil, err
	}
	out, err := statisticsHistoryReport(ctx, db, in, state, time.Now())
	if err != nil {
		return nil, err
	}
	var worker struct {
		CheckedAt string `json:"checked_at"`
		Error     string `json:"error"`
	}
	workerErr := moduleRead(filepath.Join(s.moduleDir("website-statistics-v2"), "history-worker.json"), &worker)
	out["history_worker_checked_at"] = worker.CheckedAt
	out["history_worker_error"] = ""
	stamp, parseErr := time.Parse(time.RFC3339, worker.CheckedAt)
	out["history_worker_fresh"] = workerErr == nil && parseErr == nil && !stamp.After(time.Now().Add(time.Minute)) && time.Since(stamp) <= 45*time.Second && worker.Error == ""
	if workerErr != nil && !errors.Is(workerErr, os.ErrNotExist) || workerErr == nil && (len(worker.Error) > 256 || parseErr != nil) {
		out["history_worker_error"] = "后台采集状态无法核对；手动读取结果不代表后台正常"
	} else if worker.Error != "" {
		out["history_worker_error"] = worker.Error
	}
	return out, nil
}

func statisticsHistoryReport(ctx context.Context, db *sql.DB, in core.AppModuleInput, state statisticsIngestion, now time.Time) (map[string]any, error) {
	from, to, err := analyticsWindow(in)
	if err != nil {
		return nil, err
	}
	if !core.ValidID(in.SiteID) {
		return nil, errors.New("统计网站标识无效")
	}
	cutoff := now.AddDate(0, 0, -statisticsHistoryDays)
	historyLimited := !from.IsZero() && from.Before(cutoff)
	evicted := int64(0)
	err = db.QueryRowContext(ctx, "SELECT evicted FROM access_retention WHERE site=?", in.SiteID).Scan(&evicted)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var first, last sql.NullInt64
	if err = db.QueryRowContext(ctx, "SELECT min(stamp),max(stamp) FROM access_rows WHERE site=?", in.SiteID).Scan(&first, &last); err != nil {
		return nil, err
	}
	// All filter values remain SQL parameters. Exclusive to-time and complete
	// timestamps are also checked by the shared accumulator (Unix indices are
	// only a coarse prefilter and do not lose fractional seconds).
	query := "SELECT payload,stamp,ip,path,status,seconds,bot FROM access_rows WHERE site=? AND stamp>=?"
	args := []any{in.SiteID, cutoff.Unix()}
	if !from.IsZero() {
		query += " AND stamp>=?"
		args = append(args, from.Unix())
	}
	if !to.IsZero() {
		query += " AND stamp<=?"
		args = append(args, to.Unix())
	}
	if in.StatusCode != 0 {
		query += " AND status=?"
		args = append(args, in.StatusCode)
	}
	if in.OnlyBots {
		query += " AND bot=1"
	}
	if in.Search != "" {
		query += " AND (instr(path,?)>0 OR instr(ip,?)>0)"
		args = append(args, in.Search, in.Search)
	}
	query += " ORDER BY stamp,seq"
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	partial := historyLimited || evicted > 0 || state.Blocked > 0 || state.Compressed > 0 || state.Missing > 0 || state.Backlog > 0 || state.Invalid > 0
	out, err := buildAnalyticsRows(ctx, func() (analyticsAccess, error) {
		if !rows.Next() {
			if e := rows.Err(); e != nil {
				return analyticsAccess{}, e
			}
			return analyticsAccess{}, io.EOF
		}
		var raw string
		var row analyticsAccess
		var stamp int64
		var ip, path string
		var status, bot int
		var seconds float64
		if e := rows.Scan(&raw, &stamp, &ip, &path, &status, &seconds, &bot); e != nil {
			return row, e
		}
		if len(raw) > 32768 || json.Unmarshal([]byte(raw), &row) != nil {
			return row, errors.New("统计历史行损坏，未冒充空数据")
		}
		canonical, actualTime, valid := statisticsPrivateRow([]byte(raw), now)
		if !valid || canonical != row || actualTime != stamp || row.Remote != ip || row.Path != path || row.Status != status || row.Seconds != seconds || bot != 0 && bot != 1 || (bot == 1) != strings.Contains(row.Agent, "bot") {
			return row, errors.New("统计历史内容与索引身份不符，保留并拒绝生成误导报告")
		}
		return row, nil
	}, in.SiteID, in, partial, now)
	if err != nil {
		return nil, err
	}
	out["scope"] = "网站日志增量历史；最近 30 天、全站合计最多 250000 条及 512 MiB；时间 UTC，独立 IP 不等于 UV；错误/慢请求各显示最近 100 条。原日志不被修改。"
	out["history_persistent"] = true
	out["history_retention_days"] = statisticsHistoryDays
	out["history_row_limit"] = statisticsHistoryRows
	out["history_backlog_bytes"] = state.Backlog
	out["history_blocked_sources"] = state.Blocked
	out["history_compressed_sources"] = state.Compressed
	out["history_missing_log"] = state.Missing > 0
	out["history_invalid_lines"] = state.Invalid
	out["history_evicted_rows"] = evicted
	out["history_before_retention"] = historyLimited
	out["history_checked_at"] = state.Updated
	out["history_raw_user_agents_stored"] = false
	out["history_query_strings_stored"] = false
	out["history_first_request"] = ""
	out["history_last_request"] = ""
	if first.Valid {
		out["history_first_request"] = time.Unix(first.Int64, 0).UTC().Format(time.RFC3339)
	}
	if last.Valid {
		out["history_last_request"] = time.Unix(last.Int64, 0).UTC().Format(time.RFC3339)
	}
	return out, nil
}

// Closed browsers do not stop collection. This bounded worker holds the same
// lock as application uninstall and log rotation; it never installs/enables
// the application. Errors persist as private, non-secret state and are not
// converted to healthy/zero traffic.
func (s *Service) runStatisticsHistoryWorker(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	cursor := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.mu.Lock()
		if !s.moduleInstalled("website-statistics-v2") {
			s.mu.Unlock()
			continue
		}
		bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
		directory, err := os.OpenFile(s.Config.SitesDir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		var entries []os.DirEntry
		if err == nil {
			entries, err = directory.ReadDir(10001)
			directory.Close()
			if errors.Is(err, io.EOF) {
				err = nil
			}
		}
		ids := []string{}
		if err == nil && len(entries) <= 10000 {
			for _, e := range entries {
				if e.IsDir() && core.ValidID(e.Name()) {
					ids = append(ids, e.Name())
				}
			}
		} else if err == nil {
			err = errors.New("受管网站目录超过 10000 项")
		}
		if len(ids) > 0 && err == nil {
			db, e := s.openStatisticsHistory(bounded)
			err = e
			if err == nil {
				for i := 0; i < min(len(ids), 4); i++ {
					id := ids[(cursor+i)%len(ids)]
					_, e = s.ingestStatisticsHistory(bounded, db, id, time.Now())
					if e != nil {
						err = errors.New("历史采集未完成；原数据及进度保留，请刷新网站报告核对")
						// Continue other sites while the budget remains. A single
						// broken website cannot monopolize every future batch.
						if bounded.Err() != nil {
							break
						}
					}
				}
				db.Close()
				cursor = (cursor + 4) % len(ids)
			}
		}
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		_ = moduleWrite(filepath.Join(s.moduleDir("website-statistics-v2"), "history-worker.json"), map[string]any{"checked_at": core.Now(), "error": detail, "healthy": err == nil, "sites_discovered": len(ids)})
		cancel()
		s.mu.Unlock()
	}
}
