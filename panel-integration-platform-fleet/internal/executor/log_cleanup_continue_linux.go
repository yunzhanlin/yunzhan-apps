//go:build linux

package executor

import (
	"context"
	"database/sql"
	"errors"
	"local/panel/internal/core"
	"os"
	"strings"
	"syscall"
	"time"
)

func siteLogSHA256(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}

func validSiteLogContinuation(v core.LogCleanupContinuation, plan string) bool {
	at, e := time.Parse(time.RFC3339Nano, v.VerifiedAt)
	return core.ValidID(v.RequestID) && core.ValidID(v.SiteID) && v.PlanSHA256 == core.Hash(plan) && siteLogSHA256(v.EvidenceSHA256) && e == nil && at.UTC().Format(time.RFC3339Nano) == v.VerifiedAt
}

func readSiteLogContinuation(ctx context.Context, db *sql.DB, request, site, plan string) (*core.LogCleanupContinuation, error) {
	v := core.LogCleanupContinuation{RequestID: request, SiteID: site}
	var size int
	var evidence string
	e := db.QueryRowContext(ctx, `SELECT plan_sha256,verified_at,evidence_sha256,length(evidence),CASE WHEN length(evidence)<=524288 THEN evidence ELSE '' END FROM operation_continuations WHERE request_id=?`, request).Scan(&v.PlanSHA256, &v.VerifiedAt, &v.EvidenceSHA256, &size, &evidence)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if !validSiteLogContinuation(v, plan) || size < 1 || size > 512<<10 || core.Hash(evidence) != v.EvidenceSHA256 || validateWAFRotationJSONShape([]byte(evidence)) != nil {
		return nil, errors.New("继续执行证据与摘要不匹配；保留阻塞")
	}
	return &v, nil
}

func siteLogPendingOperations(ctx context.Context, db *sql.DB, site string) (int, error) {
	rows, e := db.QueryContext(ctx, `SELECT o.request_id,length(o.plan),CASE WHEN length(o.plan)<=524288 THEN o.plan ELSE '' END,coalesce(c.plan_sha256,''),coalesce(c.verified_at,''),coalesce(c.evidence_sha256,''),coalesce(length(c.evidence),0),CASE WHEN length(c.evidence)<=524288 THEN c.evidence ELSE '' END FROM operations o LEFT JOIN operation_continuations c ON c.request_id=o.request_id WHERE o.site_id=? AND o.state!='completed' LIMIT 1001`, site)
	if e != nil {
		return 0, e
	}
	defer rows.Close()
	pending, count := 0, 0
	for rows.Next() {
		count++
		var plan, evidence string
		var size, evidenceSize int
		v := core.LogCleanupContinuation{SiteID: site}
		if e = rows.Scan(&v.RequestID, &size, &plan, &v.PlanSHA256, &v.VerifiedAt, &v.EvidenceSHA256, &evidenceSize, &evidence); e != nil {
			return 0, e
		}
		if count > 1000 || size < 1 || size > 512<<10 {
			return 0, errors.New("未完成日志操作超过核实预算；不绕过未知记录")
		}
		if v.PlanSHA256 == "" && v.VerifiedAt == "" && v.EvidenceSHA256 == "" && evidenceSize == 0 {
			pending++
			continue
		}
		if !validSiteLogContinuation(v, plan) || evidenceSize < 1 || evidenceSize > 512<<10 || core.Hash(evidence) != v.EvidenceSHA256 || validateWAFRotationJSONShape([]byte(evidence)) != nil {
			return 0, errors.New("日志继续执行核实记录异常；不解除阻塞")
		}
	}
	return pending, rows.Err()
}

func siteLogEntryIdentity(info os.FileInfo, entry siteLogPlanEntry) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Dev) == entry.Device && stat.Ino == entry.Inode
}

// Permit only the original active inode (safe rollback), or a new active
// inode with its original archive retained. Missing expired paths stay unknown.
func siteLogContinuationFiles(ctx context.Context, root *os.Root, site string, plan siteLogPlan) ([]plannedSiteLog, []plannedSiteLog, error) {
	active, retired := []plannedSiteLog{}, []plannedSiteLog{}
	for _, entry := range plan.Rotate {
		if e := ctx.Err(); e != nil {
			return nil, nil, e
		}
		current, e := root.Lstat(entry.Name)
		if e != nil || privateLogEntry(current) != nil {
			return nil, nil, errors.New("活动日志缺失或身份不可核实；不解除阻塞")
		}
		archive, archiveErr := root.Lstat(entry.Target)
		if siteLogEntryIdentity(current, entry) {
			if !errors.Is(archiveErr, os.ErrNotExist) || current.Size() < entry.Bytes {
				return nil, nil, errors.New("原活动日志存在但归档冲突或内容缩短；保留阻塞")
			}
		} else {
			modified, _ := time.Parse(time.RFC3339Nano, entry.ModifiedAt)
			if archiveErr != nil || privateLogEntry(archive) != nil || !siteLogEntryIdentity(archive, entry) || archive.Size() < entry.Bytes || archive.ModTime().Before(modified) {
				return nil, nil, errors.New("原轮转归档未保留或身份不可核实；不解除阻塞")
			}
			retired = append(retired, plannedSiteLog{name: entry.Target, info: archive})
		}
	}
	for _, entry := range plan.Delete {
		if e := ctx.Err(); e != nil {
			return nil, nil, e
		}
		info, e := root.Lstat(entry.Name)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || privateLogEntry(info) != nil || !siteLogEntryIdentity(info, entry) || info.Size() != entry.Bytes || info.ModTime().UTC().Format(time.RFC3339Nano) != entry.ModifiedAt {
			return nil, nil, errors.New("过期日志已替换或发生写入；保留数据和阻塞")
		}
		retired = append(retired, plannedSiteLog{name: entry.Name, info: info})
	}
	for _, kind := range []string{"access", "error"} {
		name := "panel-" + site + "." + kind + ".log"
		info, e := root.Lstat(name)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || privateLogEntry(info) != nil {
			return nil, nil, errors.New("本站当前日志类型或归属异常；不解除阻塞")
		}
		active = append(active, plannedSiteLog{name: name, info: info})
	}
	if len(active) == 0 {
		return nil, nil, errors.New("本站没有可验证的 Nginx 活动日志；不解除阻塞")
	}
	return active, retired, nil
}

func (s *Service) verifySiteLogContinuationNative(ctx context.Context, active, retired []plannedSiteLog) error {
	// Prepare only reads identity and descriptor metadata. Do not call the
	// returned SIGUSR1 callback: recovery must never replay file mutations.
	if _, e := s.prepareSiteLogReopen(ctx, active); e != nil {
		return e
	}
	return siteLogExpiredOpenWriters(ctx, s.systemPath("/proc"), retired)
}

func (s *Service) continueSiteLogCleanup(ctx context.Context, in core.LogCleanupContinueRequest, verify func(context.Context, []plannedSiteLog, []plannedSiteLog) error) (core.LogCleanupContinuation, error) {
	out := core.LogCleanupContinuation{RequestID: in.RequestID, SiteID: in.SiteID, PlanSHA256: in.PlanSHA256}
	if !core.ValidID(in.RequestID) || !core.ValidID(in.SiteID) || !siteLogSHA256(in.PlanSHA256) || !in.AcknowledgeUnknown {
		return out, errors.New("日志继续执行核实参数无效")
	}
	db, closeDB, e := s.openSiteLogLedger(ctx)
	if e != nil {
		return out, e
	}
	defer closeDB()
	var site, state, started, raw string
	var size int
	e = db.QueryRowContext(ctx, `SELECT site_id,state,started_at,length(plan),CASE WHEN length(plan)<=524288 THEN plan ELSE '' END FROM operations WHERE request_id=?`, in.RequestID).Scan(&site, &state, &started, &size, &raw)
	if e != nil || site != in.SiteID || size < 1 || size > 512<<10 || core.Hash(raw) != in.PlanSHA256 || (state != "unknown" && state != "running") {
		return out, errors.New("未知日志记录归属、状态或计划已变化；不解除阻塞")
	}
	saved, e := readSiteLogContinuation(ctx, db, in.RequestID, in.SiteID, raw)
	if e != nil {
		return out, e
	}
	if saved != nil {
		return *saved, nil
	}
	plan, e := decodeSiteLogInspectionPlan(raw, site, started)
	if e != nil {
		return out, e
	}
	base := s.systemPath("/var/log/nginx")
	if ownedRuntimePath(base, true) != nil {
		return out, errors.New("日志目录归属不可核实；不解除阻塞")
	}
	root, e := os.OpenRoot(base)
	if e != nil {
		return out, e
	}
	defer root.Close()
	anchor, e := root.Stat(".")
	if e != nil {
		return out, e
	}
	active, retired, e := siteLogContinuationFiles(ctx, root, site, plan)
	if e != nil {
		return out, e
	}
	if verify == nil {
		verify = s.verifySiteLogContinuationNative
	}
	if e = verify(ctx, active, retired); e != nil {
		return out, e
	}
	current, e := os.Lstat(base)
	if e != nil || ownedRuntimePath(base, true) != nil || !os.SameFile(anchor, current) {
		return out, errors.New("日志目录在核实时发生替换；不解除阻塞")
	}
	if e = siteLogContinuationStable(root, active, retired); e != nil {
		return out, e
	}
	if _, _, e = siteLogContinuationFiles(ctx, root, site, plan); e != nil {
		return out, e
	}
	evidence, e := encodeSiteLogPlan(active, retired)
	if e != nil {
		return out, e
	}
	out.VerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
	out.EvidenceSHA256 = core.Hash(string(evidence))
	_, e = db.ExecContext(ctx, `INSERT INTO operation_continuations(request_id,plan_sha256,verified_at,evidence_sha256,evidence) VALUES(?,?,?,?,?)`, in.RequestID, out.PlanSHA256, out.VerifiedAt, out.EvidenceSHA256, string(evidence))
	return out, e
}

func siteLogContinuationStable(root *os.Root, active, retired []plannedSiteLog) error {
	for role, items := range [][]plannedSiteLog{active, retired} {
		for _, item := range items {
			info, e := root.Lstat(item.name)
			if e != nil || privateLogEntry(info) != nil || !os.SameFile(info, item.info) {
				return errors.New("日志文件身份在核实时变化；不解除阻塞")
			}
			if role == 0 && info.Size() < item.info.Size() || role == 1 && (info.Size() != item.info.Size() || !info.ModTime().Equal(item.info.ModTime())) {
				return errors.New("日志发生缩短或归档写入；不解除阻塞")
			}
		}
	}
	return nil
}
