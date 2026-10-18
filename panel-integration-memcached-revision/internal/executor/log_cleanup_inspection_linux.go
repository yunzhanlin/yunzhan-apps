//go:build linux

package executor

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func decodeSiteLogInspectionPlan(raw, site, started string) (siteLogPlan, error) {
	var plan siteLogPlan
	if len(raw) > 512<<10 || validateWAFRotationJSONShape([]byte(raw)) != nil {
		return plan, errors.New("日志核实计划格式异常；保留原记录")
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if d.Decode(&plan) != nil || d.Decode(new(any)) != io.EOF || plan.Rotate == nil || plan.Delete == nil || len(plan.Rotate) > 2 || len(plan.Delete) > siteLogExpiredLimit {
		return plan, errors.New("日志核实计划字段或容量异常")
	}
	at, e := time.Parse(time.RFC3339Nano, started)
	if e != nil || at.UTC().Format(time.RFC3339Nano) != started {
		return plan, errors.New("日志核实计划时间不可核实")
	}
	seen := map[string]bool{}
	for role, items := range [][]siteLogPlanEntry{plan.Rotate, plan.Delete} {
		for _, entry := range items {
			modified, e := time.Parse(time.RFC3339Nano, entry.ModifiedAt)
			if e != nil || modified.UTC().Format(time.RFC3339Nano) != entry.ModifiedAt || entry.Inode == 0 || entry.Bytes < 0 || seen[entry.Name] {
				return plan, errors.New("日志计划文件身份无效或重复")
			}
			seen[entry.Name] = true
			if role == 0 {
				if (entry.Name != "panel-"+site+".access.log" && entry.Name != "panel-"+site+".error.log") || entry.Target != entry.Name+"."+at.UTC().Format("20060102-150405") {
					return plan, errors.New("日志轮转计划包含非本站固定路径")
				}
			} else if entry.Target != "" || !core.ValidSiteLogArchiveName(site, entry.Name) {
				return plan, errors.New("过期日志计划包含非本站文件")
			}
		}
	}
	return plan, nil
}

func observedSiteLogIdentity(root *os.Root, name string, expected siteLogPlanEntry) string {
	info, e := root.Lstat(name)
	if errors.Is(e, os.ErrNotExist) {
		return "absent"
	}
	if e != nil || privateLogEntry(info) != nil {
		return "unverifiable"
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != expected.Device || stat.Ino != expected.Inode {
		return "different_inode"
	}
	if stat.Uid != expected.Owner {
		return "original_inode_owner_changed"
	}
	if info.Size() != expected.Bytes || info.ModTime().UTC().Format(time.RFC3339Nano) != expected.ModifiedAt {
		return "original_inode_written"
	}
	return "original_inode_unchanged"
}

func (s *Service) inspectSiteLogCleanup(ctx context.Context, site, request string) (core.LogCleanupInspection, error) {
	out := core.LogCleanupInspection{SiteID: site, RequestID: request, State: "not_recorded", Files: []core.LogCleanupFileInspection{}, ReadOnly: true}
	if !core.ValidID(site) || !core.ValidID(request) {
		return out, errors.New("日志核实标识无效")
	}
	path := filepath.Join(s.Config.StateDir, "log-cleanup/operations.sqlite")
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return out, nil
	} else if e != nil {
		return out, errors.New("日志操作记录不可读取")
	}
	db, closeDB, e := s.openSiteLogLedgerMode(ctx, false)
	if e != nil {
		return out, e
	}
	defer closeDB()
	var savedSite, result, plan string
	var planBytes, resultBytes int
	e = db.QueryRowContext(ctx, `SELECT site_id,retention_days,state,started_at,length(plan),length(result) FROM operations WHERE request_id=?`, request).Scan(&savedSite, &out.RetentionDays, &out.State, &out.StartedAt, &planBytes, &resultBytes)
	if errors.Is(e, sql.ErrNoRows) {
		return out, nil
	}
	if e != nil || savedSite != site || out.RetentionDays < 1 || out.RetentionDays > 100 || (out.State != "running" && out.State != "unknown" && out.State != "completed") || planBytes < 1 || planBytes > 512<<10 || resultBytes > siteLogLedgerResultLimit {
		return out, errors.New("日志操作记录归属、状态或容量异常；未读取或接管文件")
	}
	if e = db.QueryRowContext(ctx, `SELECT plan,result FROM operations WHERE request_id=? AND site_id=?`, request, site).Scan(&plan, &result); e != nil {
		return out, e
	}
	decoded, e := decodeSiteLogInspectionPlan(plan, site, out.StartedAt)
	if e != nil {
		return out, e
	}
	out.PlanSHA256 = core.Hash(plan)
	var hasContinuation int
	if e = db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='operation_continuations'`).Scan(&hasContinuation); e != nil {
		return out, e
	}
	if hasContinuation == 1 {
		v, e := readSiteLogContinuation(ctx, db, request, site, plan)
		if e != nil {
			return out, e
		}
		if v != nil {
			if out.State == "completed" {
				return out, errors.New("日志继续执行核实记录异常；不接管")
			}
			out.Continuation = v
		}
	}
	if out.State == "completed" {
		completed, e := decodeCompletedSiteLogResult(result, site)
		if e != nil {
			return out, e
		}
		out.Result = &completed
	}
	base := s.systemPath("/var/log/nginx")
	if ownedRuntimePath(base, true) != nil {
		return out, errors.New("日志目录归属异常；核实未执行")
	}
	root, e := os.OpenRoot(base)
	if e != nil {
		return out, e
	}
	defer root.Close()
	for role, items := range [][]siteLogPlanEntry{decoded.Rotate, decoded.Delete} {
		for _, entry := range items {
			if e = ctx.Err(); e != nil {
				return out, e
			}
			file := core.LogCleanupFileInspection{Name: entry.Name, State: observedSiteLogIdentity(root, entry.Name, entry), PlannedBytes: entry.Bytes}
			if role == 0 {
				file.Role = "rotation"
				file.ArchiveState = observedSiteLogIdentity(root, entry.Target, entry)
			} else {
				file.Role = "expiration"
			}
			out.Files = append(out.Files, file)
		}
	}
	return out, nil
}
