package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"local/panel/internal/diskjob"
)

var errHostDiskAuthority = errors.New("全盘任务仅原完整管理员可管理；原账户、角色或菜单权限不能核对")
var errHostDiskRecord = errors.New("原全盘任务记录或执行意图无法核对；未提交、重发或覆盖")
var ErrHostDiskCancelRequested = errors.New("原全盘任务已请求取消；未启动或继续枚举")

type HostDiskJob struct {
	ID          string          `json:"id"`
	Request     diskjob.Request `json:"request"`
	State       string          `json:"state"`
	CancelState string          `json:"cancel_state"`
	CreatedAt   string          `json:"created_at"`
	UpdatedAt   string          `json:"updated_at"`
	dispatchSHA string
	actor       string
	key         string
}

func hostDiskAuthority(ctx context.Context, db accessReader, actor string) (UserAccess, error) {
	if !ValidID(actor) {
		return UserAccess{}, errHostDiskAuthority
	}
	access, err := readUserAccessContext(ctx, db, actor)
	if err != nil || !fullAdministrator(access) || access.Revision < 1 {
		return UserAccess{}, errHostDiskAuthority
	}
	return access, nil
}

func validateHostDiskJob(j HostDiskJob) error {
	if diskjob.ValidateRequest(j.Request) != nil || j.ID != j.Request.JobID || j.actor != j.Request.ActorID || !ValidID(j.key) {
		return errHostDiskRecord
	}
	created, e1 := time.Parse(time.RFC3339, j.CreatedAt)
	updated, e2 := time.Parse(time.RFC3339, j.UpdatedAt)
	if e1 != nil || e2 != nil || updated.Before(created) || created.Year() < 2026 {
		return errHostDiskRecord
	}
	if j.CancelState != "" && j.CancelState != "requested" && j.CancelState != "not_dispatched" {
		return errHostDiskRecord
	}
	raw, _ := json.Marshal(j.Request)
	if j.dispatchSHA != "" && j.dispatchSHA != Hash(string(raw)) {
		return errHostDiskRecord
	}
	switch j.State {
	case "queued":
		if j.dispatchSHA != "" || j.CancelState != "" {
			return errHostDiskRecord
		}
	case "dispatching", "running", "uncertain":
		if j.dispatchSHA == "" || j.CancelState != "" {
			return errHostDiskRecord
		}
	case "cancel_requested":
		if j.dispatchSHA == "" || j.CancelState != "requested" {
			return errHostDiskRecord
		}
	case "canceled":
		if j.dispatchSHA == "" && j.CancelState != "not_dispatched" {
			return errHostDiskRecord
		}
	case "complete", "partial", "failed":
		if j.dispatchSHA == "" {
			return errHostDiskRecord
		}
	default:
		return errHostDiskRecord
	}
	return nil
}

type hostDiskRows interface{ Scan(...any) error }

func scanHostDiskJob(row hostDiskRows) (HostDiskJob, error) {
	var j HostDiskJob
	var raw string
	if err := row.Scan(&j.ID, &j.actor, &raw, &j.key, &j.State, &j.dispatchSHA, &j.CancelState, &j.CreatedAt, &j.UpdatedAt); err != nil {
		return j, err
	}
	in, err := diskjob.DecodeRequest([]byte(raw))
	if err != nil {
		return j, errHostDiskRecord
	}
	j.Request = in
	return j, validateHostDiskJob(j)
}

const hostDiskColumns = "id,actor_id,request,idempotency_key,state,dispatch_sha256,cancel_state,created_at,updated_at"

func hostDiskAudit(ctx context.Context, db accessReader, j HostDiskJob) error {
	var count int
	var owner, result string
	if db.QueryRowContext(ctx, "SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action='disk.host.queue' AND target=?", j.ID).Scan(&count, &owner, &result) != nil || count != 1 || owner != j.actor || result != "queued" {
		return errHostDiskRecord
	}
	if db.QueryRowContext(ctx, "SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action='disk.host.dispatch' AND target=?", j.ID).Scan(&count, &owner, &result) != nil {
		return errHostDiskRecord
	}
	if j.dispatchSHA == "" {
		if count != 0 {
			return errHostDiskRecord
		}
	} else if count != 1 || owner != j.actor || result != j.dispatchSHA {
		return errHostDiskRecord
	}
	if j.State == "complete" || j.State == "partial" || j.State == "failed" || j.State == "canceled" && j.dispatchSHA != "" {
		_, found, err := hostDiskOriginalResult(ctx, db, j)
		if err != nil {
			return errHostDiskRecord
		}
		_, closed, err := hostDiskOriginalClosure(ctx, db, j)
		if err != nil || found == closed {
			return errHostDiskRecord
		}
		otherAction := "disk.host.result"
		if found {
			otherAction = "disk.host.close"
		}
		if db.QueryRowContext(ctx, "SELECT count(*) FROM audit_logs WHERE action=? AND target=?", otherAction, j.ID).Scan(&count) != nil || count != 0 {
			return errHostDiskRecord
		}
	} else {
		if db.QueryRowContext(ctx, "SELECT count(*) FROM disk_host_job_results WHERE job_id=?", j.ID).Scan(&count) != nil || count != 0 {
			return errHostDiskRecord
		}
		if db.QueryRowContext(ctx, "SELECT count(*) FROM audit_logs WHERE action='disk.host.result' AND target=?", j.ID).Scan(&count) != nil || count != 0 {
			return errHostDiskRecord
		}
		if db.QueryRowContext(ctx, "SELECT count(*) FROM disk_host_job_closures WHERE job_id=?", j.ID).Scan(&count) != nil || count != 0 {
			return errHostDiskRecord
		}
		if db.QueryRowContext(ctx, "SELECT count(*) FROM audit_logs WHERE action='disk.host.close' AND target=?", j.ID).Scan(&count) != nil || count != 0 {
			return errHostDiskRecord
		}
	}
	return nil
}

// Dedicated ledger, not runtime_jobs/general app report or global worker queue.
// No executor POST happens until a separately committed single-dispatch intent.
// Actor IDs intentionally are not a users FK: deleting an account revokes access
// and worker authority but must preserve original evidence, not block deletion.
func (s *Store) QueueHostDisk(ctx context.Context, in diskjob.Selection, key, actor string) (HostDiskJob, bool, error) {
	if diskjob.ValidateSelection(in) != nil || !ValidID(key) {
		return HostDiskJob{}, false, errHostDiskRecord
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return HostDiskJob{}, false, err
	}
	defer tx.Rollback()
	access, err := hostDiskAuthority(ctx, tx, actor)
	if err != nil {
		return HostDiskJob{}, false, err
	}
	prior, err := scanHostDiskJob(tx.QueryRowContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE idempotency_key=?", key))
	if err == nil {
		if prior.actor != actor || prior.Request.Selection != in || hostDiskAudit(ctx, tx, prior) != nil {
			return HostDiskJob{}, false, errHostDiskRecord
		}
		return prior, true, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return HostDiskJob{}, false, errHostDiskRecord
	}
	if err := hostDiskApplicationIdle(ctx, tx); err != nil {
		return HostDiskJob{}, false, err
	}
	var count int
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM disk_host_jobs").Scan(&count) != nil || count >= diskjob.ActiveJobsMax {
		return HostDiskJob{}, false, errors.New("全盘任务记录达到128份，未自动清理原证据")
	}
	id, created := ID(), Now()
	r := diskjob.Request{Format: 1, JobID: id, ActorID: actor, AccessRevision: strconv.FormatInt(access.Revision, 10), Selection: in}
	raw, _ := json.Marshal(r)
	if _, err := tx.ExecContext(ctx, "INSERT INTO disk_host_jobs(id,actor_id,request,idempotency_key,state,created_at,updated_at) VALUES(?,?,?,?,'queued',?,?)", id, actor, string(raw), key, created, created); err != nil {
		return HostDiskJob{}, false, errors.New("原全盘任务仍未确认结束，未并行创建新扫描")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'disk.host.queue',?,'queued',?)", actor, id, created); err != nil {
		return HostDiskJob{}, false, err
	}
	j := HostDiskJob{ID: id, Request: r, State: "queued", CreatedAt: created, UpdatedAt: created, actor: actor, key: key}
	return j, false, tx.Commit()
}

// Reading history does not expand permissions or reveal another administrator's
// private host paths. A restored full admin may observe its old original job;
// that does not authorize redispatch using a stale access revision.
func (s *Store) HostDiskForActor(ctx context.Context, id, actor string) (HostDiskJob, error) {
	if !ValidID(id) {
		return HostDiskJob{}, errHostDiskRecord
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return HostDiskJob{}, err
	}
	defer tx.Rollback()
	if _, err := hostDiskAuthority(ctx, tx, actor); err != nil {
		return HostDiskJob{}, err
	}
	j, err := scanHostDiskJob(tx.QueryRowContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE id=? AND actor_id=?", id, actor))
	if err != nil {
		return HostDiskJob{}, errHostDiskRecord
	}
	if hostDiskAudit(ctx, tx, j) != nil {
		return HostDiskJob{}, errHostDiskRecord
	}
	return j, tx.Commit()
}

// True means GET-only reconciliation: never repeat the POST after a crash,
// timeout, cancellation request, restart or terminal original receipt.
func (s *Store) HostDiskDispatchBoundary(ctx context.Context, id, actor string) (HostDiskJob, bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return HostDiskJob{}, false, err
	}
	defer tx.Rollback()
	access, err := hostDiskAuthority(ctx, tx, actor)
	if err != nil {
		return HostDiskJob{}, false, err
	}
	j, err := scanHostDiskJob(tx.QueryRowContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE id=? AND actor_id=?", id, actor))
	if err != nil {
		return HostDiskJob{}, false, errHostDiskRecord
	}
	if hostDiskAudit(ctx, tx, j) != nil {
		return HostDiskJob{}, false, errHostDiskRecord
	}
	if j.State != "queued" {
		return j, true, tx.Commit()
	}
	if j.Request.AccessRevision != strconv.FormatInt(access.Revision, 10) {
		return HostDiskJob{}, false, errHostDiskAuthority
	}
	var count int
	var owner, result string
	if tx.QueryRowContext(ctx, "SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action='disk.host.queue' AND target=?", id).Scan(&count, &owner, &result) != nil || count != 1 || owner != actor || result != "queued" {
		return HostDiskJob{}, false, errHostDiskRecord
	}
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM audit_logs WHERE action='disk.host.dispatch' AND target=?", id).Scan(&count) != nil || count != 0 {
		return HostDiskJob{}, false, errHostDiskRecord
	}
	raw, _ := json.Marshal(j.Request)
	j.dispatchSHA = Hash(string(raw))
	j.State = "dispatching"
	j.UpdatedAt = Now()
	if _, err := tx.ExecContext(ctx, "UPDATE disk_host_jobs SET state='dispatching',dispatch_sha256=?,updated_at=? WHERE id=? AND state='queued' AND dispatch_sha256=''", j.dispatchSHA, j.UpdatedAt, id); err != nil {
		return HostDiskJob{}, false, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'disk.host.dispatch',?,?,?)", actor, id, j.dispatchSHA, j.UpdatedAt); err != nil {
		return HostDiskJob{}, false, err
	}
	return j, false, tx.Commit()
}

// Cancelling a still-undispatched Core row is terminal. Cancelling a dispatched
// row is only an intent: actual termination and original result reconciliation
// belong to the fixed root scope handler, never a blind success from HTTP202.
func (s *Store) RequestHostDiskCancel(ctx context.Context, id, actor string) (HostDiskJob, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return HostDiskJob{}, err
	}
	defer tx.Rollback()
	if _, err := hostDiskAuthority(ctx, tx, actor); err != nil {
		return HostDiskJob{}, err
	}
	j, err := scanHostDiskJob(tx.QueryRowContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE id=? AND actor_id=?", id, actor))
	if err != nil {
		return HostDiskJob{}, errHostDiskRecord
	}
	if hostDiskAudit(ctx, tx, j) != nil {
		return HostDiskJob{}, errHostDiskRecord
	}
	switch j.State {
	case "queued":
		j.State = "canceled"
		j.CancelState = "not_dispatched"
	case "dispatching", "running", "uncertain":
		j.State = "cancel_requested"
		j.CancelState = "requested"
	case "cancel_requested", "canceled", "complete", "partial", "failed":
		return j, tx.Commit()
	default:
		return HostDiskJob{}, errHostDiskRecord
	}
	j.UpdatedAt = Now()
	if _, err := tx.ExecContext(ctx, "UPDATE disk_host_jobs SET state=?,cancel_state=?,updated_at=? WHERE id=?", j.State, j.CancelState, j.UpdatedAt, id); err != nil {
		return HostDiskJob{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'disk.host.cancel',?,?,?)", actor, id, j.CancelState, j.UpdatedAt); err != nil {
		return HostDiskJob{}, err
	}
	return j, tx.Commit()
}

// Used by the fixed root worker with a separately opened READ-ONLY Core DB.
// Does not migrate the database, read credentials, write Core state or grant
// privileges from a supplied actor string. The exact original queued intent,
// unique audit actor/digest and current full authorization must all agree.
func (s *Store) ValidateHostDiskNative(ctx context.Context, request diskjob.Request) error {
	if diskjob.ValidateRequest(request) != nil {
		return errHostDiskRecord
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return errHostDiskRecord
	}
	defer tx.Rollback()
	access, err := hostDiskAuthority(ctx, tx, request.ActorID)
	if err != nil || request.AccessRevision != strconv.FormatInt(access.Revision, 10) {
		return errHostDiskAuthority
	}
	j, err := scanHostDiskJob(tx.QueryRowContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE id=? AND actor_id=?", request.JobID, request.ActorID))
	if err != nil || j.Request != request || j.dispatchSHA == "" || hostDiskAudit(ctx, tx, j) != nil {
		return errHostDiskRecord
	}
	if j.State == "cancel_requested" {
		return ErrHostDiskCancelRequested
	}
	if j.State != "dispatching" && j.State != "running" && j.State != "uncertain" {
		return errHostDiskRecord
	}
	if err := hostDiskApplicationIdle(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func hostDiskApplicationIdle(ctx context.Context, db accessReader) error {
	var count int
	if db.QueryRowContext(ctx, "SELECT count(*) FROM runtime_jobs WHERE target_id='disk-analysis' AND (state IS NULL OR state NOT IN ('succeeded','failed','canceled'))").Scan(&count) != nil || count != 0 {
		return errors.New("磁盘应用存在未结束的安装、更新、配置或卸载操作，未开始全盘任务")
	}
	return nil
}
