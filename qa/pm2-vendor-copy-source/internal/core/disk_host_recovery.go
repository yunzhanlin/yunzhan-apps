package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"

	"local/panel/internal/diskjob"
)

// Original ownership never changes. A CURRENT full operator may explicitly
// stop/close an orphan or interrupted host task, without receiving its private
// paths, reports or permission to redispatch its original authorization.
func hostDiskOriginalClosure(ctx context.Context, db accessReader, j HostDiskJob) (diskjob.Closure, bool, error) {
	var requestSHA, sha, raw, state, operator string
	err := db.QueryRowContext(ctx, "SELECT request_sha256,closure_sha256,closure,state,operator_id FROM disk_host_job_closures WHERE job_id=?", j.ID).Scan(&requestSHA, &sha, &raw, &state, &operator)
	if errors.Is(err, sql.ErrNoRows) {
		return diskjob.Closure{}, false, nil
	}
	if err != nil || requestSHA != j.dispatchSHA || !ValidID(operator) {
		return diskjob.Closure{}, false, errHostDiskRecord
	}
	c, err := diskjob.DecodeClosure([]byte(raw), j.Request)
	if err != nil || diskjob.ClosureSHA(c) != sha || c.State != state || state != j.State {
		return diskjob.Closure{}, false, errHostDiskRecord
	}
	var count int
	var auditActor, auditSHA string
	if db.QueryRowContext(ctx, "SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action='disk.host.close' AND target=?", j.ID).Scan(&count, &auditActor, &auditSHA) != nil || count != 1 || auditActor != operator || auditSHA != sha {
		return diskjob.Closure{}, false, errHostDiskRecord
	}
	return c, true, nil
}

func hostDiskTerminal(state string) bool {
	return state == "complete" || state == "partial" || state == "failed" || state == "canceled"
}

func (s *Store) PrepareHostDiskRecovery(ctx context.Context, id, operator string) (HostDiskJob, *diskjob.RecoveryRequest, error) {
	if !ValidID(id) {
		return HostDiskJob{}, nil, errHostDiskRecord
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return HostDiskJob{}, nil, err
	}
	defer tx.Rollback()
	access, err := hostDiskAuthority(ctx, tx, operator)
	if err != nil {
		return HostDiskJob{}, nil, err
	}
	j, err := scanHostDiskJob(tx.QueryRowContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE id=?", id))
	if err != nil || hostDiskAudit(ctx, tx, j) != nil {
		return HostDiskJob{}, nil, errHostDiskRecord
	}
	if hostDiskTerminal(j.State) {
		return j, nil, tx.Commit()
	}
	if j.State != "cancel_requested" {
		state, cancelState := "cancel_requested", "requested"
		if j.dispatchSHA == "" {
			state, cancelState = "canceled", "not_dispatched"
		}
		if _, err := tx.ExecContext(ctx, "UPDATE disk_host_jobs SET state=?,cancel_state=?,updated_at=? WHERE id=?", state, cancelState, Now(), id); err != nil {
			return HostDiskJob{}, nil, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'disk.host.recovery.request',?,?,?)", operator, id, j.dispatchSHA, Now()); err != nil {
			return HostDiskJob{}, nil, err
		}
		j.State, j.CancelState, j.UpdatedAt = state, cancelState, Now()
	}
	if j.dispatchSHA == "" {
		return j, nil, tx.Commit()
	}
	in := diskjob.RecoveryRequest{Format: 1, Operator: diskjob.InventoryRequest{Format: 1, ActorID: operator, AccessRevision: strconv.FormatInt(access.Revision, 10)}, Request: j.Request}
	return j, &in, tx.Commit()
}

// Root uses a separately opened read-only DB. This does not invent a new
// owner/revision or permit a command; it only validates an explicit stop fence.
func (s *Store) ValidateHostDiskRecovery(ctx context.Context, in diskjob.RecoveryRequest) error {
	raw, _ := json.Marshal(in)
	if _, err := diskjob.DecodeRecoveryRequest(raw); err != nil {
		return errHostDiskRecord
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	access, err := hostDiskAuthority(ctx, tx, in.Operator.ActorID)
	if err != nil || in.Operator.AccessRevision != strconv.FormatInt(access.Revision, 10) {
		return errHostDiskAuthority
	}
	j, err := scanHostDiskJob(tx.QueryRowContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE id=?", in.Request.JobID))
	if err != nil || j.Request != in.Request || j.dispatchSHA != diskjob.RequestSHA(in.Request) || j.State != "cancel_requested" || j.CancelState != "requested" || hostDiskAudit(ctx, tx, j) != nil {
		return errHostDiskRecord
	}
	return tx.Commit()
}

func (s *Store) FinishHostDiskRecovery(ctx context.Context, in diskjob.RecoveryRequest, ack diskjob.RecoveryAck) (HostDiskJob, error) {
	if diskjob.ValidateRecoveryAck(ack, in.Request) != nil {
		return HostDiskJob{}, errHostDiskRecord
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return HostDiskJob{}, err
	}
	defer tx.Rollback()
	access, err := hostDiskAuthority(ctx, tx, in.Operator.ActorID)
	if err != nil || in.Operator.AccessRevision != strconv.FormatInt(access.Revision, 10) {
		return HostDiskJob{}, errHostDiskAuthority
	}
	j, err := scanHostDiskJob(tx.QueryRowContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE id=?", in.Request.JobID))
	if err != nil || j.Request != in.Request || j.dispatchSHA != diskjob.RequestSHA(in.Request) || hostDiskAudit(ctx, tx, j) != nil {
		return HostDiskJob{}, errHostDiskRecord
	}
	if hostDiskTerminal(j.State) {
		if prior, found, err := hostDiskOriginalClosure(ctx, tx, j); err != nil || !found || ack.Closure == nil || diskjob.ClosureSHA(prior) != diskjob.ClosureSHA(*ack.Closure) {
			return HostDiskJob{}, errHostDiskRecord
		}
		return j, tx.Commit()
	}
	if j.State != "cancel_requested" || j.CancelState != "requested" {
		return HostDiskJob{}, errHostDiskRecord
	}
	if ack.Closure == nil {
		return j, tx.Commit()
	}
	c := *ack.Closure
	raw, _ := json.Marshal(c)
	sha := diskjob.ClosureSHA(c)
	if _, err := tx.ExecContext(ctx, "INSERT INTO disk_host_job_closures(job_id,request_sha256,closure_sha256,closure,state,operator_id,created_at) VALUES(?,?,?,?,?,?,?)", j.ID, j.dispatchSHA, sha, string(raw), c.State, in.Operator.ActorID, Now()); err != nil {
		return HostDiskJob{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'disk.host.close',?,?,?)", in.Operator.ActorID, j.ID, sha, Now()); err != nil {
		return HostDiskJob{}, err
	}
	j.State = c.State
	j.UpdatedAt = Now()
	if _, err := tx.ExecContext(ctx, "UPDATE disk_host_jobs SET state=?,updated_at=? WHERE id=?", j.State, j.UpdatedAt, j.ID); err != nil {
		return HostDiskJob{}, err
	}
	return j, tx.Commit()
}

func (s *Store) HostDiskClosureForActor(ctx context.Context, id, actor string) (diskjob.Closure, bool, error) {
	j, err := s.HostDiskForActor(ctx, id, actor)
	if err != nil {
		return diskjob.Closure{}, false, err
	}
	return hostDiskOriginalClosure(ctx, s.DB, j)
}
