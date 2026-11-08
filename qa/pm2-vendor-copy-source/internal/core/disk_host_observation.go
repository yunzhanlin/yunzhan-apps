package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"local/panel/internal/diskjob"
)

// Root's read-only observer uses this without native-worker authority: the
// original full owner may inspect history after a role is restored, but cannot
// redispatch the old authorization revision.
func (s *Store) ValidateHostDiskObservation(ctx context.Context, in diskjob.Request) error {
	if diskjob.ValidateRequest(in) != nil {
		return errHostDiskRecord
	}
	j, err := s.HostDiskForActor(ctx, in.JobID, in.ActorID)
	if err != nil || j.Request != in || j.dispatchSHA == "" {
		return errHostDiskRecord
	}
	return nil
}

func hostDiskOriginalResult(ctx context.Context, db accessReader, j HostDiskJob) (diskjob.Result, bool, error) {
	var requestSHA, resultSHA, raw, state string
	err := db.QueryRowContext(ctx, "SELECT request_sha256,result_sha256,result,state FROM disk_host_job_results WHERE job_id=?", j.ID).Scan(&requestSHA, &resultSHA, &raw, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return diskjob.Result{}, false, nil
	}
	if err != nil || requestSHA != j.dispatchSHA {
		return diskjob.Result{}, false, errHostDiskRecord
	}
	var result diskjob.Result
	if json.Unmarshal([]byte(raw), &result) != nil {
		return diskjob.Result{}, false, errHostDiskRecord
	}
	started := result.Started
	d := diskjob.Dispatch{Format: 1, JobID: j.ID, ActorID: j.actor, RequestSHA: j.dispatchSHA, ExecutorSHA: started.ExecutorSHA}
	decoded, err := diskjob.DecodeResult([]byte(raw), started, d, j.Request)
	if err != nil || resultSHA != diskjob.ResultSHA(decoded) || state != decoded.State || state != j.State {
		return diskjob.Result{}, false, errHostDiskRecord
	}
	var count int
	var actor, digest string
	if db.QueryRowContext(ctx, "SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action='disk.host.result' AND target=?", j.ID).Scan(&count, &actor, &digest) != nil || count != 1 || actor != j.actor || digest != resultSHA {
		return diskjob.Result{}, false, errHostDiskRecord
	}
	return decoded, true, nil
}

// Called only with a trusted executor response, never a public request body.
// Persists a terminal original exactly once and does not release the global
// active slot on HTTP 202, unit disappearance, missing receipts or lost replies.
func (s *Store) ObserveHostDisk(ctx context.Context, o diskjob.Observation, actor string) (HostDiskJob, error) {
	if diskjob.ValidateObservation(o, o.Request) != nil || actor != o.Request.ActorID {
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
	j, err := scanHostDiskJob(tx.QueryRowContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE id=? AND actor_id=?", o.Request.JobID, actor))
	if err != nil || j.Request != o.Request || j.dispatchSHA == "" || hostDiskAudit(ctx, tx, j) != nil {
		return HostDiskJob{}, errHostDiskRecord
	}
	terminal := j.State == "complete" || j.State == "partial" || j.State == "failed" || j.State == "canceled"
	if terminal {
		original, found, err := hostDiskOriginalResult(ctx, tx, j)
		if err == nil && !found {
			c, closed, e := hostDiskOriginalClosure(ctx, tx, j)
			if e != nil || !closed || c.Kind != "result_summary" || o.Result == nil || !o.TerminalVerified || o.ResultSHA != c.ResultSHA || o.State != c.State {
				return HostDiskJob{}, errHostDiskRecord
			}
			return j, tx.Commit()
		}
		if err != nil || !found || o.Result == nil || !o.TerminalVerified || diskjob.ResultSHA(original) != o.ResultSHA {
			return HostDiskJob{}, errHostDiskRecord
		}
		return j, tx.Commit()
	}
	state := j.State
	if o.TerminalVerified {
		state = o.State
		raw, _ := json.Marshal(o.Result)
		if _, err := tx.ExecContext(ctx, "INSERT INTO disk_host_job_results(job_id,request_sha256,result_sha256,result,state,created_at) VALUES(?,?,?,?,?,?)", j.ID, j.dispatchSHA, o.ResultSHA, string(raw), state, Now()); err != nil {
			return HostDiskJob{}, errHostDiskRecord
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'disk.host.result',?,?,?)", actor, j.ID, o.ResultSHA, Now()); err != nil {
			return HostDiskJob{}, err
		}
	} else if j.State != "cancel_requested" {
		switch o.State {
		case "running":
			state = "running"
		case "starting":
			if j.State != "dispatching" {
				return HostDiskJob{}, errHostDiskRecord
			}
		case "settling", "uncertain":
			state = "uncertain"
		default:
			return HostDiskJob{}, errHostDiskRecord
		}
	}
	if state != j.State {
		j.UpdatedAt = Now()
		result, err := tx.ExecContext(ctx, "UPDATE disk_host_jobs SET state=?,updated_at=? WHERE id=? AND state=?", state, j.UpdatedAt, j.ID, j.State)
		if err != nil {
			return HostDiskJob{}, err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return HostDiskJob{}, errHostDiskRecord
		}
		j.State = state
	}
	if err := validateHostDiskJob(j); err != nil {
		return HostDiskJob{}, err
	}
	return j, tx.Commit()
}

func (s *Store) HostDiskResultForActor(ctx context.Context, id, actor string) (diskjob.Result, bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return diskjob.Result{}, false, err
	}
	defer tx.Rollback()
	if _, err := hostDiskAuthority(ctx, tx, actor); err != nil {
		return diskjob.Result{}, false, err
	}
	j, err := scanHostDiskJob(tx.QueryRowContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE id=? AND actor_id=?", id, actor))
	if err != nil || hostDiskAudit(ctx, tx, j) != nil {
		return diskjob.Result{}, false, errHostDiskRecord
	}
	r, found, err := hostDiskOriginalResult(ctx, tx, j)
	if err != nil {
		return r, found, err
	}
	return r, found, tx.Commit()
}

func (a *Server) diskHostObservationRoutes(m *http.ServeMux) {
	// GET only reconciles this original ID. It never queues, starts, cancels,
	// downloads, installs, repairs or resubmits a native task.
	m.HandleFunc("GET /api/software/disk-analysis/host/jobs/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		j, err := a.Store.HostDiskForActor(ctx, r.PathValue("id"), u.ID)
		if err != nil {
			fail(w, 403, "仅原完整管理员可读取原全盘任务")
			return
		}
		if result, found, err := a.Store.HostDiskResultForActor(ctx, j.ID, u.ID); err != nil {
			fail(w, 409, "原全盘结果或审计无法核对")
			return
		} else if found {
			send(w, 200, map[string]any{"job": j, "result": result, "terminal_verified": true})
			return
		}
		if j.dispatchSHA == "" {
			send(w, 200, map[string]any{"job": j, "terminal_verified": j.State == "canceled", "native_dispatched": false})
			return
		}
		if c, closed, err := a.Store.HostDiskClosureForActor(ctx, j.ID, u.ID); err != nil {
			fail(w, 409, "原任务终结凭证无法核对")
			return
		} else if closed && c.Kind != "result_summary" {
			send(w, 200, map[string]any{"job": j, "closure": c, "terminal_verified": true, "report_unavailable": true})
			return
		}
		var observation diskjob.Observation
		if err := a.Executor.Call(ctx, "POST", "/v1/disk-host-jobs/observe", j.Request, &observation); err != nil {
			fail(w, 409, "原全盘执行状态暂不能核对；未重发任务，也未认定结束")
			return
		}
		j, err = a.Store.ObserveHostDisk(ctx, observation, u.ID)
		if err != nil {
			fail(w, 409, "原任务授权、结果或实际退出证据无法核对")
			return
		}
		send(w, 200, map[string]any{"job": j, "observation": observation, "terminal_verified": observation.TerminalVerified})
	}))
}
