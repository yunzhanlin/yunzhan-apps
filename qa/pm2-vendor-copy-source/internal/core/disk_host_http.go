package core

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"time"

	"local/panel/internal/diskjob"
)

func (s *Store) HostDiskReplay(ctx context.Context, in diskjob.Selection, key, actor string) (HostDiskJob, bool, error) {
	if diskjob.ValidateSelection(in) != nil || !ValidID(key) {
		return HostDiskJob{}, false, errHostDiskRecord
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return HostDiskJob{}, false, err
	}
	defer tx.Rollback()
	if _, err := hostDiskAuthority(ctx, tx, actor); err != nil {
		return HostDiskJob{}, false, err
	}
	j, err := scanHostDiskJob(tx.QueryRowContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE idempotency_key=?", key))
	if errors.Is(err, sql.ErrNoRows) {
		return HostDiskJob{}, false, nil
	}
	if err != nil || j.actor != actor || j.Request.Selection != in || hostDiskAudit(ctx, tx, j) != nil {
		return HostDiskJob{}, false, errHostDiskRecord
	}
	return j, true, tx.Commit()
}

func (s *Store) HostDiskJobsForActor(ctx context.Context, actor string) ([]HostDiskJob, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := hostDiskAuthority(ctx, tx, actor); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE actor_id=? ORDER BY created_at DESC,id DESC LIMIT 129", actor)
	if err != nil {
		return nil, err
	}
	jobs := []HostDiskJob{}
	for rows.Next() {
		j, err := scanHostDiskJob(rows)
		if err != nil || j.actor != actor {
			rows.Close()
			return nil, errHostDiskRecord
		}
		jobs = append(jobs, j)
		if len(jobs) > diskjob.ActiveJobsMax {
			rows.Close()
			return nil, errHostDiskRecord
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, j := range jobs {
		if hostDiskAudit(ctx, tx, j) != nil {
			return nil, errHostDiskRecord
		}
	}
	return jobs, tx.Commit()
}

// Lost HTTP replies are reconciled by the original submission key using GET.
// No inventory lookup, new intent, or Root dispatch is performed here.
func (s *Store) HostDiskByRequest(ctx context.Context, key, actor string) (HostDiskJob, bool, error) {
	if !ValidID(key) {
		return HostDiskJob{}, false, errHostDiskRecord
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return HostDiskJob{}, false, err
	}
	defer tx.Rollback()
	if _, err := hostDiskAuthority(ctx, tx, actor); err != nil {
		return HostDiskJob{}, false, err
	}
	j, err := scanHostDiskJob(tx.QueryRowContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs WHERE idempotency_key=? AND actor_id=?", key, actor))
	if errors.Is(err, sql.ErrNoRows) {
		return HostDiskJob{}, false, tx.Commit()
	}
	if err != nil || j.actor != actor || hostDiskAudit(ctx, tx, j) != nil {
		return HostDiskJob{}, false, errHostDiskRecord
	}
	return j, true, tx.Commit()
}

func (a *Server) hostDiskState(ctx context.Context, actor string) (diskjob.HostState, error) {
	in, err := a.Store.HostDiskInventoryRequest(ctx, actor)
	if err != nil {
		return diskjob.HostState{}, err
	}
	var state diskjob.HostState
	if err := a.Executor.Call(ctx, "POST", "/v1/disk-host-jobs/inventory", in, &state); err != nil {
		return diskjob.HostState{}, errHostDiskRecord
	}
	if diskjob.ValidateHostState(state) != nil || a.Store.ValidateHostDiskInventory(ctx, in) != nil {
		return diskjob.HostState{}, errHostDiskRecord
	}
	return state, nil
}

func hostDiskSelectionCurrent(state diskjob.HostState, in diskjob.Selection) bool {
	if diskjob.ValidateHostState(state) != nil || !state.Installed || state.AppVersion != in.AppVersion || state.InstallationID != in.InstallationID || state.AppSHA != in.AppSHA || state.Inventory == nil || state.Inventory.Host != (diskjob.Host{BootID: in.BootID, NamespaceID: in.NamespaceID}) {
		return false
	}
	for _, m := range state.Inventory.Mounts.Mounts {
		if m.ID == in.MountID && m.BindingSHA == in.MountSHA && m.Class == "local" && m.Actionable {
			return true
		}
	}
	return false
}

func (a *Server) dispatchHostDisk(ctx context.Context, j HostDiskJob, actor string) (HostDiskJob, bool, error) {
	boundary, only, err := a.Store.HostDiskDispatchBoundary(ctx, j.ID, actor)
	if err != nil {
		return j, false, err
	}
	if only {
		return boundary, boundary.State == "dispatching" || boundary.State == "uncertain" || boundary.State == "cancel_requested", nil
	}
	var ack diskjob.DispatchAck
	if err := a.Executor.Call(ctx, "POST", "/v1/disk-host-jobs/dispatch", boundary.Request, &ack); err != nil || diskjob.ValidateDispatchAck(ack, boundary.Request) != nil {
		// The original committed intent is deliberately retained. No second
		// POST, new ID, native-success claim or implicit retry after lost reply.
		return boundary, true, nil
	}
	current, err := a.Store.HostDiskForActor(ctx, j.ID, actor)
	return current, false, err
}

// A confirmed cancellation that sent no signal may have won the startup race.
// Close only its original admission using the existing current-operator and
// Root lease/scope proof. An unconfirmed cancel reply never enters this path.
func (a *Server) finishHostDiskConfirmedCancel(ctx context.Context, original HostDiskJob, actor string) (signaled, terminal bool, err error) {
	if original.Request.ActorID != actor || original.Request.JobID != original.ID || original.State != "cancel_requested" || original.CancelState != "requested" {
		return false, false, errHostDiskRecord
	}
	current, request, err := a.Store.PrepareHostDiskRecovery(ctx, original.ID, actor)
	if err != nil || current.Request != original.Request {
		return false, false, errHostDiskRecord
	}
	if request == nil {
		return false, hostDiskTerminal(current.State), nil
	}
	var ack diskjob.RecoveryAck
	if err := a.Executor.Call(ctx, "POST", "/v1/disk-host-jobs/recover", request, &ack); err != nil || diskjob.ValidateRecoveryAck(ack, original.Request) != nil {
		return false, false, errHostDiskRecord
	}
	if _, err := a.Store.FinishHostDiskRecovery(ctx, *request, ack); err != nil {
		return false, false, err
	}
	return ack.SignalRequested, ack.Closure != nil, nil
}

func (a *Server) diskHostTaskRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/software/disk-analysis/host/requests/{key}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		j, found, err := a.Store.HostDiskByRequest(r.Context(), r.PathValue("key"), u.ID)
		if err != nil {
			fail(w, 403, "原提交标识或当前完整管理员权限无法核对")
			return
		}
		if !found {
			send(w, 200, map[string]any{"found": false})
			return
		}
		send(w, 200, map[string]any{"found": true, "job": j})
	}))
	m.HandleFunc("GET /api/software/disk-analysis/host", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
		defer cancel()
		if _, err := a.Store.HostDiskInventoryRequest(ctx, u.ID); err != nil {
			fail(w, 403, "全盘清单仅完整管理员可读取")
			return
		}
		state, err := a.hostDiskState(ctx, u.ID)
		if err != nil {
			fail(w, 409, "全盘清单、当前安装或权限暂不能核对；未返回部分清单")
			return
		}
		send(w, 200, state)
	}))
	m.HandleFunc("GET /api/software/disk-analysis/host/jobs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		jobs, err := a.Store.HostDiskJobsForActor(r.Context(), u.ID)
		if err != nil {
			fail(w, 403, "仅原完整管理员可读取全盘任务历史")
			return
		}
		send(w, 200, map[string]any{"jobs": jobs})
	}))
	m.HandleFunc("POST /api/software/disk-analysis/host/jobs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, err := a.Store.HostDiskInventoryRequest(r.Context(), u.ID); err != nil {
			fail(w, 403, "全盘扫描仅完整管理员可提交")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
		in, decodeErr := diskjob.DecodeSelection(raw)
		key := r.Header.Get("Idempotency-Key")
		if err != nil || decodeErr != nil || !ValidID(key) {
			fail(w, 400, "扫描选择或原请求标识无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 24*time.Second)
		defer cancel()
		j, replay, err := a.Store.HostDiskReplay(ctx, in, key, u.ID)
		if err != nil {
			fail(w, 409, "原请求标识或任务主体无法核对；未覆盖")
			return
		}
		if !replay {
			state, err := a.hostDiskState(ctx, u.ID)
			if err != nil || !hostDiskSelectionCurrent(state, in) {
				fail(w, 409, "安装实例或挂载清单已变化，请刷新；未开始扫描")
				return
			}
			j, _, err = a.Store.QueueHostDisk(ctx, in, key, u.ID)
			if err != nil {
				fail(w, 409, err.Error())
				return
			}
		}
		j, uncertain, err := a.dispatchHostDisk(ctx, j, u.ID)
		if err != nil {
			fail(w, 409, "原任务派发授权或状态无法核对；未换ID重发")
			return
		}
		send(w, 202, map[string]any{"job": j, "replayed": replay, "dispatch_uncertain": uncertain, "terminal_verified": false})
	}))
	m.HandleFunc("POST /api/software/disk-analysis/host/jobs/{id}/cancel", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		ctx, cancel := context.WithTimeout(r.Context(), 16*time.Second)
		defer cancel()
		j, err := a.Store.RequestHostDiskCancel(ctx, r.PathValue("id"), u.ID)
		if err != nil {
			fail(w, 403, "仅原完整管理员可取消全盘任务")
			return
		}
		if j.State != "cancel_requested" {
			send(w, 200, map[string]any{"job": j, "native_cancel_requested": false, "terminal_verified": hostDiskTerminal(j.State)})
			return
		}
		var ack diskjob.CancelAck
		err = a.Executor.Call(ctx, "POST", "/v1/disk-host-jobs/cancel", j.Request, &ack)
		uncertain := err != nil || diskjob.ValidateCancelAck(ack, j.Request) != nil
		signaled, terminal := !uncertain && ack.SignalRequested, false
		if !uncertain && !signaled {
			var closeErr error
			signaled, terminal, closeErr = a.finishHostDiskConfirmedCancel(ctx, j, u.ID)
			uncertain = closeErr != nil
		}
		current, err := a.Store.HostDiskForActor(ctx, j.ID, u.ID)
		if err != nil {
			fail(w, 403, "原任务当前读取权限无法核对")
			return
		}
		send(w, 202, map[string]any{"job": current, "cancel_uncertain": uncertain, "native_cancel_requested": !uncertain && signaled, "terminal_verified": !uncertain && terminal})
	}))
}
