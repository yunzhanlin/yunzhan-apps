//go:build linux

package executor

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/upgradeguard"
)

func rabbitMQMigrationUnit(job string, recovery bool) string {
	if recovery {
		return "panel-rabbitmq-reconcile@" + job + ".service"
	}
	return "panel-rabbitmq-migration@" + job + ".service"
}

func (s *Service) rabbitMQMigrationRoutes(m *http.ServeMux) {
	const path = "/v1/rabbitmq-migrations/{job}"
	m.HandleFunc("POST "+path, s.startRabbitMQMigrationRequest)
	m.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
		d, ok := rabbitMQNativeRequestDispatch(w, r)
		if !ok {
			return
		}
		status, err := s.observeRabbitMQNativeJob(r.Context(), d)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, status)
	})
	m.HandleFunc("POST "+path+"/reconcile", func(w http.ResponseWriter, r *http.Request) {
		d, ok := rabbitMQNativeRequestDispatch(w, r)
		if !ok {
			return
		}
		var input struct{}
		if !readJSON(w, r, &input) {
			return
		}
		status, err := s.observeRabbitMQNativeJob(r.Context(), d)
		if err != nil || !status.NeedsRecovery || upgradeguard.Blocked() {
			respond(w, 409, map[string]string{"error": "RabbitMQ 原任务当前无法恢复"})
			return
		}
		if _, err := s.Config.Run(r.Context(), "/usr/bin/systemctl", "start", "--no-block", rabbitMQMigrationUnit(d.JobID, true)); err != nil {
			respond(w, 409, map[string]string{"error": "RabbitMQ 原任务恢复请求尚未确认"})
			return
		}
		status.NeedsRecovery = false
		respond(w, 202, status)
	})
}

func rabbitMQNativeRequestDispatch(w http.ResponseWriter, r *http.Request) (core.RabbitMQMigrationDispatch, bool) {
	w.Header().Set("Cache-Control", "no-store")
	id := r.PathValue("job")
	if !core.ValidID(id) || r.URL.RawQuery != "" {
		respond(w, 400, map[string]string{"error": "RabbitMQ 原任务标识无效"})
		return core.RabbitMQMigrationDispatch{}, false
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		respond(w, 503, map[string]string{"error": "无法核对 RabbitMQ 原迁移记录"})
		return core.RabbitMQMigrationDispatch{}, false
	}
	defer reader.db.Close()
	d, err := (&core.Store{DB: reader.db}).ReadRabbitMQMigrationDispatch(r.Context(), id)
	if err != nil || !reader.current() {
		respond(w, 404, map[string]string{"error": "无法核对 RabbitMQ 原迁移记录"})
		return core.RabbitMQMigrationDispatch{}, false
	}
	return d, true
}

func (s *Service) startRabbitMQMigrationRequest(w http.ResponseWriter, r *http.Request) {
	dispatch, ok := rabbitMQNativeRequestDispatch(w, r)
	if !ok {
		return
	}
	var submitted core.RabbitMQMigrationDispatch
	if !readJSON(w, r, &submitted) {
		return
	}
	if submitted != dispatch || upgradeguard.Blocked() {
		respond(w, 409, map[string]string{"error": "RabbitMQ 原迁移提交与已保存授权不符"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	reader, err := openDiskHostCoreReader()
	if err != nil {
		respond(w, 409, map[string]string{"error": "RabbitMQ 原迁移授权不可验证"})
		return
	}
	defer reader.db.Close()
	if err := verifyRabbitMQOriginalDispatch(ctx, reader, dispatch); err != nil {
		respond(w, 403, map[string]string{"error": "RabbitMQ 原迁移授权已变化"})
		return
	}
	if err := claimRabbitMQDispatch(ctx, dispatch); err != nil {
		respond(w, 409, map[string]string{"error": "RabbitMQ 原迁移已提交或执行器状态无法核对"})
		return
	}
	if _, err := s.Config.Run(ctx, "/usr/bin/systemctl", "start", "--no-block", rabbitMQMigrationUnit(dispatch.JobID, false)); err != nil {
		respond(w, 409, map[string]string{"error": "RabbitMQ 原迁移已保留，执行状态待核对"})
		return
	}
	respond(w, 202, core.RabbitMQMigrationStatus{
		JobID: dispatch.JobID, RequestID: dispatch.RequestID, ProjectID: dispatch.ProjectID, Phase: "submitted",
	})
}

func claimRabbitMQDispatch(ctx context.Context, dispatch core.RabbitMQMigrationDispatch) error {
	lease, err := productionDockerMutationStore().begin(ctx)
	if err != nil {
		return err
	}
	defer lease.Close()
	return lease.use(ctx, func(bound context.Context) error {
		anchor := lease.tree.roots[len(lease.tree.roots)-1]
		return writeRabbitMQMigrationRecord(anchor, dispatch.JobID+".rabbitmq-dispatched", []byte(dispatch.RequestID))
	})
}

func checkRabbitMQDispatchClaim(lease *dockerMutationLease, dispatch core.RabbitMQMigrationDispatch) error {
	anchor := lease.tree.roots[len(lease.tree.roots)-1]
	if _, err := anchor.Lstat(dispatch.JobID + ".rabbitmq-cancelled"); !errors.Is(err, os.ErrNotExist) {
		return errRabbitMQMigrationPending
	}
	raw, err := geoStoreRead(anchor, dispatch.JobID+".rabbitmq-dispatched", 32)
	if err != nil || string(raw) != dispatch.RequestID {
		return errRabbitMQMigrationPending
	}
	return nil
}

func (s *Service) observeRabbitMQNativeJob(ctx context.Context, d core.RabbitMQMigrationDispatch) (core.RabbitMQMigrationStatus, error) {
	status := core.RabbitMQMigrationStatus{
		JobID: d.JobID, RequestID: d.RequestID, ProjectID: d.ProjectID, Phase: "submitted",
	}
	journal, plan, state, err := productionRabbitMQMigrationStore().read(d.JobID)
	if errors.Is(err, os.ErrNotExist) {
		closed, readErr := rabbitMQMigrationCancelled(d)
		if readErr != nil {
			return status, readErr
		}
		if closed {
			status.Phase = "cancelled-before-stop"
			return status, nil
		}
		// A lost systemd reply leaves its original reservation. The recovery
		// worker can atomically close a job that never reached a durable plan.
		submitted, _ := time.Parse(time.RFC3339, d.SubmittedAt)
		if time.Since(submitted) > 20*time.Second {
			status.NeedsRecovery, readErr = s.rabbitMQMigrationUnitsIdle(ctx, d.JobID)
		}
		return status, readErr
	}
	if err != nil {
		return status, err
	}
	defer journal.Close()
	if plan.RequestID != d.RequestID || plan.ActorID != d.ActorID || plan.ProjectID != d.ProjectID ||
		plan.TargetManifestSHA != d.Input.TargetManifestSHA256 || plan.SourceSHA != d.Input.SourceSHA256 {
		return status, errRabbitMQIdentity
	}
	status.Phase = state.Phase
	if rabbitMQMigrationMayChangeDocker(state.Phase) || state.Phase == "prepared" {
		status.NeedsRecovery, err = s.rabbitMQMigrationUnitsIdle(ctx, d.JobID)
	}
	return status, err
}

func (s *Service) rabbitMQMigrationUnitsIdle(ctx context.Context, job string) (bool, error) {
	for _, recovery := range []bool{false, true} {
		out, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "--property=ActiveState", "--value", rabbitMQMigrationUnit(job, recovery))
		if err != nil {
			return false, errRabbitMQMigrationPending
		}
		switch strings.TrimSpace(out) {
		case "active", "activating", "deactivating", "reloading":
			return false, nil
		case "failed", "inactive":
		default:
			return false, errRabbitMQMigrationPending
		}
	}
	return true, nil
}

func rabbitMQMigrationCancelled(d core.RabbitMQMigrationDispatch) (bool, error) {
	tree, err := openDockerMutationTree(productionDockerMutationStore().state)
	if err != nil {
		return false, err
	}
	defer tree.close()
	file := d.JobID + ".rabbitmq-cancelled"
	raw, err := geoStoreRead(tree.roots[len(tree.roots)-1], file, 32)
	if errors.Is(err, os.ErrNotExist) && tree.current() {
		return false, nil
	}
	if err != nil || !tree.current() || string(raw) != d.RequestID {
		return false, errRabbitMQMigrationPending
	}
	return true, nil
}
