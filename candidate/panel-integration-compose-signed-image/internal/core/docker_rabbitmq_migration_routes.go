package core

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"time"
)

type RabbitMQMigrationStatus struct {
	JobID         string `json:"job_id"`
	RequestID     string `json:"request_id"`
	ProjectID     string `json:"project_id"`
	Phase         string `json:"phase"`
	NeedsRecovery bool   `json:"needs_recovery,omitempty"`
}

func (s RabbitMQMigrationStatus) matches(d RabbitMQMigrationDispatch) bool {
	if s.JobID != d.JobID || s.RequestID != d.RequestID || s.ProjectID != d.ProjectID {
		return false
	}
	switch s.Phase {
	case "submitted", "prepared", "quiesce-intent", "resume-listeners-intent", "stop-original-intent",
		"original-stopped", "copy-intent", "copy-verified", "bridge-intent", "bridge-stopped",
		"target-check-intent", "target-verified-offline", "restore-original-intent", "restart-original-intent",
		"publish-endpoint-intent", "target-published", "original-restored", "cancelled-before-stop":
		return true
	}
	return false
}

func (a *Server) rabbitMQMigrationJobRoutes(m *http.ServeMux) {
	const route = "/api/docker/projects/{id}/rabbitmq-migrations"
	m.HandleFunc("GET "+route, a.authorize(a.latestRabbitMQMigration))
	m.HandleFunc("POST "+route, a.authorize(a.submitRabbitMQMigration))
	m.HandleFunc("GET "+route+"/{request}", a.authorize(a.observeRabbitMQMigration))
	m.HandleFunc("POST "+route+"/{request}/reconcile", a.authorize(a.reconcileRabbitMQMigration))
}

func (a *Server) submitRabbitMQMigration(w http.ResponseWriter, r *http.Request, actor identity) {
	w.Header().Set("Cache-Control", "no-store")
	project, request := r.PathValue("id"), r.Header.Get("Idempotency-Key")
	if !ValidID(project) || !ValidID(request) || len(r.Header.Values("Idempotency-Key")) != 1 || r.URL.RawQuery != "" {
		fail(w, 400, "RabbitMQ 原项目或幂等编号无效")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	input, decodeErr := DecodeRabbitMQMigrationInput(raw)
	if err != nil || decodeErr != nil {
		fail(w, 400, "RabbitMQ 迁移需要有效预检、签名包和明确停机确认")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	if _, err := rabbitMQMigrationAdministrator(ctx, a.Store.DB, actor.ID, 0); err != nil {
		fail(w, 403, "RabbitMQ 迁移需要当前完整管理员")
		return
	}
	prior, priorState, found, err := rabbitMQMigrationRequest(ctx, a.Store.DB, request)
	if err != nil || found && (prior.ActorID != actor.ID || prior.ProjectID != project || prior.Input != input) {
		fail(w, 409, "RabbitMQ 原请求身份或内容不符")
		return
	}
	if found {
		send(w, 202, RabbitMQMigrationStatus{JobID: prior.JobID, RequestID: request, ProjectID: project, Phase: priorState})
		return
	}
	if a.Executor == nil || a.AppCatalog == nil {
		fail(w, 503, "RabbitMQ 迁移服务暂不可用")
		return
	}
	manifest, err := a.AppCatalog.FetchRabbitMQMigrationManifest(ctx, rabbitMQ440AppVersion, input.TargetManifestSHA256)
	if err != nil || manifest.Delivery.Target != RabbitMQ440Template || validateRegistryComposeDelivery(manifest) != nil ||
		appCompatible(manifest) != nil {
		fail(w, 409, "RabbitMQ 目标未通过已签名目录和本机兼容性核对")
		return
	}
	var report RabbitMQMigrationPreflight
	preflight := "/v1/docker/projects/" + project + "/rabbitmq-migration-preflight"
	if a.Executor.Call(ctx, http.MethodGet, preflight, nil, &report) != nil ||
		report.ProjectID != project || report.SourceSHA256 != input.SourceSHA256 || report.BrokerVersion != "4.1.4" ||
		report.Node != RabbitMQNodeName || report.DataVolume != "panel_"+project[:12]+"_data" ||
		report.AlarmCount != 0 || report.ConnectionCount != 0 || report.DisabledStableFeatures == nil ||
		len(report.DisabledStableFeatures) != 0 {
		fail(w, 409, "原 RabbitMQ 实例变化或有未完成的迁移预检，请重新核对")
		return
	}
	d, fresh, err := a.Store.reserveRabbitMQMigration(ctx, actor.ID, project, request, input)
	if err != nil {
		fail(w, 409, "原 RabbitMQ 项目已有迁移任务或当前权限发生变化")
		return
	}
	status := RabbitMQMigrationStatus{JobID: d.JobID, RequestID: request, ProjectID: project, Phase: "submitted"}
	if fresh {
		// A lost reply keeps the original reservation. A duplicate browser
		// POST observes it without sending another native start.
		endpoint := "/v1/rabbitmq-migrations/" + d.JobID
		var observed RabbitMQMigrationStatus
		if a.Executor.Call(ctx, http.MethodPost, endpoint, d, &observed) == nil && observed.matches(d) {
			status = observed
		}
	}
	send(w, 202, status)
}

func (a *Server) rabbitMQMigrationRequestForActor(w http.ResponseWriter, r *http.Request,
	actor identity) (RabbitMQMigrationDispatch, string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	request, project := r.PathValue("request"), r.PathValue("id")
	if !ValidID(request) || !ValidID(project) || r.URL.RawQuery != "" {
		fail(w, 400, "RabbitMQ 原项目或作业标识无效")
		return RabbitMQMigrationDispatch{}, "", false
	}
	if _, err := rabbitMQMigrationAdministrator(r.Context(), a.Store.DB, actor.ID, 0); err != nil {
		fail(w, 403, "RabbitMQ 迁移需要当前完整管理员")
		return RabbitMQMigrationDispatch{}, "", false
	}
	d, state, found, err := rabbitMQMigrationRequest(r.Context(), a.Store.DB, request)
	if err != nil || !found || d.ProjectID != project {
		fail(w, 404, "无法核对指定的 RabbitMQ 原迁移")
		return RabbitMQMigrationDispatch{}, "", false
	}
	return d, state, true
}

func (a *Server) observeRabbitMQMigration(w http.ResponseWriter, r *http.Request, actor identity) {
	d, state, ok := a.rabbitMQMigrationRequestForActor(w, r, actor)
	if !ok {
		return
	}
	status := RabbitMQMigrationStatus{JobID: d.JobID, RequestID: d.RequestID, ProjectID: d.ProjectID, Phase: state}
	if state == "submitted" && a.Executor != nil {
		var observed RabbitMQMigrationStatus
		ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
		defer cancel()
		if a.Executor.Call(ctx, http.MethodGet, "/v1/rabbitmq-migrations/"+d.JobID, nil, &observed) == nil && observed.matches(d) {
			if a.Store.finishRabbitMQMigration(ctx, d, observed) != nil {
				fail(w, 409, "原 RabbitMQ 迁移回执尚未完成记录")
				return
			}
			status = observed
		}
	}
	send(w, 200, status)
}

func (a *Server) reconcileRabbitMQMigration(w http.ResponseWriter, r *http.Request, actor identity) {
	d, state, ok := a.rabbitMQMigrationRequestForActor(w, r, actor)
	if !ok {
		return
	}
	if state != "submitted" || a.Executor == nil {
		fail(w, 409, "原 RabbitMQ 迁移已结束或执行器不可用")
		return
	}
	var observed RabbitMQMigrationStatus
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	if a.Executor.Call(ctx, http.MethodPost, "/v1/rabbitmq-migrations/"+d.JobID+"/reconcile", struct{}{}, &observed) != nil ||
		!observed.matches(d) {
		fail(w, 409, "原迁移恢复尚未启动，稍后查询同一原请求")
		return
	}
	send(w, 202, observed)
}

func (a *Server) latestRabbitMQMigration(w http.ResponseWriter, r *http.Request, actor identity) {
	w.Header().Set("Cache-Control", "no-store")
	project := r.PathValue("id")
	if !ValidID(project) || r.URL.RawQuery != "" {
		fail(w, 400, "RabbitMQ 原项目标识无效")
		return
	}
	if _, err := rabbitMQMigrationAdministrator(r.Context(), a.Store.DB, actor.ID, 0); err != nil {
		fail(w, 403, "RabbitMQ 迁移需要当前完整管理员")
		return
	}
	var request string
	err := a.Store.DB.QueryRowContext(r.Context(), "SELECT request_id FROM rabbitmq_migration_requests WHERE project_id=? AND state='submitted'", project).Scan(&request)
	if errors.Is(err, sql.ErrNoRows) {
		send(w, 200, map[string]any{"request_id": ""})
		return
	}
	if err != nil || !ValidID(request) {
		fail(w, 409, "无法核对原 RabbitMQ 项目迁移任务")
		return
	}
	r.SetPathValue("request", request)
	a.observeRabbitMQMigration(w, r, actor)
}
