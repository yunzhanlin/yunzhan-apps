package core

import (
	"context"
	"net/http"
	"time"
)

const RabbitMQNodeName = "rabbit@cloudstack-rabbitmq"

type RabbitMQMigrationPreflight struct {
	ProjectID              string   `json:"project_id"`
	ObservedAt             string   `json:"observed_at"`
	BrokerVersion          string   `json:"broker_version"`
	Node                   string   `json:"node"`
	DataVolume             string   `json:"data_volume"`
	DisabledStableFeatures []string `json:"disabled_stable_features"`
	AlarmCount             int      `json:"alarm_count"`
	ConnectionCount        int      `json:"connection_count"`
}

func (a *Server) rabbitMQMigrationPreflightRoute(m *http.ServeMux) {
	m.HandleFunc("GET /api/docker/projects/{id}/rabbitmq-migration-preflight", a.authorize(func(w http.ResponseWriter, r *http.Request, _ identity) {
		id := r.PathValue("id")
		w.Header().Set("Cache-Control", "no-store")
		if !ValidID(id) || r.URL.RawQuery != "" {
			fail(w, http.StatusBadRequest, "RabbitMQ 迁移预检项目标识无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 38*time.Second)
		defer cancel()
		var report RabbitMQMigrationPreflight
		if err := a.Executor.Call(ctx, http.MethodGet, "/v1/docker/projects/"+id+"/rabbitmq-migration-preflight", nil, &report); err != nil {
			fail(w, http.StatusConflict, err.Error())
			return
		}
		if report.ProjectID != id || report.BrokerVersion != "4.1.4" || report.Node != RabbitMQNodeName ||
			report.DataVolume != "panel_"+id[:12]+"_data" || report.ObservedAt == "" ||
			report.DisabledStableFeatures == nil || report.AlarmCount < 0 || report.ConnectionCount < 0 {
			fail(w, http.StatusBadGateway, "无法核对原 RabbitMQ 迁移预检身份")
			return
		}
		send(w, http.StatusOK, report)
	}))
}
