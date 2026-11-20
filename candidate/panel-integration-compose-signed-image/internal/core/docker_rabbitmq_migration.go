package core

import (
	"context"
	"encoding/json"
	"errors"
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
	SourceSHA256           string   `json:"source_sha256,omitempty"`
}

// Bind an administrator's approval to the exact original project and
// container restart generation without exposing configuration or credentials.
type RabbitMQMigrationSource struct {
	ProjectID   string
	ContainerID string
	StartedAt   string
	Volume      string
	ConfigSHA   string
	MetadataSHA string
}

func (source RabbitMQMigrationSource) SHA256() string {
	encoded, _ := json.Marshal(source)
	return Hash(string(encoded))
}

type RabbitMQMigrationInput struct {
	SourceSHA256         string `json:"source_sha256"`
	TargetManifestSHA256 string `json:"target_manifest_sha256"`
	DowntimeAcknowledged bool   `json:"downtime_acknowledged"`
}

func DecodeRabbitMQMigrationInput(raw []byte) (RabbitMQMigrationInput, error) {
	var input RabbitMQMigrationInput
	if len(raw) == 0 || len(raw) > 1024 {
		return input, errors.New("RabbitMQ 原预检、签名目标和停机确认必须完整")
	}
	fields := []string{"source_sha256", "target_manifest_sha256", "downtime_acknowledged"}
	if strictLogCleanupObject(raw, fields, &input) != nil ||
		!dockerRequestDigestPattern.MatchString(input.SourceSHA256) ||
		!dockerRequestDigestPattern.MatchString(input.TargetManifestSHA256) || !input.DowntimeAcknowledged {
		return RabbitMQMigrationInput{}, errors.New("RabbitMQ 原预检、签名目标和停机确认必须完整")
	}
	return input, nil
}

func (a *Server) rabbitMQMigrationPreflightRoute(m *http.ServeMux) {
	a.rabbitMQMigrationJobRoutes(m)
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
			report.DisabledStableFeatures == nil || report.AlarmCount < 0 || report.ConnectionCount < 0 ||
			(report.SourceSHA256 != "" && !dockerRequestDigestPattern.MatchString(report.SourceSHA256)) {
			fail(w, http.StatusBadGateway, "无法核对原 RabbitMQ 迁移预检身份")
			return
		}
		send(w, http.StatusOK, report)
	}))
}
