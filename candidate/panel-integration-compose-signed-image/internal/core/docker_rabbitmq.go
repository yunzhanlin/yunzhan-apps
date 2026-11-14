package core

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const RabbitMQQueueLimit = 1024
const RabbitMQVHostLimit = 256

type RabbitMQQueueRow struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	State          string `json:"state"`
	Durable        *bool  `json:"durable"`
	Ready          *int64 `json:"messages_ready"`
	Unacknowledged *int64 `json:"messages_unacknowledged"`
	Consumers      *int64 `json:"consumers"`
}

type RabbitMQQueueReport struct {
	ProjectID  string             `json:"project_id"`
	ObservedAt string             `json:"observed_at"`
	VHosts     []string           `json:"virtual_hosts"`
	VHost      string             `json:"virtual_host"`
	Queues     []RabbitMQQueueRow `json:"queues"`
}

func ValidRabbitMQName(name string) bool {
	return name != "" && len(name) <= 255 && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsControl) < 0
}

func RabbitMQQueueVHost(raw string) (string, error) {
	if raw == "" {
		return "/", nil
	}
	if len(raw) > 1024 {
		return "", errors.New("RabbitMQ 虚拟主机参数无效")
	}
	values, err := url.ParseQuery(raw)
	if err != nil || len(values) != 1 || len(values["vhost"]) != 1 || !ValidRabbitMQName(values.Get("vhost")) {
		return "", errors.New("RabbitMQ 虚拟主机参数无效")
	}
	return values.Get("vhost"), nil
}

func IsPanelRabbitMQImage(value string) bool {
	return value == dockerRabbitMQImage
}

func (a *Server) dockerRabbitMQRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/docker/projects/{id}/rabbitmq-queues", a.authorize(func(w http.ResponseWriter, r *http.Request, _ identity) {
		id := r.PathValue("id")
		vhost, err := RabbitMQQueueVHost(r.URL.RawQuery)
		if !ValidID(id) || err != nil {
			fail(w, http.StatusBadRequest, "RabbitMQ 项目或虚拟主机标识无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var result RabbitMQQueueReport
		route := "/v1/docker/projects/" + id + "/rabbitmq-queues?" + url.Values{"vhost": {vhost}}.Encode()
		if err := a.Executor.Call(ctx, http.MethodGet, route, nil, &result); err != nil {
			fail(w, http.StatusConflict, err.Error())
			return
		}
		if result.ProjectID != id || result.VHost != vhost || result.ObservedAt == "" || result.VHosts == nil || result.Queues == nil {
			fail(w, http.StatusBadGateway, "RabbitMQ 队列报告身份无法核对")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		send(w, http.StatusOK, result)
	}))
}
