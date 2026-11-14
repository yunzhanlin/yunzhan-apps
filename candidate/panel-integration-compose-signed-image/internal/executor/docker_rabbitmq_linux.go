//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os/exec"
	"slices"
	"strings"
	"time"

	"local/panel/internal/core"
)

var rabbitMQReadSlots = make(chan struct{}, 3)
var errRabbitMQIdentity = errors.New("无法唯一核对该项目的原 RabbitMQ 容器，请检查项目运行状态")

type rabbitMQContainer struct {
	ID     string `json:"Id"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status    string `json:"Status"`
		PID       int    `json:"Pid"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
}

func rabbitMQProject(raw []byte, id string) (composeMetadata, error) {
	var value composeMetadata
	if !core.ValidID(id) || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &value) != nil || value.ID != id ||
		value.Engine != "panel_"+id[:12] || value.TemplateID != "rabbitmq" || value.Services != 1 ||
		!dockerResourceNamePattern.MatchString(value.Name) {
		return value, errRabbitMQIdentity
	}
	return value, nil
}

func inspectRabbitMQ(ctx context.Context, project composeMetadata) (rabbitMQContainer, error) {
	var result rabbitMQContainer
	filters, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + project.Engine}})
	var rows []struct {
		ID string `json:"Id"`
	}
	if _, err := dockerRequest(ctx, http.MethodGet, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), nil, &rows, 256<<10); err != nil ||
		len(rows) != 1 || !core.ValidDockerContainerID(rows[0].ID) {
		return result, errRabbitMQIdentity
	}
	id := rows[0].ID
	raw, err := dockerRequest(ctx, http.MethodGet, "/containers/"+id+"/json", nil, nil, 256<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &result) != nil ||
		result.ID != id || result.Config.Labels["com.docker.compose.project"] != project.Engine ||
		result.Config.Labels["com.docker.compose.service"] != "rabbitmq" ||
		!strings.EqualFold(result.Config.Labels["com.docker.compose.oneoff"], "false") ||
		!core.IsPanelRabbitMQImage(result.Config.Image) || result.State.Status != "running" || result.State.PID < 1 {
		return result, errRabbitMQIdentity
	}
	if _, err := time.Parse(time.RFC3339Nano, result.State.StartedAt); err != nil {
		return result, errRabbitMQIdentity
	}
	return result, nil
}

func rabbitMQRead(ctx context.Context, id string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()
	// The selected name is a single positional argument. No shell, published
	// port, network password, CLI node override or client-defined command.
	cmd := exec.CommandContext(ctx, "/usr/bin/docker", append(
		[]string{"--host", "unix:///run/docker.sock", "exec", "--user", "rabbitmq", "--env", "HOME=/var/lib/rabbitmq", id,
			"rabbitmqctl", "--quiet", "--timeout", "6", "--formatter", "json"}, args...)...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	out, stderr := &boundedBuffer{max: 256 << 10}, &boundedBuffer{max: 2048}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = out, stderr, time.Second
	if !core.ValidDockerContainerID(id) {
		return nil, errRabbitMQIdentity
	}
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		return nil, errors.New("RabbitMQ 未能返回队列数据，请核对服务状态后重试")
	}
	if out.truncated {
		return nil, errors.New("RabbitMQ 查询超出报告容量，无法提供完整结果")
	}
	return out.Bytes(), nil
}

func rabbitMQVHosts(raw []byte) ([]string, error) {
	var rows []struct {
		Name string `json:"name"`
	}
	if memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &rows) != nil || len(rows) == 0 || len(rows) > core.RabbitMQVHostLimit {
		return nil, errors.New("无法读取完整的 RabbitMQ 虚拟主机清单")
	}
	names := make([]string, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if !core.ValidRabbitMQName(row.Name) || seen[row.Name] {
			return nil, errors.New("RabbitMQ 虚拟主机清单包含无效或重复名称")
		}
		seen[row.Name] = true
		names = append(names, row.Name)
	}
	slices.Sort(names)
	return names, nil
}

func rabbitMQQueues(raw []byte) ([]core.RabbitMQQueueRow, error) {
	var rows []core.RabbitMQQueueRow
	if memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &rows) != nil || rows == nil || len(rows) > core.RabbitMQQueueLimit {
		return nil, errors.New("无法读取完整的 RabbitMQ 队列清单")
	}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if !core.ValidRabbitMQName(row.Name) || seen[row.Name] || !core.ValidRabbitMQName(row.Type) ||
			!core.ValidRabbitMQName(row.State) || row.Durable == nil ||
			row.Ready != nil && *row.Ready < 0 || row.Unacknowledged != nil && *row.Unacknowledged < 0 ||
			row.Consumers != nil && *row.Consumers < 0 {
			return nil, errors.New("RabbitMQ 队列报告包含无效字段")
		}
		seen[row.Name] = true
	}
	slices.SortFunc(rows, func(a, b core.RabbitMQQueueRow) int { return strings.Compare(a.Name, b.Name) })
	return rows, nil
}

func readRabbitMQQueueReport(ctx context.Context, id, vhost string) (core.RabbitMQQueueReport, error) {
	var report core.RabbitMQQueueReport
	select {
	case rabbitMQReadSlots <- struct{}{}:
		defer func() { <-rabbitMQReadSlots }()
	default:
		return report, errors.New("RabbitMQ 队列读取繁忙，请稍后刷新")
	}
	dir, err := openComposeUpdateDirectory(dockerProjects, id)
	if err != nil {
		return report, errRabbitMQIdentity
	}
	defer dir.Close()
	raw, info, err := dir.read("metadata.json", 16<<10)
	if err != nil {
		return report, errRabbitMQIdentity
	}
	project, err := rabbitMQProject(raw, id)
	if err != nil {
		return report, err
	}
	before, err := inspectRabbitMQ(ctx, project)
	if err != nil {
		return report, err
	}
	hosts, err := rabbitMQRead(ctx, before.ID, "list_vhosts", "name")
	if err != nil {
		return report, err
	}
	names, err := rabbitMQVHosts(hosts)
	if err != nil {
		return report, err
	}
	report.VHosts, report.VHost, report.Queues = names, vhost, []core.RabbitMQQueueRow{}
	if slices.Contains(names, vhost) {
		output, err := rabbitMQRead(ctx, before.ID, "list_queues", "--vhost="+vhost, "name", "type",
			"state", "durable", "messages_ready", "messages_unacknowledged", "consumers")
		if err != nil {
			return report, err
		}
		report.Queues, err = rabbitMQQueues(output)
		if err != nil {
			return report, err
		}
	}
	after, err := inspectRabbitMQ(ctx, project)
	current, currentInfo, fileErr := dir.read("metadata.json", 16<<10)
	if err != nil || fileErr != nil || before.ID != after.ID || before.State != after.State ||
		!sameComposeUpdateFile(info, currentInfo) || !bytes.Equal(raw, current) {
		return report, errors.New("读取期间 RabbitMQ 项目已变化，请重新刷新")
	}
	report.ProjectID, report.ObservedAt = id, core.Now()
	return report, nil
}

func dockerRabbitMQRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/docker/projects/{id}/rabbitmq-queues", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		vhost, err := core.RabbitMQQueueVHost(r.URL.RawQuery)
		if !core.ValidID(id) || err != nil {
			respond(w, 400, map[string]string{"error": "RabbitMQ 项目或虚拟主机标识无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 23*time.Second)
		defer cancel()
		report, err := readRabbitMQQueueReport(ctx, id, vhost)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		respond(w, 200, report)
	})
}
