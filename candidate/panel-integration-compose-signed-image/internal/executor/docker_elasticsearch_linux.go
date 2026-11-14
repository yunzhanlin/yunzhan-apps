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
	"strconv"
	"strings"
	"time"

	"local/panel/internal/core"
)

var errElasticsearchProject = errors.New("无法核对原 Elasticsearch 快照项目、容器和卷")

type elasticsearchSnapshotContainer struct {
	ID     string                `json:"Id"`
	Mounts []rabbitMQVolumeMount `json:"Mounts"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Privileged  bool   `json:"Privileged"`
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	State struct {
		Status    string `json:"Status"`
		PID       int    `json:"Pid"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
}

func inspectElasticsearchSnapshotContainer(ctx context.Context, p composeMetadata, image string) (elasticsearchSnapshotContainer, error) {
	var out elasticsearchSnapshotContainer
	filters, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + p.Engine}})
	var matches []struct {
		ID string `json:"Id"`
	}
	if _, e := dockerRequest(ctx, http.MethodGet, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), nil, &matches, 256<<10); e != nil ||
		len(matches) != 1 || !core.ValidDockerContainerID(matches[0].ID) {
		return out, errElasticsearchProject
	}
	id := matches[0].ID
	raw, err := dockerRequest(ctx, http.MethodGet, "/containers/"+id+"/json", nil, nil, 256<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &out) != nil ||
		out.ID != id || out.Config.Image != image || out.Config.Labels["com.docker.compose.project"] != p.Engine ||
		out.Config.Labels["com.docker.compose.service"] != core.ElasticsearchLegacyTemplate ||
		!strings.EqualFold(out.Config.Labels["com.docker.compose.oneoff"], "false") ||
		out.HostConfig.Privileged || out.HostConfig.NetworkMode != p.Engine+"_default" ||
		out.State.Status != "running" || out.State.PID < 1 {
		return out, errElasticsearchProject
	}
	if _, err = time.Parse(time.RFC3339Nano, out.State.StartedAt); err != nil {
		return out, errElasticsearchProject
	}
	expected := map[string]string{"/usr/share/elasticsearch/data": p.Engine + "_data",
		"/usr/share/elasticsearch/logs": p.Engine + "_snapshots"}
	if len(out.Mounts) != len(expected) {
		return out, errElasticsearchProject
	}
	for _, mount := range out.Mounts {
		if mount.Name == "" || expected[mount.Destination] != mount.Name || mount.Type != "volume" || mount.Driver != "local" || !mount.RW {
			return out, errElasticsearchProject
		}
		delete(expected, mount.Destination)
	}
	return out, nil
}

type elasticsearchSnapshotHTTP struct{ id, password string }

func (c elasticsearchSnapshotHTTP) call(ctx context.Context, method, path string, in, out any) (int, error) {
	var config strings.Builder
	config.WriteString("user = " + strconv.Quote("elastic:"+c.password) + "\n")
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		config.WriteString("header = \"Content-Type: application/json\"\ndata-binary = " + strconv.Quote(string(b)) + "\n")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/docker", "--host", "unix:///run/docker.sock", "exec", "-i", c.id,
		"/usr/bin/curl", "--disable", "--config", "-", "--silent", "--show-error", "--noproxy", "*",
		"--connect-timeout", "3", "--max-time", "6", "--max-filesize", "262144", "--request", method,
		"--write-out", "\n%{http_code}", "http://127.0.0.1:9200"+path)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.Stdin = strings.NewReader(config.String())
	stdout, stderr := &boundedBuffer{max: 264 << 10}, &boundedBuffer{max: 1024}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = stdout, stderr, time.Second
	if err := cmd.Run(); err != nil || ctx.Err() != nil || stdout.truncated {
		return 0, errors.New("无法核对 Elasticsearch 原请求状态")
	}
	// Elasticsearch JSON may include newlines. The last line is curl's status.
	all := stdout.String()
	last := strings.LastIndexByte(all, '\n')
	if last < 0 {
		return 0, errors.New("Elasticsearch 返回的请求状态无效")
	}
	b, code := all[:last], all[last+1:]
	status, err := strconv.Atoi(code)
	if err != nil || status < 200 || status > 599 {
		return 0, errors.New("Elasticsearch 返回的请求状态无效")
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return status, errors.New("Elasticsearch 拒绝当前管理员凭据")
	}
	if (status == http.StatusOK || status == http.StatusAccepted) && out != nil && (memcachedDaemonJSON([]byte(b)) != nil || json.Unmarshal([]byte(b), out) != nil) {
		return status, errors.New("Elasticsearch 返回的快照数据无效")
	}
	return status, nil
}

const elasticSnapshotRepoAPI = "/_snapshot/" + core.ElasticsearchSnapshotRepository

func (c elasticsearchSnapshotHTTP) verifyRepository(ctx context.Context, create bool) error {
	type settings struct {
		Location string `json:"location"`
		ReadOnly string `json:"readonly"`
	}
	var response map[string]struct {
		Type     string   `json:"type"`
		Settings settings `json:"settings"`
	}
	status, err := c.call(ctx, http.MethodGet, elasticSnapshotRepoAPI, nil, &response)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound && create {
		var ack struct {
			Acknowledged bool `json:"acknowledged"`
		}
		status, err = c.call(ctx, http.MethodPut, elasticSnapshotRepoAPI+"?verify=true",
			map[string]any{"type": "fs", "settings": map[string]any{"location": core.ElasticsearchSnapshotRepositoryPath}}, &ack)
		if err != nil || status != http.StatusOK || !ack.Acknowledged {
			return errors.New("Elasticsearch 未确认独立快照仓库")
		}
		return nil
	}
	repo, ok := response[core.ElasticsearchSnapshotRepository]
	if status != http.StatusOK || !ok || len(response) != 1 || repo.Type != "fs" ||
		repo.Settings.Location != core.ElasticsearchSnapshotRepositoryPath ||
		(repo.Settings.ReadOnly != "" && repo.Settings.ReadOnly != "false") {
		return errors.New("Elasticsearch 快照仓库位置或写入状态与项目不符")
	}
	return nil
}

func (c elasticsearchSnapshotHTTP) indexExists(ctx context.Context, index string) (bool, error) {
	var out struct {
		Indices []struct {
			Name string `json:"name"`
		} `json:"indices"`
		Aliases     []json.RawMessage `json:"aliases"`
		DataStreams []json.RawMessage `json:"data_streams"`
	}
	status, err := c.call(ctx, http.MethodGet, "/_resolve/index/"+index+"?expand_wildcards=all", nil, &out)
	if err != nil {
		return false, err
	}
	if status == http.StatusNotFound {
		return false, nil
	}
	if status != http.StatusOK || out.Indices == nil || out.Aliases == nil || out.DataStreams == nil || len(out.Indices) > 1 {
		return false, errors.New("无法核对 Elasticsearch 索引身份")
	}
	if len(out.Aliases) > 0 || len(out.DataStreams) > 0 || len(out.Indices) == 1 && out.Indices[0].Name != index {
		return false, errors.New("只支持单个具体索引，不能使用别名或数据流")
	}
	return len(out.Indices) == 1, nil
}

type elasticsearchIndexSnapshots struct {
	Snapshots []struct {
		Snapshot string   `json:"snapshot"`
		State    string   `json:"state"`
		Indices  []string `json:"indices"`
	} `json:"snapshots"`
}

func (c elasticsearchSnapshotHTTP) submit(ctx context.Context, in core.ElasticsearchSnapshotRequest, restore bool) error {
	if err := c.verifyRepository(ctx, !restore); err != nil {
		return err
	}
	route := elasticSnapshotRepoAPI + "/" + in.Snapshot
	var found elasticsearchIndexSnapshots
	status, err := c.call(ctx, http.MethodGet, route+"?verbose=true", nil, &found)
	if err != nil {
		return err
	}
	request := map[string]any{"indices": in.Index, "ignore_unavailable": false, "include_global_state": false, "feature_states": []string{"none"}}
	method := http.MethodPut
	if restore {
		if status != http.StatusOK || len(found.Snapshots) != 1 || found.Snapshots[0].Snapshot != in.Snapshot ||
			found.Snapshots[0].State != "SUCCESS" || len(found.Snapshots[0].Indices) != 1 || found.Snapshots[0].Indices[0] != in.Index {
			return errors.New("仅可恢复所选索引的完整快照")
		}
		exists, err := c.indexExists(ctx, in.RestoreIndex)
		if err != nil {
			return err
		}
		if exists {
			return errors.New("恢复目标已存在，请使用新的索引名称")
		}
		request["rename_pattern"] = "^" + in.Index + "$"
		request["rename_replacement"] = in.RestoreIndex
		request["include_aliases"] = false
		request["partial"] = false
		method = http.MethodPost
		route += "/_restore"
	} else {
		if status != http.StatusNotFound {
			return errors.New("同名快照已存在或其状态无法确认，请核对原快照")
		}
		exists, err := c.indexExists(ctx, in.Index)
		if err != nil {
			return err
		}
		if !exists {
			return errors.New("所选 Elasticsearch 索引不存在")
		}
		request["partial"] = false
	}
	var result struct {
		Accepted bool `json:"accepted"`
	}
	status, err = c.call(ctx, method, route+"?wait_for_completion=false", request, &result)
	if err != nil || status != http.StatusOK && status != http.StatusAccepted || !result.Accepted {
		return errors.New("Elasticsearch 快照请求未确认，请核对原快照或恢复目标")
	}
	return nil
}

func (c elasticsearchSnapshotHTTP) observation(ctx context.Context, in core.ElasticsearchSnapshotRequest) (string, error) {
	if err := c.verifyRepository(ctx, false); err != nil {
		return "", err
	}
	var snapshots elasticsearchIndexSnapshots
	status, err := c.call(ctx, http.MethodGet, elasticSnapshotRepoAPI+"/"+in.Snapshot+"?verbose=true", nil, &snapshots)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "missing", nil
	}
	if status != http.StatusOK || len(snapshots.Snapshots) != 1 || snapshots.Snapshots[0].Snapshot != in.Snapshot {
		return "", errors.New("无法核对原 Elasticsearch 快照")
	}
	snapshot := snapshots.Snapshots[0]
	if len(snapshot.Indices) != 1 || snapshot.Indices[0] != in.Index {
		return "", errors.New("快照与所选源索引不一致")
	}
	switch snapshot.State {
	case "IN_PROGRESS", "STARTED", "INIT":
		return "running", nil
	case "FAILED", "PARTIAL", "INCOMPATIBLE":
		return "failed", nil
	case "SUCCESS":
		if in.RestoreIndex == "" {
			return "complete", nil
		}
	default:
		return "", errors.New("无法识别 Elasticsearch 快照状态")
	}
	// A restored index can exist while its primaries are still initializing.
	// Report its observed health; do not infer that a specific request created it.
	var health struct {
		Status  string                     `json:"status"`
		Indices map[string]json.RawMessage `json:"indices"`
	}
	status, err = c.call(ctx, http.MethodGet, "/_cluster/health/"+in.RestoreIndex+"?level=indices&timeout=4s", nil, &health)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "missing", nil
	}
	if status != http.StatusOK || len(health.Indices) > 1 {
		return "", errors.New("无法核对目标索引健康状态")
	}
	if _, ok := health.Indices[in.RestoreIndex]; !ok {
		return "missing", nil
	}
	if health.Status == "green" || health.Status == "yellow" {
		return "complete", nil
	}
	if health.Status == "red" {
		return "running", nil
	}
	return "", errors.New("无法识别目标索引健康状态")
}

func runElasticsearchSnapshotOperation(ctx context.Context, id string, in core.ElasticsearchSnapshotRequest, action string) (string, error) {
	ctx, unlock, err := composeLock(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()
	dir, err := openComposeUpdateDirectory(dockerProjects, id)
	if err != nil {
		return "", errElasticsearchProject
	}
	defer dir.Close()
	metadata, metadataInfo, err := dir.read("metadata.json", 16<<10)
	var p composeMetadata
	if err != nil || memcachedDaemonJSON(metadata) != nil || json.Unmarshal(metadata, &p) != nil || p.ID != id ||
		p.Engine != "panel_"+id[:12] || p.TemplateID != core.ElasticsearchSnapshotTemplate || p.Services != 1 {
		return "", errElasticsearchProject
	}
	data, info, err := dir.read("compose.yaml", 32<<10)
	if err != nil {
		return "", errElasticsearchProject
	}
	source := string(data)
	_, tail, found := strings.Cut(source, "\n      ELASTIC_PASSWORD: \"")
	password, _, closed := strings.Cut(tail, "\"")
	if !found || !closed || !core.ElasticsearchSnapshotComposeMatches(source, p.HostPort, password) {
		return "", errElasticsearchProject
	}
	_, imageTail, _ := strings.Cut(source, "\n    image: ")
	image, _, _ := strings.Cut(imageTail, "\n")
	before, err := inspectElasticsearchSnapshotContainer(ctx, p, image)
	if err != nil {
		return "", err
	}
	current, now, err := dir.read("compose.yaml", 32<<10)
	meta, metaInfo, metaErr := dir.read("metadata.json", 16<<10)
	if err != nil || metaErr != nil || !sameComposeUpdateFile(info, now) || !bytes.Equal(current, data) ||
		!sameComposeUpdateFile(metadataInfo, metaInfo) || !bytes.Equal(meta, metadata) {
		return "", errElasticsearchProject
	}
	client := elasticsearchSnapshotHTTP{id: before.ID, password: in.Password}
	state := "accepted"
	if action == "status" {
		state, err = client.observation(ctx, in)
	} else {
		err = client.submit(ctx, in, action == "restore")
	}
	if err != nil {
		return "", err
	}
	after, err := inspectElasticsearchSnapshotContainer(ctx, p, image)
	if err != nil || before.ID != after.ID || before.State != after.State {
		return "", errors.New("快照提交期间实例状态已变化，请核对原操作")
	}
	return state, nil
}

func dockerElasticsearchRoutes(m *http.ServeMux) {
	for _, action := range []string{"create", "restore", "status"} {
		m.HandleFunc("POST /v1/docker/projects/{id}/elasticsearch-snapshots/"+action, func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			var in core.ElasticsearchSnapshotRequest
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if !readJSON(w, r, &in) {
				return
			}
			restore := action == "restore" || action == "status" && in.RestoreIndex != ""
			if !core.ValidID(id) || in.Validate(restore) != nil {
				respond(w, 400, map[string]string{"error": "Elasticsearch 快照参数无效"})
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 58*time.Second)
			defer cancel()
			state, err := runElasticsearchSnapshotOperation(ctx, id, in, action)
			if err != nil {
				respond(w, 409, map[string]string{"error": err.Error()})
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			status := http.StatusAccepted
			if action == "status" {
				status = http.StatusOK
			}
			respond(w, status, core.ElasticsearchSnapshotResult{ProjectID: id, Snapshot: in.Snapshot, Index: in.Index, RestoreIndex: in.RestoreIndex, State: state})
		})
	}
}
