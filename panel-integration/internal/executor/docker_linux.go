//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const dockerJobs = "/var/lib/panel-executor/docker-jobs"

var dockerObjectPattern = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
var dockerResourceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

func dockerClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", "/run/docker.sock")
	}}}
}

func dockerRequest(ctx context.Context, method, path string, in, out any, max int64) ([]byte, error) {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return nil, e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, "http://docker"+path, body)
	if e != nil {
		return nil, e
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := dockerClient(10 * time.Minute).Do(req)
	if e != nil {
		return nil, fmt.Errorf("Docker daemon 连接失败: %w", e)
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, errors.New("Docker 响应超过限制")
	}
	if resp.StatusCode >= 400 {
		var message struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &message)
		if message.Message == "" {
			message.Message = fmt.Sprintf("Docker daemon HTTP %d", resp.StatusCode)
		}
		return nil, errors.New(message.Message)
	}
	if out != nil && len(b) > 0 {
		if e = json.Unmarshal(b, out); e != nil {
			return nil, e
		}
	}
	return b, nil
}

func dockerAvailable(ctx context.Context) error {
	_, e := dockerRequest(ctx, http.MethodGet, "/_ping", nil, nil, 1024)
	return e
}

func dockerOverview(ctx context.Context) (map[string]any, error) {
	var version struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
		Arch       string `json:"Arch"`
		OS         string `json:"Os"`
	}
	var info struct {
		Containers        int    `json:"Containers"`
		ContainersRunning int    `json:"ContainersRunning"`
		ContainersPaused  int    `json:"ContainersPaused"`
		ContainersStopped int    `json:"ContainersStopped"`
		Images            int    `json:"Images"`
		Driver            string `json:"Driver"`
		DockerRootDir     string `json:"DockerRootDir"`
	}
	if _, e := dockerRequest(ctx, http.MethodGet, "/version", nil, &version, 1024*1024); e != nil {
		return nil, e
	}
	if _, e := dockerRequest(ctx, http.MethodGet, "/info", nil, &info, 2*1024*1024); e != nil {
		return nil, e
	}
	return map[string]any{"available": true, "active": true, "version": version.Version, "api_version": version.APIVersion, "architecture": version.Arch, "os": version.OS, "containers": info.Containers, "running": info.ContainersRunning, "paused": info.ContainersPaused, "stopped": info.ContainersStopped, "images": info.Images, "storage_driver": info.Driver, "data_root": info.DockerRootDir}, nil
}

func dockerContainers(ctx context.Context) (any, error) {
	var out []struct {
		ID      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		ImageID string            `json:"ImageID"`
		Command string            `json:"Command"`
		Created int64             `json:"Created"`
		State   string            `json:"State"`
		Status  string            `json:"Status"`
		Labels  map[string]string `json:"Labels"`
		Ports   []struct {
			IP          string `json:"IP"`
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
	}
	_, e := dockerRequest(ctx, http.MethodGet, "/containers/json?all=1", nil, &out, 8*1024*1024)
	return map[string]any{"containers": out}, e
}

func dockerImages(ctx context.Context) (any, error) {
	var out []struct {
		ID          string   `json:"Id"`
		RepoTags    []string `json:"RepoTags"`
		RepoDigests []string `json:"RepoDigests"`
		Created     int64    `json:"Created"`
		Size        int64    `json:"Size"`
		Containers  int64    `json:"Containers"`
	}
	_, e := dockerRequest(ctx, http.MethodGet, "/images/json?all=0", nil, &out, 8*1024*1024)
	return map[string]any{"images": out}, e
}

func dockerNetworks(ctx context.Context) (any, error) {
	var out []struct {
		ID         string            `json:"Id"`
		Name       string            `json:"Name"`
		Driver     string            `json:"Driver"`
		Scope      string            `json:"Scope"`
		Internal   bool              `json:"Internal"`
		Attachable bool              `json:"Attachable"`
		Labels     map[string]string `json:"Labels"`
		Containers map[string]any    `json:"Containers"`
	}
	_, e := dockerRequest(ctx, http.MethodGet, "/networks", nil, &out, 8*1024*1024)
	return map[string]any{"networks": out}, e
}

func dockerVolumes(ctx context.Context) (any, error) {
	var out struct {
		Volumes []struct {
			Name       string            `json:"Name"`
			Driver     string            `json:"Driver"`
			Mountpoint string            `json:"Mountpoint"`
			Scope      string            `json:"Scope"`
			Labels     map[string]string `json:"Labels"`
		} `json:"Volumes"`
	}
	_, e := dockerRequest(ctx, http.MethodGet, "/volumes", nil, &out, 8*1024*1024)
	if out.Volumes == nil {
		out.Volumes = []struct {
			Name       string            `json:"Name"`
			Driver     string            `json:"Driver"`
			Mountpoint string            `json:"Mountpoint"`
			Scope      string            `json:"Scope"`
			Labels     map[string]string `json:"Labels"`
		}{}
	}
	return map[string]any{"volumes": out.Volumes}, e
}

func dockerCreateNetwork(ctx context.Context, name string, internal bool) (any, error) {
	if !dockerResourceNamePattern.MatchString(name) {
		return nil, errors.New("Docker 网络名称无效")
	}
	payload := map[string]any{
		"Name":           name,
		"CheckDuplicate": true,
		"Driver":         "bridge",
		"Internal":       internal,
		"Attachable":     false,
		"Labels":         map[string]string{"com.yunzhan.panel.managed": "true", "com.yunzhan.panel.kind": "network"},
	}
	var out map[string]any
	_, e := dockerRequest(ctx, http.MethodPost, "/networks/create", payload, &out, 1024*1024)
	return out, e
}

func dockerCreateVolume(ctx context.Context, name string) (any, error) {
	if !dockerResourceNamePattern.MatchString(name) {
		return nil, errors.New("Docker 卷名称无效")
	}
	payload := map[string]any{
		"Name":   name,
		"Driver": "local",
		"Labels": map[string]string{"com.yunzhan.panel.managed": "true", "com.yunzhan.panel.kind": "volume"},
	}
	var out map[string]any
	_, e := dockerRequest(ctx, http.MethodPost, "/volumes/create", payload, &out, 1024*1024)
	return out, e
}

func dockerDeleteNetwork(ctx context.Context, id, expectedName string) error {
	if !dockerObjectPattern.MatchString(id) {
		return errors.New("Docker 网络标识无效")
	}
	var inspect struct {
		Name   string            `json:"Name"`
		Labels map[string]string `json:"Labels"`
	}
	if _, e := dockerRequest(ctx, http.MethodGet, "/networks/"+id, nil, &inspect, 1024*1024); e != nil {
		return e
	}
	if inspect.Labels["com.yunzhan.panel.managed"] != "true" || inspect.Labels["com.yunzhan.panel.kind"] != "network" {
		return errors.New("拒绝删除非面板创建的 Docker 网络")
	}
	if inspect.Name != expectedName {
		return errors.New("Docker 网络名称确认不匹配")
	}
	_, e := dockerRequest(ctx, http.MethodDelete, "/networks/"+id, nil, nil, 1024*1024)
	return e
}

func dockerDeleteVolume(ctx context.Context, name string) error {
	if !dockerResourceNamePattern.MatchString(name) {
		return errors.New("Docker 卷名称无效")
	}
	var inspect struct {
		Labels map[string]string `json:"Labels"`
	}
	escaped := url.PathEscape(name)
	if _, e := dockerRequest(ctx, http.MethodGet, "/volumes/"+escaped, nil, &inspect, 1024*1024); e != nil {
		return e
	}
	managed := inspect.Labels["com.yunzhan.panel.managed"] == "true" && inspect.Labels["com.yunzhan.panel.kind"] == "volume"
	composeProject := inspect.Labels["com.docker.compose.project"]
	panelCompose := regexp.MustCompile(`^panel_[a-f0-9]{12}$`).MatchString(composeProject)
	if !managed && !panelCompose {
		return errors.New("拒绝删除非面板创建的 Docker 卷")
	}
	if panelCompose {
		entries, _ := os.ReadDir(dockerProjects)
		for _, entry := range entries {
			if !entry.IsDir() || !core.ValidID(entry.Name()) {
				continue
			}
			if metadata, _, readErr := readComposeMetadata(entry.Name()); readErr == nil && metadata.Engine == composeProject {
				return errors.New("Compose 项目仍存在，请先删除项目")
			}
		}
	}
	_, e := dockerRequest(ctx, http.MethodDelete, "/volumes/"+escaped, nil, nil, 1024*1024)
	return e
}

func dockerLogs(ctx context.Context, id string) (string, error) {
	if !dockerObjectPattern.MatchString(id) {
		return "", errors.New("Docker 对象标识无效")
	}
	b, e := dockerRequest(ctx, http.MethodGet, "/containers/"+id+"/logs?stdout=1&stderr=1&timestamps=1&tail=200", nil, nil, 256*1024)
	if e != nil {
		return "", e
	}
	var text bytes.Buffer
	for len(b) >= 8 {
		size := int(binary.BigEndian.Uint32(b[4:8]))
		if size < 0 || size > len(b)-8 {
			break
		}
		text.Write(b[8 : 8+size])
		b = b[8+size:]
	}
	if text.Len() == 0 {
		text.Write(b)
	}
	return text.String(), nil
}

func readDockerJobResult(id string) (core.DockerJobResult, error) {
	var result core.DockerJobResult
	if !core.ValidID(id) {
		return result, errors.New("Docker 作业标识无效")
	}
	b, e := os.ReadFile(filepath.Join(dockerJobs, id+".result.json"))
	if e == nil {
		e = json.Unmarshal(b, &result)
	}
	if e == nil && result.JobID != id {
		e = errors.New("Docker 作业结果不匹配")
	}
	return result, e
}

func readDockerJobRequest(id string) (core.DockerJobRequest, error) {
	var op core.DockerJobRequest
	if !core.ValidID(id) {
		return op, errors.New("Docker 作业标识无效")
	}
	b, e := os.ReadFile(filepath.Join(dockerJobs, id+".request.json"))
	if e == nil {
		e = json.Unmarshal(b, &op)
	}
	if e == nil {
		e = core.ValidateDockerJob(op)
	}
	if e == nil && op.JobID != id {
		e = errors.New("Docker 作业参数不匹配")
	}
	return op, e
}

func dockerPull(ctx context.Context, image string) error {
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/images/create?fromImage="+url.QueryEscape(image), nil)
	if e != nil {
		return e
	}
	resp, e := dockerClient(20 * time.Minute).Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		return fmt.Errorf("镜像拉取失败: %s", strings.TrimSpace(string(b)))
	}
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 64*1024*1024))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var item struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(scanner.Bytes(), &item) == nil && item.Error != "" {
			return errors.New(item.Error)
		}
	}
	return scanner.Err()
}

func dockerCreate(ctx context.Context, op core.DockerJobRequest) (string, error) {
	type binding struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}
	exposed := map[string]struct{}{}
	bindings := map[string][]binding{}
	for _, p := range op.Ports {
		key := fmt.Sprintf("%d/%s", p.ContainerPort, p.Protocol)
		exposed[key] = struct{}{}
		bindings[key] = []binding{{HostIP: "127.0.0.1", HostPort: fmt.Sprint(p.HostPort)}}
	}
	env := make([]string, 0, len(op.Environment))
	for _, item := range op.Environment {
		env = append(env, item.Name+"="+item.Value)
	}
	payload := struct {
		Image        string              `json:"Image"`
		Cmd          []string            `json:"Cmd,omitempty"`
		Env          []string            `json:"Env,omitempty"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
		Labels       map[string]string   `json:"Labels"`
		HostConfig   struct {
			PortBindings  map[string][]binding `json:"PortBindings,omitempty"`
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
		} `json:"HostConfig"`
	}{Image: op.Image, Cmd: op.Command, Env: env, ExposedPorts: exposed, Labels: map[string]string{"com.yunzhan.panel.managed": "true", "com.yunzhan.panel.job": op.JobID}}
	payload.HostConfig.PortBindings = bindings
	payload.HostConfig.RestartPolicy.Name = op.Restart
	var created struct {
		ID string `json:"Id"`
	}
	if _, e := dockerRequest(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(op.Name), payload, &created, 1024*1024); e != nil {
		return "", e
	}
	if len(created.ID) != 64 {
		return "", errors.New("Docker 未返回完整容器标识")
	}
	if _, e := dockerRequest(ctx, http.MethodPost, "/containers/"+created.ID+"/start", nil, nil, 1024*1024); e != nil {
		_, _ = dockerRequest(context.Background(), http.MethodDelete, "/containers/"+created.ID, nil, nil, 1024*1024)
		return "", e
	}
	return created.ID, nil
}

func RunDockerJob(id string) (ret error) {
	op, e := readDockerJobRequest(id)
	if e != nil {
		return e
	}
	if e = os.Remove(filepath.Join(dockerJobs, id+".request.json")); e != nil {
		return e
	}
	result := core.DockerJobResult{JobID: id, State: "running", Image: op.Image}
	_ = writeJSON(filepath.Join(dockerJobs, id+".result.json"), result)
	defer func() {
		if ret != nil {
			result.State, result.Error = "failed", ret.Error()
		} else {
			result.State, result.Message = "succeeded", "Docker 作业完成"
		}
		if writeErr := writeJSON(filepath.Join(dockerJobs, id+".result.json"), result); ret == nil {
			ret = writeErr
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if e = dockerAvailable(ctx); e != nil {
		return e
	}
	if op.Action == "pull" {
		return dockerPull(ctx, op.Image)
	}
	result.ContainerID, e = dockerCreate(ctx, op)
	return e
}

func (s *Service) dockerRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/docker", func(w http.ResponseWriter, r *http.Request) {
		out, e := dockerOverview(r.Context())
		if e != nil {
			respond(w, 503, map[string]any{"error": e.Error(), "available": false, "active": false})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/docker/containers", func(w http.ResponseWriter, r *http.Request) {
		out, e := dockerContainers(r.Context())
		if e != nil {
			respond(w, 503, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/docker/images", func(w http.ResponseWriter, r *http.Request) {
		out, e := dockerImages(r.Context())
		if e != nil {
			respond(w, 503, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/docker/networks", func(w http.ResponseWriter, r *http.Request) {
		out, e := dockerNetworks(r.Context())
		if e != nil {
			respond(w, 503, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/docker/networks", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name     string `json:"name"`
			Internal bool   `json:"internal"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		out, e := dockerCreateNetwork(r.Context(), in.Name, in.Internal)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 201, out)
	})
	m.HandleFunc("DELETE /v1/docker/networks/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ExpectedName string `json:"expected_name"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if e := dockerDeleteNetwork(r.Context(), r.PathValue("id"), in.ExpectedName); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	m.HandleFunc("GET /v1/docker/volumes", func(w http.ResponseWriter, r *http.Request) {
		out, e := dockerVolumes(r.Context())
		if e != nil {
			respond(w, 503, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/docker/volumes", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name string `json:"name"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		out, e := dockerCreateVolume(r.Context(), in.Name)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 201, out)
	})
	m.HandleFunc("DELETE /v1/docker/volumes/{name}", func(w http.ResponseWriter, r *http.Request) {
		if e := dockerDeleteVolume(r.Context(), r.PathValue("name")); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	m.HandleFunc("GET /v1/docker/containers/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		logs, e := dockerLogs(r.Context(), r.PathValue("id"))
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]string{"logs": logs})
	})
	m.HandleFunc("POST /v1/docker/jobs", func(w http.ResponseWriter, r *http.Request) {
		var op core.DockerJobRequest
		if !readJSON(w, r, &op) {
			return
		}
		if e := core.ValidateDockerJob(op); e != nil {
			respond(w, 400, map[string]string{"error": e.Error()})
			return
		}
		if e := dockerAvailable(r.Context()); e != nil {
			respond(w, 503, map[string]string{"error": e.Error()})
			return
		}
		if e := os.MkdirAll(dockerJobs, 0700); e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		if e := writeExclusiveJSON(filepath.Join(dockerJobs, op.JobID+".request.json"), op); e != nil {
			respond(w, 409, map[string]string{"error": "Docker 作业标识已存在"})
			return
		}
		queued := core.DockerJobResult{JobID: op.JobID, State: "queued", Image: op.Image}
		if e := writeJSON(filepath.Join(dockerJobs, op.JobID+".result.json"), queued); e != nil {
			_ = os.Remove(filepath.Join(dockerJobs, op.JobID+".request.json"))
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		if _, e := s.Config.Run(r.Context(), "/usr/bin/systemctl", "start", "--no-block", "panel-docker-job@"+op.JobID+".service"); e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 202, queued)
	})
	m.HandleFunc("GET /v1/docker/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		result, e := readDockerJobResult(r.PathValue("id"))
		if e != nil {
			respond(w, 404, map[string]string{"error": "Docker 作业不存在"})
			return
		}
		if result.State == "queued" || result.State == "running" {
			unit := "panel-docker-job@" + result.JobID + ".service"
			if result.Kind == "compose" {
				unit = "panel-compose-job@" + result.JobID + ".service"
			}
			active, _ := s.Config.Run(r.Context(), "/usr/bin/systemctl", "show", "-p", "ActiveState", "--value", unit)
			state := strings.TrimSpace(active)
			// A successful oneshot becomes inactive immediately after the worker exits.
			// Its final atomic result write can become visible a few milliseconds after
			// systemd reports that transition, so reread before returning the stale
			// queued/running snapshot. Inactive by itself is not a failure.
			if state == "inactive" {
				for i := 0; i < 5 && (result.State == "queued" || result.State == "running"); i++ {
					select {
					case <-r.Context().Done():
						i = 5
					case <-time.After(50 * time.Millisecond):
						if latest, readErr := readDockerJobResult(result.JobID); readErr == nil {
							result = latest
						}
					}
				}
			} else if state == "failed" {
				// The worker's deferred error write normally wins. Give it a brief
				// chance to publish the concrete daemon error before synthesizing one.
				time.Sleep(100 * time.Millisecond)
				if latest, readErr := readDockerJobResult(result.JobID); readErr == nil {
					result = latest
				}
			}
			if state == "failed" && (result.State == "queued" || result.State == "running") {
				result.State, result.Error = "failed", "Docker 作业进程已停止，可核对后重新提交"
				_ = writeJSON(filepath.Join(dockerJobs, result.JobID+".result.json"), result)
			}
		}
		respond(w, 200, result)
	})
	for _, action := range []string{"start", "stop", "restart"} {
		action := action
		m.HandleFunc("POST /v1/docker/containers/{id}/"+action, func(w http.ResponseWriter, r *http.Request) {
			if !dockerObjectPattern.MatchString(r.PathValue("id")) {
				respond(w, 400, map[string]string{"error": "Docker 对象标识无效"})
				return
			}
			path := "/containers/" + r.PathValue("id") + "/" + action
			if action == "stop" || action == "restart" {
				path += "?t=10"
			}
			if _, e := dockerRequest(r.Context(), http.MethodPost, path, nil, nil, 1024*1024); e != nil {
				respond(w, 409, map[string]string{"error": e.Error()})
				return
			}
			respond(w, 200, map[string]bool{"ok": true})
		})
	}
	m.HandleFunc("DELETE /v1/docker/containers/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !dockerObjectPattern.MatchString(r.PathValue("id")) {
			respond(w, 400, map[string]string{"error": "Docker 对象标识无效"})
			return
		}
		if _, e := dockerRequest(r.Context(), http.MethodDelete, "/containers/"+r.PathValue("id")+"?v=false", nil, nil, 1024*1024); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	m.HandleFunc("DELETE /v1/docker/images/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !dockerObjectPattern.MatchString(r.PathValue("id")) {
			respond(w, 400, map[string]string{"error": "Docker 对象标识无效"})
			return
		}
		if _, e := dockerRequest(r.Context(), http.MethodDelete, "/images/"+r.PathValue("id")+"?force=false&noprune=true", nil, nil, 2*1024*1024); e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	s.dockerComposeRoutes(m)
}
