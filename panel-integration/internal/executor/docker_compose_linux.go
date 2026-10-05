//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const dockerProjects = "/etc/panel/compose"

var composeForbiddenKey = regexp.MustCompile(`(?mi)^\s*(?:env_file|extends|include|build|dockerfile|file|configs|secrets)\s*:`)

type composeProjectRequest struct {
	JobID      string `json:"job_id"`
	ProjectID  string `json:"project_id"`
	Action     string `json:"action"`
	Name       string `json:"name,omitempty"`
	Compose    string `json:"compose,omitempty"`
	TemplateID string `json:"template_id,omitempty"`
}

type composeMetadata struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Engine     string `json:"engine_name"`
	TemplateID string `json:"template_id,omitempty"`
	HostPort   int    `json:"host_port,omitempty"`
	Services   int    `json:"services"`
	CreatedAt  string `json:"created_at"`
}

type composeConfig struct {
	Services map[string]struct {
		Image          string            `json:"image"`
		Build          json.RawMessage   `json:"build"`
		ContainerName  string            `json:"container_name"`
		Privileged     bool              `json:"privileged"`
		NetworkMode    string            `json:"network_mode"`
		PID            string            `json:"pid"`
		IPC            string            `json:"ipc"`
		UTS            string            `json:"uts"`
		UserNSMode     string            `json:"userns_mode"`
		Runtime        string            `json:"runtime"`
		Restart        string            `json:"restart"`
		CapAdd         []string          `json:"cap_add"`
		CapDrop        []string          `json:"cap_drop"`
		Devices        []json.RawMessage `json:"devices"`
		DeviceRules    []string          `json:"device_cgroup_rules"`
		SecurityOpt    []string          `json:"security_opt"`
		Sysctls        map[string]string `json:"sysctls"`
		CredentialSpec json.RawMessage   `json:"credential_spec"`
		Ports          []struct {
			HostIP    string `json:"host_ip"`
			Target    int    `json:"target"`
			Published string `json:"published"`
			Protocol  string `json:"protocol"`
			Mode      string `json:"mode"`
		} `json:"ports"`
		Volumes []struct {
			Type   string `json:"type"`
			Source string `json:"source"`
			Target string `json:"target"`
		} `json:"volumes"`
	} `json:"services"`
	Volumes map[string]struct {
		External   bool              `json:"external"`
		Driver     string            `json:"driver"`
		DriverOpts map[string]string `json:"driver_opts"`
	} `json:"volumes"`
	Networks map[string]struct {
		External   bool              `json:"external"`
		Driver     string            `json:"driver"`
		DriverOpts map[string]string `json:"driver_opts"`
	} `json:"networks"`
	Secrets map[string]json.RawMessage `json:"secrets"`
	Configs map[string]json.RawMessage `json:"configs"`
}

func validateComposeRequest(v composeProjectRequest) error {
	if !core.ValidID(v.JobID) || !core.ValidID(v.ProjectID) {
		return errors.New("Compose 作业标识无效")
	}
	switch v.Action {
	case "create":
		if !dockerResourceNamePattern.MatchString(v.Name) || len(v.Name) > 40 {
			return errors.New("Compose 项目名称无效")
		}
		if len(v.Compose) < 20 || len(v.Compose) > 48*1024 || strings.ContainsRune(v.Compose, 0) {
			return errors.New("Compose 内容长度无效")
		}
		if v.TemplateID != "" && !core.IsDockerTemplate(v.TemplateID) {
			return errors.New("应用模板不存在")
		}
	case "start", "stop", "restart", "update":
		if v.Name != "" || v.Compose != "" || v.TemplateID != "" {
			return errors.New("Compose 操作包含多余参数")
		}
	case "delete":
		if !dockerResourceNamePattern.MatchString(v.Name) || v.Compose != "" || v.TemplateID != "" {
			return errors.New("Compose 删除确认无效")
		}
	default:
		return errors.New("Compose 作业动作无效")
	}
	return nil
}

func composeCommand(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/docker", append([]string{"compose"}, args...)...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	out := &boundedBuffer{max: 1024 * 1024}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 2 * time.Second
	if e := cmd.Run(); e != nil {
		return out.String(), fmt.Errorf("docker compose: %w: %s", e, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func composePull(ctx context.Context, args ...string) (string, error) {
	var output string
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		output, err = composeCommand(ctx, args...)
		if err == nil || ctx.Err() != nil {
			return output, err
		}
		message := strings.ToLower(err.Error())
		transient := strings.Contains(message, "unexpected eof") || strings.Contains(message, ": eof") || strings.Contains(message, "tls handshake timeout") || strings.Contains(message, "connection reset by peer") || strings.Contains(message, "i/o timeout") || strings.Contains(message, "temporary failure in name resolution")
		if !transient || attempt == 3 {
			return output, err
		}
		select {
		case <-ctx.Done():
			return output, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 3 * time.Second):
		}
	}
	return output, err
}

func composeArgs(metadata composeMetadata, dir string, tail ...string) []string {
	return append([]string{"-p", metadata.Engine, "-f", filepath.Join(dir, "compose.yaml")}, tail...)
}

func validateComposeFile(ctx context.Context, metadata composeMetadata, dir, source string) (composeConfig, error) {
	var config composeConfig
	if composeForbiddenKey.MatchString(source) || strings.Contains(source, "!include") {
		return config, errors.New("Compose 不允许外部文件、构建、include、config 或 secret 指令")
	}
	out, e := composeCommand(ctx, composeArgs(metadata, dir, "config", "--format", "json")...)
	if e != nil {
		return config, e
	}
	if e = json.Unmarshal([]byte(out), &config); e != nil {
		return config, errors.New("Compose 规范化结果无效")
	}
	if len(config.Services) < 1 || len(config.Services) > 16 {
		return config, errors.New("Compose 服务数量应为 1–16 个")
	}
	if len(config.Secrets) > 0 || len(config.Configs) > 0 {
		return config, errors.New("Compose 首版不接受 secrets 或 configs")
	}
	for name, service := range config.Services {
		if !dockerResourceNamePattern.MatchString(name) || service.Image == "" {
			return config, errors.New("Compose 服务名称或镜像无效")
		}
		if e = core.ValidateDockerJob(core.DockerJobRequest{JobID: metadata.ID, Action: "pull", Image: service.Image}); e != nil {
			return config, fmt.Errorf("服务 %s 的镜像无效", name)
		}
		last := service.Image[strings.LastIndex(service.Image, "/")+1:]
		if !strings.Contains(last, ":") && !strings.Contains(service.Image, "@sha256:") {
			return config, fmt.Errorf("服务 %s 必须指定镜像标签或摘要", name)
		}
		for _, option := range service.SecurityOpt {
			if option != "no-new-privileges:true" {
				return config, errors.New("只允许 no-new-privileges 安全选项")
			}
		}
		if len(service.Build) > 0 && string(service.Build) != "null" || service.ContainerName != "" || service.Privileged || service.NetworkMode != "" || service.PID != "" || service.IPC != "" || service.UTS != "" || service.UserNSMode != "" || service.Runtime != "" || len(service.CapAdd) > 0 || len(service.Devices) > 0 || len(service.DeviceRules) > 0 || len(service.Sysctls) > 0 || len(service.CredentialSpec) > 0 && string(service.CredentialSpec) != "null" {
			return config, fmt.Errorf("服务 %s 请求了特权、宿主机或设备能力", name)
		}
		if service.Restart != "" && service.Restart != "no" && service.Restart != "on-failure" && service.Restart != "unless-stopped" {
			return config, fmt.Errorf("服务 %s 的重启策略无效", name)
		}
		for _, port := range service.Ports {
			published, parseErr := strconv.Atoi(port.Published)
			if parseErr != nil || published < 1024 || published > 65535 || port.Target < 1 || port.Target > 65535 || port.HostIP != "127.0.0.1" || (port.Protocol != "tcp" && port.Protocol != "udp") {
				return config, fmt.Errorf("服务 %s 只能使用 127.0.0.1 的非特权端口", name)
			}
		}
		for _, volume := range service.Volumes {
			if volume.Type != "volume" || volume.Source == "" || !strings.HasPrefix(volume.Target, "/") {
				return config, fmt.Errorf("服务 %s 只允许受管命名卷", name)
			}
		}
	}
	for name, volume := range config.Volumes {
		if volume.External || (volume.Driver != "" && volume.Driver != "local") || len(volume.DriverOpts) > 0 || !dockerResourceNamePattern.MatchString(name) {
			return config, fmt.Errorf("卷 %s 必须是项目内 local 命名卷", name)
		}
	}
	for name, network := range config.Networks {
		if network.External || (network.Driver != "" && network.Driver != "bridge") || len(network.DriverOpts) > 0 || !dockerResourceNamePattern.MatchString(name) {
			return config, fmt.Errorf("网络 %s 必须是项目内 bridge 网络", name)
		}
	}
	return config, nil
}

func wordPressTemplatePort(config composeConfig) (int, error) {
	if len(config.Services) != 2 || config.Services["wordpress"].Image != "wordpress:7.1.2-php8.3-apache" || config.Services["db"].Image != "mariadb:11.8.9" {
		return 0, errors.New("WordPress 模板服务或精确镜像不匹配")
	}
	web, db := config.Services["wordpress"], config.Services["db"]
	if len(web.Ports) != 1 || len(db.Ports) != 0 || web.Ports[0].HostIP != "127.0.0.1" || web.Ports[0].Target != 80 || web.Ports[0].Protocol != "tcp" {
		return 0, errors.New("WordPress 模板端口不匹配")
	}
	port, e := strconv.Atoi(web.Ports[0].Published)
	if e != nil || port < 1024 || port > 65535 {
		return 0, errors.New("WordPress 模板回环端口无效")
	}
	return port, nil
}

func templatePublishedPort(config composeConfig) (int, error) {
	port := 0
	for _, service := range config.Services {
		for _, binding := range service.Ports {
			if port != 0 {
				return 0, errors.New("应用模板只能发布一个主机端口")
			}
			published, e := strconv.Atoi(binding.Published)
			if e != nil || published < 1024 || published > 65535 || binding.HostIP != "127.0.0.1" {
				return 0, errors.New("应用模板回环端口无效")
			}
			port = published
		}
	}
	if port == 0 {
		return 0, errors.New("应用模板缺少主机端口")
	}
	return port, nil
}

func dualTemplatePort(config composeConfig, id string) (int, error) {
	if len(config.Services) != 1 {
		return 0, errors.New("双端口模板服务数量不匹配")
	}
	service := config.Services[id]
	if len(service.Ports) != 2 {
		return 0, errors.New("双端口模板端口数量不匹配")
	}
	main, other := 15672, 5672
	if id == "openlitespeed" {
		main, other = 8088, 7080
	}
	port, next := 0, 0
	for _, p := range service.Ports {
		value, e := strconv.Atoi(p.Published)
		if e != nil || p.HostIP != "127.0.0.1" || p.Protocol != "tcp" {
			return 0, errors.New("双端口模板只能监听回环 TCP")
		}
		switch p.Target {
		case main:
			port = value
		case other:
			next = value
		default:
			return 0, errors.New("模板服务端口不匹配")
		}
	}
	if port < 1024 || port >= 65535 || next != port+1 {
		return 0, errors.New("模板回环端口必须为连续的两个非特权端口")
	}
	return port, nil
}

func composeLock() (func(), error) {
	f, e := os.OpenFile(filepath.Join(dockerJobs, "compose.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX); e != nil {
		f.Close()
		return nil, e
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
}

func readComposeRequest(id string) (composeProjectRequest, error) {
	var op composeProjectRequest
	if !core.ValidID(id) {
		return op, errors.New("Compose 作业标识无效")
	}
	b, e := os.ReadFile(filepath.Join(dockerJobs, id+".compose.request.json"))
	if e == nil {
		e = json.Unmarshal(b, &op)
	}
	if e == nil {
		e = validateComposeRequest(op)
	}
	if e == nil && op.JobID != id {
		e = errors.New("Compose 作业参数不匹配")
	}
	return op, e
}

func readComposeMetadata(id string) (composeMetadata, string, error) {
	var metadata composeMetadata
	if !core.ValidID(id) {
		return metadata, "", errors.New("Compose 项目标识无效")
	}
	dir := filepath.Join(dockerProjects, id)
	if e := ordinary(dir, true); e != nil {
		return metadata, "", e
	}
	b, e := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if e == nil {
		e = json.Unmarshal(b, &metadata)
	}
	if e != nil || metadata.ID != id || !dockerResourceNamePattern.MatchString(metadata.Name) || metadata.Engine != "panel_"+id[:12] || metadata.TemplateID == "wordpress-blog" && (metadata.HostPort < 1024 || metadata.HostPort > 65535) {
		return metadata, "", errors.New("Compose 项目元数据无效")
	}
	if e = ordinary(filepath.Join(dir, "compose.yaml"), false); e != nil {
		return metadata, "", e
	}
	return metadata, dir, nil
}

func RunComposeJob(id string) (ret error) {
	op, e := readComposeRequest(id)
	if e != nil {
		return e
	}
	if e = os.Remove(filepath.Join(dockerJobs, id+".compose.request.json")); e != nil {
		return e
	}
	result := core.DockerJobResult{JobID: id, Kind: "compose", State: "running", ProjectID: op.ProjectID}
	_ = writeJSON(filepath.Join(dockerJobs, id+".result.json"), result)
	defer func() {
		if ret != nil {
			result.State, result.Error = "failed", ret.Error()
		} else {
			result.State, result.Message = "succeeded", "Compose 作业完成"
		}
		if writeErr := writeJSON(filepath.Join(dockerJobs, id+".result.json"), result); ret == nil {
			ret = writeErr
		}
	}()
	unlock, e := composeLock()
	if e != nil {
		return e
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	if e = dockerAvailable(ctx); e != nil {
		return e
	}
	if e = os.MkdirAll(dockerProjects, 0700); e != nil {
		return e
	}
	if op.Action == "create" {
		finalDir := filepath.Join(dockerProjects, op.ProjectID)
		if _, statErr := os.Lstat(finalDir); !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("Compose 项目标识已存在")
		}
		tmpDir := filepath.Join(dockerProjects, ".tmp-"+op.JobID)
		if e = os.Mkdir(tmpDir, 0700); e != nil {
			return e
		}
		defer os.RemoveAll(tmpDir)
		metadata := composeMetadata{ID: op.ProjectID, Name: op.Name, Engine: "panel_" + op.ProjectID[:12], TemplateID: op.TemplateID, CreatedAt: core.Now()}
		if e = atomicWrite(filepath.Join(tmpDir, "compose.yaml"), []byte(op.Compose), 0600); e != nil {
			return e
		}
		config, validateErr := validateComposeFile(ctx, metadata, tmpDir, op.Compose)
		if validateErr != nil {
			return validateErr
		}
		if op.TemplateID == "wordpress-blog" {
			metadata.HostPort, e = wordPressTemplatePort(config)
			if e != nil {
				return e
			}
		} else if op.TemplateID == "rabbitmq" || op.TemplateID == "openlitespeed" {
			metadata.HostPort, e = dualTemplatePort(config, op.TemplateID)
			if e != nil {
				return e
			}
		} else if op.TemplateID != "" {
			metadata.HostPort, e = templatePublishedPort(config)
			if e != nil {
				return e
			}
		}
		metadata.Services = len(config.Services)
		b, _ := json.Marshal(metadata)
		if e = atomicWrite(filepath.Join(tmpDir, "metadata.json"), b, 0600); e != nil {
			return e
		}
		if _, e = composePull(ctx, composeArgs(metadata, tmpDir, "pull")...); e != nil {
			return e
		}
		if _, e = composeCommand(ctx, composeArgs(metadata, tmpDir, "up", "-d", "--remove-orphans")...); e != nil {
			_, _ = composeCommand(context.Background(), composeArgs(metadata, tmpDir, "down", "--remove-orphans")...)
			return e
		}
		if e = os.Rename(tmpDir, finalDir); e != nil {
			_, _ = composeCommand(context.Background(), composeArgs(metadata, tmpDir, "down", "--remove-orphans")...)
			return e
		}
		return nil
	}
	metadata, dir, e := readComposeMetadata(op.ProjectID)
	if e != nil {
		return e
	}
	if op.Action == "delete" && op.Name != metadata.Name {
		return errors.New("Compose 项目名称确认不匹配")
	}
	var args []string
	switch op.Action {
	case "start":
		args = []string{"start"}
	case "stop":
		args = []string{"stop", "-t", "10"}
	case "restart":
		args = []string{"restart", "-t", "10"}
	case "update":
		if _, e = composePull(ctx, composeArgs(metadata, dir, "pull")...); e != nil {
			return e
		}
		args = []string{"up", "-d", "--remove-orphans"}
	case "delete":
		if _, e = composeCommand(ctx, composeArgs(metadata, dir, "down", "--remove-orphans")...); e != nil {
			return e
		}
		return os.RemoveAll(dir)
	}
	_, e = composeCommand(ctx, composeArgs(metadata, dir, args...)...)
	return e
}

// RecoverComposeJobs removes uncommitted create directories and marks jobs that
// no longer have a running systemd worker. Committed projects and named volumes
// are never removed by recovery.
func RecoverComposeJobs() error {
	if e := os.MkdirAll(dockerJobs, 0700); e != nil {
		return e
	}
	if e := os.MkdirAll(dockerProjects, 0700); e != nil {
		return e
	}
	unlock, e := composeLock()
	if e != nil {
		return e
	}
	defer unlock()
	entries, e := os.ReadDir(dockerProjects)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		jobID := strings.TrimPrefix(entry.Name(), ".tmp-")
		if !core.ValidID(jobID) {
			continue
		}
		dir := filepath.Join(dockerProjects, entry.Name())
		var metadata composeMetadata
		if b, readErr := os.ReadFile(filepath.Join(dir, "metadata.json")); readErr == nil && json.Unmarshal(b, &metadata) == nil && core.ValidID(metadata.ID) && metadata.Engine == "panel_"+metadata.ID[:12] {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			_, _ = composeCommand(ctx, composeArgs(metadata, dir, "down", "--remove-orphans")...)
			cancel()
		}
		if removeErr := os.RemoveAll(dir); removeErr != nil {
			return removeErr
		}
	}
	results, e := filepath.Glob(filepath.Join(dockerJobs, "*.result.json"))
	if e != nil {
		return e
	}
	for _, path := range results {
		id := strings.TrimSuffix(filepath.Base(path), ".result.json")
		result, readErr := readDockerJobResult(id)
		if readErr != nil || result.Kind != "compose" || (result.State != "queued" && result.State != "running") {
			continue
		}
		active := exec.Command("/usr/bin/systemctl", "is-active", "panel-compose-job@"+id+".service").Run() == nil
		if active {
			continue
		}
		result.State, result.Error = "failed", "Compose 作业被中断，未提交资源已清理，可重新提交"
		if writeErr := writeJSON(path, result); writeErr != nil {
			return writeErr
		}
		_ = os.Remove(filepath.Join(dockerJobs, id+".compose.request.json"))
	}
	return nil
}

func listComposeProjects(ctx context.Context) ([]map[string]any, error) {
	if e := os.MkdirAll(dockerProjects, 0700); e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(dockerProjects)
	if e != nil {
		return nil, e
	}
	out := []map[string]any{}
	for _, entry := range entries {
		if !entry.IsDir() || !core.ValidID(entry.Name()) {
			continue
		}
		metadata, _, readErr := readComposeMetadata(entry.Name())
		if readErr != nil {
			return nil, readErr
		}
		filters, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + metadata.Engine}})
		var containers []struct {
			ID     string `json:"Id"`
			State  string `json:"State"`
			Status string `json:"Status"`
			Image  string `json:"Image"`
		}
		_, requestErr := dockerRequest(ctx, http.MethodGet, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), nil, &containers, 4*1024*1024)
		if requestErr != nil {
			return nil, requestErr
		}
		running, healthy := 0, 0
		images := []string{}
		for _, container := range containers {
			if container.Image != "" {
				images = append(images, container.Image)
			}
			if container.State == "running" {
				running++
				if strings.Contains(container.Status, "(healthy)") {
					healthy++
				}
			}
		}
		state := "empty"
		if len(containers) > 0 {
			state = "stopped"
		}
		if running > 0 {
			state = "running"
		}
		out = append(out, map[string]any{"id": metadata.ID, "name": metadata.Name, "engine_name": metadata.Engine, "template_id": metadata.TemplateID, "host_port": metadata.HostPort, "services": metadata.Services, "containers": len(containers), "running": running, "healthy": healthy, "state": state, "created_at": metadata.CreatedAt, "images": images})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["created_at"].(string) > out[j]["created_at"].(string) })
	return out, nil
}

func composeLogs(ctx context.Context, id string) (string, error) {
	metadata, dir, e := readComposeMetadata(id)
	if e != nil {
		return "", e
	}
	out, e := composeCommand(ctx, composeArgs(metadata, dir, "logs", "--no-color", "--tail", "200")...)
	if len(out) > 256*1024 {
		out = out[:256*1024]
	}
	return out, e
}

func (s *Service) dockerComposeRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/docker/projects/{id}/credentials", func(w http.ResponseWriter, r *http.Request) {
		metadata, dir, e := readComposeMetadata(r.PathValue("id"))
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		fields := map[string][]string{"mongodb": {"MONGO_INITDB_ROOT_USERNAME", "MONGO_INITDB_ROOT_PASSWORD"}, "rabbitmq": {"RABBITMQ_DEFAULT_USER", "RABBITMQ_DEFAULT_PASS"}, "openlitespeed": {"CLOUDSTACK_ADMIN_PASSWORD"}}[metadata.TemplateID]
		if len(fields) == 0 {
			respond(w, 409, map[string]string{"error": "该模板不提供生成的账号凭据"})
			return
		}
		out, e := composeCommand(r.Context(), composeArgs(metadata, dir, "config", "--format", "json")...)
		if e != nil {
			respond(w, 409, map[string]string{"error": "配置读取失败"})
			return
		}
		var cfg struct {
			Services map[string]struct {
				Environment map[string]string `json:"environment"`
			} `json:"services"`
		}
		if json.Unmarshal([]byte(out), &cfg) != nil {
			respond(w, 409, map[string]string{"error": "配置解析失败"})
			return
		}
		secrets := map[string]string{}
		for _, service := range cfg.Services {
			for _, field := range fields {
				if value := service.Environment[field]; value != "" {
					secrets[field] = value
				}
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		respond(w, 200, map[string]any{"project_id": metadata.ID, "template_id": metadata.TemplateID, "host_port": metadata.HostPort, "credentials": secrets, "note": "只绑定回环地址；使用 SSH 隧道访问。双端口应用的辅助端口为主端口 + 1。"})
	})
	m.HandleFunc("GET /v1/docker/projects", func(w http.ResponseWriter, r *http.Request) {
		projects, e := listComposeProjects(r.Context())
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]any{"projects": projects})
	})
	m.HandleFunc("GET /v1/docker/projects/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		logs, e := composeLogs(r.Context(), r.PathValue("id"))
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, map[string]string{"logs": logs})
	})
	m.HandleFunc("POST /v1/docker/projects/jobs", func(w http.ResponseWriter, r *http.Request) {
		var op composeProjectRequest
		if !readJSON(w, r, &op) {
			return
		}
		if e := validateComposeRequest(op); e != nil {
			respond(w, 400, map[string]string{"error": e.Error()})
			return
		}
		if e := os.MkdirAll(dockerJobs, 0700); e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		if e := writeExclusiveJSON(filepath.Join(dockerJobs, op.JobID+".compose.request.json"), op); e != nil {
			respond(w, 409, map[string]string{"error": "Compose 作业标识已存在"})
			return
		}
		queued := core.DockerJobResult{JobID: op.JobID, Kind: "compose", State: "queued", ProjectID: op.ProjectID}
		if e := writeJSON(filepath.Join(dockerJobs, op.JobID+".result.json"), queued); e != nil {
			_ = os.Remove(filepath.Join(dockerJobs, op.JobID+".compose.request.json"))
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		if _, e := s.Config.Run(r.Context(), "/usr/bin/systemctl", "start", "--no-block", "panel-compose-job@"+op.JobID+".service"); e != nil {
			respond(w, 500, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 202, queued)
	})
}
