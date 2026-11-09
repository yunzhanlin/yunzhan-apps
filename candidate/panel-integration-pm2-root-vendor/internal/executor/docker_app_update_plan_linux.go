//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"local/panel/internal/core"
)

type composeUpdateDockerRead func(context.Context, string, any) error
type composeUpdatePort struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}
type memcachedUpdateInspection struct {
	ID     string `json:"Id"`
	Image  string `json:"Image"`
	Config *struct {
		Image       string            `json:"Image"`
		User        string            `json:"User"`
		WorkingDir  string            `json:"WorkingDir"`
		Cmd         []string          `json:"Cmd"`
		Entrypoint  []string          `json:"Entrypoint"`
		Env         []string          `json:"Env"`
		Labels      map[string]string `json:"Labels"`
		Healthcheck *struct {
			Test        []string `json:"Test"`
			Interval    int64    `json:"Interval"`
			Timeout     int64    `json:"Timeout"`
			StartPeriod int64    `json:"StartPeriod"`
			Retries     int      `json:"Retries"`
		} `json:"Healthcheck"`
	} `json:"Config"`
	State *struct {
		Running *bool `json:"Running"`
		Health  *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	HostConfig *struct {
		Privileged        *bool                          `json:"Privileged"`
		ReadonlyRootfs    *bool                          `json:"ReadonlyRootfs"`
		PidMode           string                         `json:"PidMode"`
		IpcMode           string                         `json:"IpcMode"`
		UTSMode           string                         `json:"UTSMode"`
		UsernsMode        string                         `json:"UsernsMode"`
		NetworkMode       string                         `json:"NetworkMode"`
		CapAdd            []string                       `json:"CapAdd"`
		CapDrop           []string                       `json:"CapDrop"`
		SecurityOpt       []string                       `json:"SecurityOpt"`
		Binds             []string                       `json:"Binds"`
		VolumesFrom       []string                       `json:"VolumesFrom"`
		DeviceCgroupRules []string                       `json:"DeviceCgroupRules"`
		Devices           []json.RawMessage              `json:"Devices"`
		Mounts            []json.RawMessage              `json:"Mounts"`
		Tmpfs             map[string]string              `json:"Tmpfs"`
		Sysctls           map[string]string              `json:"Sysctls"`
		PortBindings      map[string][]composeUpdatePort `json:"PortBindings"`
		RestartPolicy     struct {
			Name              string `json:"Name"`
			MaximumRetryCount int    `json:"MaximumRetryCount"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	NetworkSettings *struct {
		Ports    map[string][]composeUpdatePort `json:"Ports"`
		Networks map[string]json.RawMessage     `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []json.RawMessage `json:"Mounts"`
}

func decodeComposeUpdateMetadata(raw []byte, id string) (composeMetadata, error) {
	var m composeMetadata
	allowed := map[string]bool{"id": true, "name": true, "engine_name": true, "template_id": true, "host_port": true, "services": true, "created_at": true}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, e := d.Token()
	if e != nil || start != json.Delim('{') {
		return m, errors.New("原项目元数据不是闭合对象")
	}
	seen := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		name, ok := key.(string)
		if e != nil || !ok || !allowed[name] || seen[name] {
			return m, errors.New("原项目元数据含重复、别名或未知字段")
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return m, errors.New("原项目元数据值无效")
		}
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') || len(seen) != len(allowed) {
		return m, errors.New("原项目元数据字段集合不完整")
	}
	if _, e = d.Token(); e != io.EOF {
		return m, errors.New("原项目元数据有多余内容")
	}
	if json.Unmarshal(raw, &m) != nil || m.ID != id || !core.ValidID(id) || m.Engine != "panel_"+id[:12] || m.TemplateID != "memcached-cache" || !dockerResourceNamePattern.MatchString(m.Name) || m.Services != 1 || m.HostPort < 1024 || m.HostPort > 65535 {
		return m, errors.New("原项目不是单服务 Memcached 受管模板")
	}
	if _, e = time.Parse(time.RFC3339, m.CreatedAt); e != nil {
		return m, errors.New("原项目创建身份无效")
	}
	return m, nil
}

func memcachedUpdateRuntime(raw []byte, m composeMetadata, readImage func(string, any) error) (memcachedUpdateInspection, string, error) {
	return memcachedUpdateRuntimeState(raw, m, readImage, true)
}

// Only an original transaction's bounded restoration observes failed health.
// It still requires the same fixed command, image, service and security shape;
// it is not a general permission to adopt or replace an unhealthy container.
func memcachedUpdateRuntimeState(raw []byte, m composeMetadata, readImage func(string, any) error, healthy bool) (memcachedUpdateInspection, string, error) {
	var v memcachedUpdateInspection
	refuse := func() (memcachedUpdateInspection, string, error) {
		return memcachedUpdateInspection{}, "", errors.New("原容器身份、健康状态、运行配置或安全边界偏离受管模板；未提交更新")
	}
	if memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &v) != nil || len(v.ID) != 64 || !dockerObjectPattern.MatchString(v.ID) || v.Config == nil || v.State == nil || v.State.Running == nil || healthy && (!*v.State.Running || v.State.Health == nil || v.State.Health.Status != "healthy") || v.HostConfig == nil || v.NetworkSettings == nil {
		return refuse()
	}
	c, h, n := v.Config, v.HostConfig, v.NetworkSettings
	if c.Labels["com.docker.compose.project"] != m.Engine || c.Labels["com.docker.compose.service"] != "memcached" || c.Labels["com.docker.compose.oneoff"] != "False" ||
		c.User != "memcache" || !slices.Equal(c.Cmd, []string{"memcached", "-m", "128", "-I", "4m"}) || !slices.Equal(c.Entrypoint, []string{"docker-entrypoint.sh"}) ||
		h.Privileged == nil || *h.Privileged || h.ReadonlyRootfs == nil || *h.ReadonlyRootfs || h.PidMode != "" || h.IpcMode != "private" || h.UTSMode != "" || h.UsernsMode != "" || h.NetworkMode != m.Engine+"_default" ||
		len(h.CapAdd)+len(h.CapDrop)+len(h.SecurityOpt)+len(h.Binds)+len(h.VolumesFrom)+len(h.DeviceCgroupRules)+len(h.Devices)+len(h.Mounts)+len(h.Tmpfs)+len(h.Sysctls)+len(v.Mounts) != 0 ||
		h.RestartPolicy.Name != "unless-stopped" || h.RestartPolicy.MaximumRetryCount != 0 || len(n.Networks) != 1 {
		return refuse()
	}
	if _, ok := n.Networks[m.Engine+"_default"]; !ok {
		return refuse()
	}
	for _, ports := range []map[string][]composeUpdatePort{h.PortBindings, n.Ports} {
		if !healthy && !*v.State.Running && len(ports) == 0 && len(h.PortBindings) != 0 {
			// A stopped, otherwise exact owned service has no live NAT ports.
			// Its configured HostConfig binding must still be exact below.
			continue
		}
		p := ports["11211/tcp"]
		if len(ports) != 1 || len(p) != 1 || p[0].HostIP != "127.0.0.1" || p[0].HostPort != strconv.Itoa(m.HostPort) {
			return refuse()
		}
	}
	health := c.Healthcheck
	if health == nil || !slices.Equal(health.Test, []string{"CMD-SHELL", core.MemcachedHealthCommand}) || health.Interval != int64(10*time.Second) || health.Timeout != int64(3*time.Second) || health.StartPeriod != 0 || health.Retries != 12 {
		return refuse()
	}
	// Docker-local image identities are opaque, not assumed equal to an OCI
	// index/config/manifest digest. Bind exactly what the daemon observed.
	if len(v.Image) != 71 || v.Image[:7] != "sha256:" || !dockerObjectPattern.MatchString(v.Image[7:]) {
		return refuse()
	}
	var image struct {
		ID     string `json:"Id"`
		Config *struct {
			Env        []string `json:"Env"`
			User       string   `json:"User"`
			Entrypoint []string `json:"Entrypoint"`
			WorkingDir string   `json:"WorkingDir"`
		} `json:"Config"`
	}
	if readImage(v.Image, &image) != nil || image.ID != v.Image || image.Config == nil || image.Config.User != c.User || image.Config.WorkingDir != c.WorkingDir || !slices.Equal(image.Config.Env, c.Env) || !slices.Equal(image.Config.Entrypoint, c.Entrypoint) {
		return refuse()
	}
	// Hash full static runtime configuration, including fields this release
	// does not otherwise interpret. Never return credentials/environment or
	// raw Docker inspection. Exclude changing health logs/timestamps only.
	var all map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&all) != nil {
		return refuse()
	}
	identity, e := json.Marshal(map[string]any{"config": all["Config"], "host_config": all["HostConfig"], "network_settings": all["NetworkSettings"], "mounts": all["Mounts"]})
	if e != nil {
		return refuse()
	}
	return v, core.Hash(string(identity)), nil
}

func memcachedAppUpdatePlanAt(ctx context.Context, base, id string, read composeUpdateDockerRead) (core.MemcachedUpdatePlan, error) {
	return memcachedAppUpdatePlanBound(ctx, base, id, read, true)
}

// Only after this original transaction retained its opaque old image and made
// its ONE signed pull may it stop depending on the mutable source tag. Public
// previews/admission always resolve that tag; all other old bindings stay exact.
func memcachedAppUpdatePlanBound(ctx context.Context, base, id string, read composeUpdateDockerRead, sourceReference bool) (core.MemcachedUpdatePlan, error) {
	var empty core.MemcachedUpdatePlan
	if ctx == nil || read == nil {
		return empty, errMemcachedApply
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	d, err := openComposeUpdateDirectory(base, id)
	if err != nil {
		return empty, err
	}
	defer d.Close()
	metadata, metadataInfo, err := d.read("metadata.json", 16*1024)
	if err != nil {
		return empty, err
	}
	source, sourceInfo, err := d.read("compose.yaml", 48*1024)
	if err != nil {
		return empty, err
	}
	m, err := decodeComposeUpdateMetadata(metadata, id)
	if err != nil {
		return empty, err
	}
	filters, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + m.Engine}})
	var containers []struct {
		ID string `json:"Id"`
	}
	if read == nil || read(ctx, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), &containers) != nil || len(containers) != 1 || len(containers[0].ID) != 64 || !dockerObjectPattern.MatchString(containers[0].ID) {
		return empty, errors.New("原项目容器清单不唯一或无法核对，未提交更新")
	}
	var raw json.RawMessage
	if read(ctx, "/containers/"+containers[0].ID+"/json", &raw) != nil {
		return empty, errors.New("原项目容器身份暂不可确认")
	}
	v, runtimeSHA, err := memcachedUpdateRuntime(raw, m, func(image string, out any) error { return read(ctx, "/images/"+url.PathEscape(image)+"/json", out) })
	if err != nil {
		return empty, err
	}
	if v.ID != containers[0].ID {
		return empty, errors.New("原项目容器读取期间身份变化")
	}
	plan, err := core.MemcachedComposeUpdatePlan(id, core.Hash(string(metadata)), source, m.HostPort, v.ID, v.Image, runtimeSHA)
	if err != nil {
		return empty, err
	}
	if v.Config.Image != plan.CurrentImage {
		return empty, errors.New("原容器镜像声明与原项目配置不一致")
	}
	// A rollback of the original YAML must not resolve a moved old tag to a
	// different local image. This readonly check is a precondition, not image
	// retention: a future worker must repeat it under the original EX lease,
	// retain that exact opaque image ID and use --pull never on rollback.
	if sourceReference {
		var tagged json.RawMessage
		if read(ctx, "/images/"+url.PathEscape(plan.CurrentImage)+"/json", &tagged) != nil || len(tagged) == 0 || len(tagged) > 1<<20 {
			return empty, errors.New("原镜像声明暂不可解析；不能保证按原配置回滚，未提交更新")
		}
		fields, tagErr := dockerPullJSONObject(tagged)
		tagID, validTagID := dockerPullJSONString(fields["Id"])
		if tagErr != nil || !validTagID || tagID != v.Image {
			return empty, errors.New("原镜像声明已偏离运行中的镜像身份；保留原容器，未提交更新")
		}
	}
	metadataAfter, mi, me := d.read("metadata.json", 16*1024)
	sourceAfter, si, se := d.read("compose.yaml", 48*1024)
	if me != nil || se != nil || !sameComposeUpdateFile(metadataInfo, mi) || !sameComposeUpdateFile(sourceInfo, si) || !bytes.Equal(metadata, metadataAfter) || !bytes.Equal(source, sourceAfter) || !d.current() {
		return empty, errors.New("预检期间原项目配置或目录身份变化")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return plan, core.ValidateMemcachedUpdatePlan(plan, id)
}

func (s *Service) memcachedAppUpdatePlanRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/docker/projects/{id}/app-update-plan", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		read := func(ctx context.Context, path string, out any) error {
			_, err := dockerRequest(ctx, http.MethodGet, path, nil, out, 1024*1024)
			return err
		}
		plan, err := memcachedAppUpdatePlanAt(ctx, dockerProjects, r.PathValue("id"), read)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		respond(w, 200, plan)
	})
}
