package core

import (
	"context"
	"errors"
	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type AppRegistryStatus struct {
	ID         string `json:"id"`
	StateKnown bool   `json:"state_known"`
	Installed  bool   `json:"installed"`
	Healthy    bool   `json:"healthy"`
	Detail     string `json:"detail"`
}

type AppRegistryPage struct {
	Catalog appcatalog.Catalog  `json:"catalog"`
	Status  []AppRegistryStatus `json:"status"`
	Source  appcatalog.LoadInfo `json:"source"`
}

func (a *Server) appRegistryCacheDir() string {
	return filepath.Join(a.Config.DataDir, "app-registry")
}

func (a *Server) loadAppCatalog(ctxTimeout time.Duration, r *http.Request) (appcatalog.Catalog, appcatalog.LoadInfo, error) {
	ctx, cancel := contextWithTimeout(r.Context(), ctxTimeout)
	defer cancel()
	return a.AppCatalog.LoadCatalog(ctx, filepath.Join(a.appRegistryCacheDir(), "catalog"), 15*time.Minute)
}

// contextWithTimeout is a small seam for tests and keeps every GitHub request bounded.
var contextWithTimeout = func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

func (a *Server) appRegistryStatuses(ctx context.Context, catalog appcatalog.Catalog) []AppRegistryStatus {
	installedRuntime := map[string]bool{}
	var runtimes struct {
		Installed []struct {
			ID     string `json:"id"`
			Family string `json:"family"`
			Status string `json:"status"`
		} `json:"installed"`
	}
	software := map[string]SoftwareAppStatus{}
	var softwareRows []SoftwareAppStatus
	compose := map[string]bool{}
	composeHealthy := map[string]bool{}
	var projects struct {
		Projects []struct {
			TemplateID string `json:"template_id"`
			State      string `json:"state"`
			Services   int    `json:"services"`
			Running    int    `json:"running"`
			Healthy    int    `json:"healthy"`
		} `json:"projects"`
	}
	// Independent probes must not inherit time already spent by a slow earlier probe.
	var runtimeErr, softwareErr, composeErr error
	var probes sync.WaitGroup
	probes.Add(3)
	go func() {
		defer probes.Done()
		runtimeErr = a.Executor.Call(ctx, http.MethodGet, "/v1/runtimes", nil, &runtimes)
	}()
	go func() {
		defer probes.Done()
		softwareErr = a.Executor.Call(ctx, http.MethodGet, "/v1/software", nil, &softwareRows)
	}()
	go func() {
		defer probes.Done()
		composeErr = a.Executor.Call(ctx, http.MethodGet, "/v1/docker/projects", nil, &projects)
	}()
	probes.Wait()
	if runtimeErr == nil {
		for _, item := range runtimes.Installed {
			if item.Status == "installed" {
				installedRuntime[item.ID] = true
				if item.Family != "" {
					installedRuntime["family:"+item.Family] = true
				}
			}
		}
	}
	if softwareErr == nil {
		for _, item := range softwareRows {
			software[item.ID] = item
		}
	}
	if composeErr == nil {
		for _, project := range projects.Projects {
			if project.TemplateID != "" {
				compose[project.TemplateID] = true
				if project.State == "running" && project.Services > 0 && project.Running == project.Services && project.Healthy == project.Services {
					composeHealthy[project.TemplateID] = true
				}
			}
		}
	}
	out := make([]AppRegistryStatus, 0, len(catalog.Apps))
	for _, app := range catalog.Apps {
		status := AppRegistryStatus{ID: app.ID, StateKnown: true, Detail: "未安装"}
		if app.Stage != "ready" {
			status.Detail = map[string]string{"integration": "正在接入安装器", "design": "功能实现中"}[app.Stage]
			out = append(out, status)
			continue
		}
		switch app.Provider {
		case "runtime":
			status.StateKnown = runtimeErr == nil
			if app.Target == "docker-auto" {
				status.Installed = installedRuntime["family:docker"]
			} else {
				status.Installed = installedRuntime[app.Target]
			}
			status.Healthy = status.Installed
		case "panel-module":
			status.StateKnown = softwareErr == nil
			row := software[app.Target]
			status.Installed, status.Healthy = row.Installed, row.Healthy
			if row.Detail != "" {
				status.Detail = row.Detail
			}
		case "compose":
			status.StateKnown = composeErr == nil
			status.Installed = compose[app.Target]
			status.Healthy = composeHealthy[app.Target]
		}
		if !status.StateKnown {
			status.Detail = "状态暂未确认，请刷新；不会据此重复安装"
		}
		if status.Installed && status.Detail == "未安装" {
			if status.Healthy {
				status.Detail = "已安装且健康探针通过"
			} else {
				status.Detail = "已安装，需要核对运行状态"
			}
		}
		out = append(out, status)
	}
	return out
}

func (a *Server) installRegistryApp(w http.ResponseWriter, r *http.Request, u identity) {
	var in struct {
		Settings map[string]any `json:"settings"`
		Name     string         `json:"name"`
		HostPort int            `json:"host_port"`
	}
	if !decode(w, r, &in) {
		return
	}
	catalog, _, err := a.loadAppCatalog(15*time.Second, r)
	if err != nil {
		fail(w, 503, err.Error())
		return
	}
	item, ok := appcatalog.Find(catalog, strings.TrimSpace(r.PathValue("id")))
	if !ok {
		fail(w, 404, "应用不在已签名目录中")
		return
	}
	ctx, cancel := contextWithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	manifest, err := a.AppCatalog.FetchManifest(ctx, item, filepath.Join(a.appRegistryCacheDir(), "packages"))
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	if err = appCompatible(manifest); err != nil {
		fail(w, 409, err.Error())
		return
	}
	_ = a.Store.Audit(u.Username, "app-registry.pull", manifest.ID+"@"+manifest.Version, "verified")
	switch manifest.Delivery.Provider {
	case "runtime":
		releaseID := manifest.Delivery.Target
		if releaseID == "docker-auto" {
			releases := runtimecatalog.DockerReleaseOn(runtimecatalog.HostDebianMajor())
			if len(releases) != 1 {
				fail(w, 409, "当前系统没有已审核的 Docker 安装包")
				return
			}
			releaseID = releases[0].ID
		}
		if _, ok := runtimecatalog.Find(releaseID); !ok {
			fail(w, 409, "应用包引用的运行时未纳入本机允许列表")
			return
		}
		job, err := a.Store.QueueInstall(releaseID, r.Header.Get("Idempotency-Key"), u.Username)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 202, map[string]any{"job_id": job, "provider": "runtime", "target": releaseID})
	case "panel-module":
		_, moduleOK := FindAppModule(manifest.Delivery.Target)
		if !moduleOK && manifest.Delivery.Target != "nginx-waf" && manifest.Delivery.Target != "system-hardening" && manifest.Delivery.Target != "intrusion-prevention" {
			fail(w, 409, "当前面板版本尚未提供该功能处理器")
			return
		}
		job, err := a.Store.QueueSoftwareAction(manifest.Delivery.Target, "install", in.Settings, r.Header.Get("Idempotency-Key"), u.Username)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 202, map[string]any{"job_id": job, "provider": "panel-module", "target": manifest.Delivery.Target})
	case "compose":
		if !IsDockerTemplate(manifest.Delivery.Target) {
			fail(w, 409, "当前面板版本尚未提供该 Compose 处理器")
			return
		}
		if in.HostPort == 0 {
			in.HostPort = map[string]int{"memcached-cache": 21211, "phpmyadmin": 18080, "mongodb": 27017, "elasticsearch": 19200, "rabbitmq": 15672, "openlitespeed": 18888}[manifest.Delivery.Target]
			if in.HostPort == 0 {
				in.HostPort = 18080
			}
		}
		if strings.TrimSpace(in.Name) == "" {
			in.Name = manifest.Delivery.Target + "-" + ID()[:8]
		}
		compose, err := dockerTemplate(manifest.Delivery.Target, in.HostPort)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		op := DockerProjectRequest{JobID: ID(), ProjectID: ID(), Action: "create", Name: strings.TrimSpace(in.Name), Compose: compose, TemplateID: manifest.Delivery.Target}
		if err = ValidateDockerProject(op); err != nil {
			fail(w, 409, err.Error())
			return
		}
		var result DockerJobResult
		if err = a.Executor.Call(r.Context(), http.MethodPost, "/v1/docker/projects/jobs", op, &result); err != nil {
			fail(w, 409, err.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "app-registry.install", manifest.ID, "queued")
		send(w, 202, result)
	default:
		fail(w, 409, "应用包处理器不受支持")
	}
}

func (a *Server) appRegistryRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-registry", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		catalog, source, err := a.loadAppCatalog(15*time.Second, r)
		if err != nil {
			fail(w, 503, "加载已签名应用目录失败: "+err.Error())
			return
		}
		ctx, cancel := contextWithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		send(w, 200, AppRegistryPage{Catalog: catalog, Status: a.appRegistryStatuses(ctx, catalog), Source: source})
	}))
	m.HandleFunc("POST /api/app-registry/{id}/install", a.authorize(a.installRegistryApp))
}

func appCompatible(manifest appcatalog.Manifest) error {
	if manifest.Risk == "eol" {
		image, ok := LegacyPHPImages[manifest.Delivery.Target]
		if !ok || manifest.ID != strings.Replace(manifest.Delivery.Target, "php-legacy-", "php-", 1) || manifest.Delivery.Provider != "compose" || manifest.Delivery.Isolation != "legacy-container" || manifest.Delivery.Image != image {
			return errors.New("旧版 PHP 必须使用本机允许列表中的固定摘要隔离环境")
		}
	}
	osID := "debian-" + runtimecatalog.HostDebianMajor()
	architecture := runtime.GOARCH
	foundOS, foundArch := false, false
	for _, item := range manifest.Compatibility.OS {
		foundOS = foundOS || item == osID
	}
	for _, item := range manifest.Compatibility.Architectures {
		foundArch = foundArch || item == architecture
	}
	if !foundOS || !foundArch {
		return errors.New("该应用包不支持当前系统或 CPU 架构")
	}
	return nil
}
