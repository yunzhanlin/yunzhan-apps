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
	ID                  string                `json:"id"`
	StateKnown          bool                  `json:"state_known"`
	Installed           bool                  `json:"installed"`
	Healthy             bool                  `json:"healthy"`
	Detail              string                `json:"detail"`
	Supported           bool                  `json:"supported"`
	CompatibilityDetail string                `json:"compatibility_detail,omitempty"`
	InstalledVersion    string                `json:"installed_version,omitempty"`
	LatestVersion       string                `json:"latest_version"`
	VersionKnown        bool                  `json:"version_known"`
	UpdateAvailable     bool                  `json:"update_available"`
	UpdateSupported     bool                  `json:"update_supported"`
	UpdateKind          string                `json:"update_kind,omitempty"`
	UpdateDetail        string                `json:"update_detail,omitempty"`
	Instances           []AppRegistryInstance `json:"instances,omitempty"`
}

type AppRegistryInstance struct {
	ID              string `json:"id"`
	Version         string `json:"version,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
}

type AppRegistryPage struct {
	Catalog appcatalog.Catalog  `json:"catalog"`
	Status  []AppRegistryStatus `json:"status"`
	Source  appcatalog.LoadInfo `json:"source"`
	Host    AppRegistryHost     `json:"host"`
}

type AppRegistryHost struct {
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

func registrySupportOn(app appcatalog.CatalogItem, platform, arch string) (bool, string) {
	supportedOS := platform == "debian-12" || platform == "debian-13" || platform == "ubuntu-22.04" || platform == "ubuntu-24.04" || platform == "ubuntu-26.04"
	if !supportedOS || (arch != "amd64" && arch != "arm64") {
		return false, "当前系统不在 Debian 12/13、Ubuntu 22.04/24.04/26.04 的 64 位支持范围内"
	}
	if app.Stage != "ready" {
		return false, "该应用尚未完成安装器接入"
	}
	switch app.Provider {
	case "compose":
		if !IsDockerTemplate(app.Target) {
			return false, "当前面板没有该应用的受限安装器"
		}
		if arch == "arm64" {
			if _, legacy := LegacyPHPImages[app.Target]; legacy {
				return false, "固定应用镜像仅支持 x86_64；ARM64 不启用模拟运行"
			}
		}
	case "runtime":
		if app.Target == "docker-auto" {
			_, ok := runtimecatalog.DockerSpecOn(platform)
			return ok, ""
		}
		if _, ok := runtimecatalog.Find(app.Target); !ok {
			return false, "当前系统或架构没有该运行时的已审核安装源"
		}
	case "panel-module":
		if _, ok := FindAppModule(app.Target); !ok && app.Target != "nginx-waf" && app.Target != "system-hardening" && app.Target != "intrusion-prevention" {
			return false, "当前面板没有该功能处理器"
		}
		if app.Version != "" && ValidateSoftwareUpdate(app.Target, app.Version) != nil {
			return false, "新版应用需要先升级面板的受限功能处理器"
		}
	default:
		return false, "不支持该应用处理器"
	}
	return true, ""
}

func (a *Server) appRegistryCacheDir() string {
	return filepath.Join(a.Config.DataDir, "app-registry")
}

func (a *Server) loadAppCatalog(ctxTimeout time.Duration, r *http.Request) (appcatalog.Catalog, appcatalog.LoadInfo, error) {
	ctx, cancel := contextWithTimeout(r.Context(), ctxTimeout)
	defer cancel()
	maxAge := 5 * time.Minute
	if r.URL.Query().Get("refresh") == "1" {
		maxAge = 0
	}
	return a.AppCatalog.LoadCatalog(ctx, filepath.Join(a.appRegistryCacheDir(), "catalog"), maxAge)
}

// contextWithTimeout is a small seam for tests and keeps every GitHub request bounded.
var contextWithTimeout = func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

func (a *Server) appRegistryStatuses(ctx context.Context, catalog appcatalog.Catalog) []AppRegistryStatus {
	var receiptErr error
	receipts := map[string]registryReceipt{}
	if a.Store != nil {
		receiptErr = a.reconcileRegistryReceipts(ctx)
		var readErr error
		receipts, readErr = a.Store.registryReceipts()
		if readErr != nil {
			receiptErr = readErr
		}
	}
	installedRuntime := map[string]bool{}
	runtimeVersions := map[string]string{}
	var runtimes struct {
		Installed []struct {
			ID      string `json:"id"`
			Family  string `json:"family"`
			Status  string `json:"status"`
			Version string `json:"version"`
		} `json:"installed"`
	}
	software := map[string]SoftwareAppStatus{}
	var softwareRows []SoftwareAppStatus
	compose := map[string]bool{}
	composeHealthy := map[string]bool{}
	var projects struct {
		Projects []struct {
			ID         string   `json:"id"`
			TemplateID string   `json:"template_id"`
			State      string   `json:"state"`
			Services   int      `json:"services"`
			Running    int      `json:"running"`
			Healthy    int      `json:"healthy"`
			Images     []string `json:"images"`
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
				runtimeVersions[item.ID] = item.Version
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
		supported, compatibilityDetail := registrySupportOn(app, runtimecatalog.HostPlatform(), runtime.GOARCH)
		status := AppRegistryStatus{ID: app.ID, StateKnown: true, Detail: "未安装", Supported: supported, CompatibilityDetail: compatibilityDetail, LatestVersion: app.Version}
		if app.Stage != "ready" {
			status.Detail = map[string]string{"integration": "正在接入安装器", "design": "功能实现中"}[app.Stage]
			out = append(out, status)
			continue
		}
		switch app.Provider {
		case "runtime":
			status.StateKnown = runtimeErr == nil
			family := map[string]string{"nginx": "nginx", "apache": "apache", "mysql": "mysql", "redis": "redis", "docker-manager": "docker"}[app.ID]
			if strings.HasPrefix(app.ID, "php-") {
				family = "php"
			}
			for _, row := range runtimes.Installed {
				if row.Status != "installed" || (row.ID != app.Target && (family == "" || row.Family != family)) {
					continue
				}
				if family == "php" && !strings.HasPrefix(row.Version, versionBranch(app.Version)+".") {
					continue
				}
				status.Installed = true
				version := runtimeVersions[row.ID]
				if receipt, ok := receipts[app.ID+":"+row.ID]; ok && (receipt.Target == row.ID || app.Target == "docker-auto") {
					version = receipt.Version
				}
				if cmp, ok := appcatalog.CompareVersions(version, status.InstalledVersion); status.InstalledVersion == "" || (ok && cmp > 0) {
					status.InstalledVersion = version
				}
			}
			status.VersionKnown = appcatalog.ValidVersion(status.InstalledVersion)
			status.Healthy = status.Installed
		case "panel-module":
			status.StateKnown = softwareErr == nil
			row := software[app.Target]
			status.Installed, status.Healthy = row.Installed, row.Healthy
			status.InstalledVersion = row.Version
			status.VersionKnown = status.Installed && appcatalog.ValidVersion(row.Version)
			if row.Detail != "" {
				status.Detail = row.Detail
			}
		case "compose":
			status.StateKnown = composeErr == nil
			status.Installed = compose[app.Target]
			status.Healthy = composeHealthy[app.Target]
			for _, project := range projects.Projects {
				if project.TemplateID != app.Target {
					continue
				}
				instance := AppRegistryInstance{ID: project.ID}
				instance.Version = registryImageVersion(app, project.Images)
				if receipt, ok := receipts[app.ID+":"+project.ID]; ok && receipt.Target == app.Target {
					instance.Version = receipt.Version
				}
				cmp, valid := appcatalog.CompareVersions(instance.Version, app.Version)
				instance.UpdateAvailable = valid && cmp < 0
				status.Instances = append(status.Instances, instance)
				status.UpdateAvailable = status.UpdateAvailable || instance.UpdateAvailable
			}
			if len(status.Instances) == 1 {
				status.InstalledVersion = status.Instances[0].Version
				status.VersionKnown = appcatalog.ValidVersion(status.InstalledVersion)
			}
		}
		if status.Installed && status.VersionKnown {
			cmp, valid := appcatalog.CompareVersions(status.InstalledVersion, app.Version)
			status.UpdateAvailable = status.UpdateAvailable || (valid && cmp < 0)
		}
		if !status.StateKnown {
			status.UpdateAvailable = false
		}
		if status.UpdateAvailable {
			switch app.Provider {
			case "panel-module":
				status.UpdateKind = "module"
				status.UpdateSupported = supported && ValidateSoftwareUpdate(app.Target, app.Version) == nil
				status.UpdateDetail = "新版功能由签名面板提供；更新保留配置、数据、基线和历史报告"
			case "runtime":
				status.UpdateKind = "runtime"
				status.UpdateSupported = supported
				status.UpdateDetail = "安装或核对已审核的运行时版本；不自动切换网站或迁移数据库"
			case "compose":
				status.UpdateKind = "compose-review"
				status.UpdateDetail = "请在 Docker 管理中逐项目核对镜像和数据迁移；不批量替换容器或重建数据卷"
			}
			if !status.UpdateSupported && app.Provider != "compose" {
				status.UpdateKind = "panel-upgrade"
				status.UpdateDetail = "仓库已有新版，但当前面板缺少已审核处理器，请先升级面板"
			}
		} else if status.Installed && !status.VersionKnown {
			status.UpdateDetail = "旧安装未记录应用包版本，不能据此判定已是最新版；请核对管理页"
		}
		if receiptErr != nil {
			status.UpdateSupported = false
			status.UpdateDetail = "应用版本记录读取失败，请稍后重试"
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

func versionBranch(version string) string {
	parts := strings.Split(strings.SplitN(version, "-", 2)[0], ".")
	if len(parts) >= 2 {
		return strings.Join(parts[:2], ".")
	}
	return version
}

func registryImageVersion(app appcatalog.CatalogItem, images []string) string {
	prefix := map[string]string{"memcached": "memcached:", "phpmyadmin": "phpmyadmin:", "mongodb": "mongo:", "elasticsearch": "docker.elastic.co/elasticsearch/elasticsearch:", "rabbitmq": "rabbitmq:", "openlitespeed": "litespeedtech/openlitespeed:"}[app.ID]
	if strings.HasPrefix(app.ID, "php-") {
		prefix = "devilbox/php-fpm:"
	}
	if prefix == "" {
		return ""
	}
	for _, image := range images {
		if !strings.HasPrefix(image, prefix) {
			continue
		}
		version := strings.SplitN(strings.TrimPrefix(image, prefix), "@", 2)[0]
		version = strings.SplitN(version, "-", 2)[0]
		// Floating major/minor tags cannot prove an exact installed version.
		if len(strings.Split(version, ".")) < 3 {
			return ""
		}
		if appcatalog.ValidVersion(version) {
			return version
		}
	}
	return ""
}

func (a *Server) installRegistryApp(w http.ResponseWriter, r *http.Request, u identity) {
	var in struct {
		Settings        map[string]any `json:"settings"`
		Name            string         `json:"name"`
		HostPort        int            `json:"host_port"`
		ExpectedVersion string         `json:"expected_version"`
		ExpectedSHA256  string         `json:"expected_sha256"`
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
	if (in.ExpectedVersion != "" && in.ExpectedVersion != item.Version) || (in.ExpectedSHA256 != "" && in.ExpectedSHA256 != item.SHA256) {
		fail(w, 409, "应用目录已变化，请刷新后重试")
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
			releases := runtimecatalog.DockerReleaseOn(runtimecatalog.HostPlatform())
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
		if err = a.Store.trackRegistryJob(item, releaseID, job); err != nil {
			fail(w, 503, "任务已提交，但应用版本记录未保存，请核对任务")
			return
		}
		send(w, 202, map[string]any{"job_id": job, "provider": "runtime", "target": releaseID})
	case "panel-module":
		_, moduleOK := FindAppModule(manifest.Delivery.Target)
		if !moduleOK && manifest.Delivery.Target != "nginx-waf" && manifest.Delivery.Target != "system-hardening" && manifest.Delivery.Target != "intrusion-prevention" {
			fail(w, 409, "当前面板版本尚未提供该功能处理器")
			return
		}
		if err = ValidateSoftwareUpdate(manifest.Delivery.Target, manifest.Version); err != nil {
			fail(w, 409, err.Error())
			return
		}
		job, err := a.Store.QueueSoftwareAction(manifest.Delivery.Target, "install", in.Settings, r.Header.Get("Idempotency-Key"), u.Username)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		if err = a.Store.trackRegistryJob(item, manifest.Delivery.Target, job); err != nil {
			fail(w, 503, "任务已提交，但应用版本记录未保存，请核对任务")
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
		if err = a.Store.trackRegistryJob(item, op.ProjectID, result.JobID); err != nil {
			fail(w, 503, "任务已提交，但应用版本记录未保存，请核对 Docker 任务")
			return
		}
		send(w, 202, result)
	default:
		fail(w, 409, "应用包处理器不受支持")
	}
}

func (a *Server) updateRegistryApp(w http.ResponseWriter, r *http.Request, u identity) {
	var in registryUpdateInput
	if !decode(w, r, &in) {
		return
	}
	key := r.Header.Get("Idempotency-Key")
	replay := func() bool {
		prior, found, err := a.Store.registryUpdateReplay(r.PathValue("id"), u.ID, key, in)
		if err != nil {
			fail(w, 409, err.Error())
			return true
		}
		if found {
			send(w, 202, map[string]string{"job_id": prior.JobID, "provider": prior.Provider})
			return true
		}
		return false
	}
	if replay() {
		return
	}
	q := r.URL.Query()
	q.Set("refresh", "1")
	r.URL.RawQuery = q.Encode()
	catalog, source, err := a.loadAppCatalog(15*time.Second, r)
	if err != nil || source.Stale {
		if replay() {
			return
		}
		fail(w, 503, "无法确认仓库最新版本，未执行更新")
		return
	}
	item, ok := appcatalog.Find(catalog, r.PathValue("id"))
	if !ok {
		if replay() {
			return
		}
		fail(w, 404, "应用不在签名目录中")
		return
	}
	if in.ExpectedVersion != item.Version || in.ExpectedSHA256 != item.SHA256 {
		if replay() {
			return
		}
		fail(w, 409, "应用目录已变化，请刷新后重试")
		return
	}
	ctx, cancel := contextWithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var status AppRegistryStatus
	for _, row := range a.appRegistryStatuses(ctx, catalog) {
		if row.ID == item.ID {
			status = row
		}
	}
	if !status.StateKnown || !status.Installed || !status.UpdateAvailable || !status.UpdateSupported {
		// The first request may commit and finish after our initial lookup.
		if replay() {
			return
		}
		fail(w, 409, "当前应用不能自动更新: "+status.UpdateDetail)
		return
	}
	manifest, err := a.AppCatalog.FetchManifest(ctx, item, filepath.Join(a.appRegistryCacheDir(), "packages"))
	if err != nil {
		if replay() {
			return
		}
		fail(w, 409, err.Error())
		return
	}
	if err = appCompatible(manifest); err != nil {
		if replay() {
			return
		}
		fail(w, 409, err.Error())
		return
	}
	job, scope := "", manifest.Delivery.Target
	switch manifest.Delivery.Provider {
	case "panel-module":
		job, err = a.Store.queueSoftwareActionBound(scope, "update", nil, manifest.Version, key, u.Username, a.Store.bindRegistryUpdate(item, scope, key, u.ID))
	case "runtime":
		if scope == "docker-auto" {
			releases := runtimecatalog.DockerReleaseOn(runtimecatalog.HostPlatform())
			if len(releases) != 1 {
				fail(w, 409, "没有已审核的 Docker 版本")
				return
			}
			scope = releases[0].ID
		}
		job, err = a.Store.queueInstallBound(scope, key, u.Username, a.Store.bindRegistryUpdate(item, scope, key, u.ID))
	default:
		fail(w, 409, "该类型暂不允许自动替换，请核对项目与迁移方案")
		return
	}
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	_ = a.Store.Audit(u.Username, "app-registry.update", item.ID+"@"+item.Version, "verified-and-queued")
	send(w, 202, map[string]string{"job_id": job, "provider": item.Provider})
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
		send(w, 200, AppRegistryPage{Catalog: catalog, Status: a.appRegistryStatuses(ctx, catalog), Source: source, Host: AppRegistryHost{Platform: runtimecatalog.HostPlatform(), Architecture: runtime.GOARCH}})
	}))
	m.HandleFunc("POST /api/app-registry/{id}/install", a.authorize(a.installRegistryApp))
	m.HandleFunc("POST /api/app-registry/{id}/update", a.authorize(a.updateRegistryApp))
}

func appCompatible(manifest appcatalog.Manifest) error {
	return appCompatibleOn(manifest, runtimecatalog.HostPlatform(), runtime.GOARCH)
}

func appCompatibleOn(manifest appcatalog.Manifest, osID, architecture string) error {
	if manifest.Risk == "eol" {
		image, ok := LegacyPHPImages[manifest.Delivery.Target]
		if !ok || manifest.ID != strings.Replace(manifest.Delivery.Target, "php-legacy-", "php-", 1) || manifest.Delivery.Provider != "compose" || manifest.Delivery.Isolation != "legacy-container" || manifest.Delivery.Image != image {
			return errors.New("旧版 PHP 必须使用本机允许列表中的固定摘要隔离环境")
		}
	}
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
