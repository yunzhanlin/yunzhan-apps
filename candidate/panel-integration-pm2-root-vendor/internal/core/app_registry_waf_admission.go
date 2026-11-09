package core

import "local/panel/internal/appcatalog"

// The executor's historical WAF migration already requires the original
// installed render and loaded fingerprint to be healthy. Reflect that same
// prerequisite before the store can enqueue an inevitably refused migration.
// This is presentation/admission only: never repair files, grant a new handler,
// change installed versions, reset failed jobs or acknowledge an unknown render.
func applyRegistryWAFConfigurationReview(status *AppRegistryStatus, app appcatalog.CatalogItem) {
	if status == nil || app.ID != "nginx-waf" || app.Target != "nginx-waf" || app.Provider != "panel-module" || app.Stage != "ready" || app.Version != WAFVersion ||
		status.ID != app.ID || status.LatestVersion != app.Version || !status.Supported || !status.StateKnown || !status.Installed || !status.VersionKnown || status.Healthy || !status.UpdateAvailable || !status.UpdateSupported || status.UpdateKind != "module" {
		return
	}
	if compared, valid := appcatalog.CompareVersions(status.InstalledVersion, app.Version); !valid || compared >= 0 {
		return
	}
	status.UpdateKind, status.UpdateSupported = "waf-config-review", false
	status.UpdateDetail = "旧版 WAF 的实际规则、网站配置或已加载指纹尚未核对通过；请先核对原配置，再进行版本迁移。未修改规则、重载服务或提交更新任务"
}
