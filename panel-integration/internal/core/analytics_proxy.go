package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// This value is generated from the panel's actual CLI listen address, never
// from a browser-supplied upstream or the externally accessible panel URL.
func ValidateAnalyticsEndpoint(value string) error {
	host, port, err := net.SplitHostPort(value)
	ip := net.ParseIP(host)
	n, pe := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || pe != nil || n < 1 || n > 65535 || net.JoinHostPort(host, strconv.Itoa(n)) != value {
		return errors.New("采集上游必须是明确的回环 IP 与有效端口")
	}
	return nil
}

func analyticsConfigInTx(tx *sql.Tx, id string) (AnalyticsConfig, error) {
	v := AnalyticsConfig{SiteID: id, Retention: 30}
	err := tx.QueryRow(`SELECT public_key,enabled,clicks,retention,revision FROM analytics_config WHERE site_id=?`, id).Scan(&v.Key, &v.Enabled, &v.Clicks, &v.Retention, &v.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return v, nil
	}
	return v, err
}

func saveAnalyticsConfigTx(tx *sql.Tx, in AnalyticsConfig) (AnalyticsConfig, error) {
	if !ValidID(in.SiteID) || in.Retention < 1 || in.Retention > 90 || in.Revision < 0 {
		return in, errors.New("统计配置参数无效")
	}
	old, err := analyticsConfigInTx(tx, in.SiteID)
	if err != nil {
		return in, err
	}
	if old.Revision != in.Revision {
		return in, errors.New("配置已改变，请刷新后重试")
	}
	in.Key = old.Key
	if in.Key == "" {
		in.Key = ID()
	}
	in.Revision++
	_, err = tx.Exec(`INSERT INTO analytics_config VALUES(?,?,?,?,?,?) ON CONFLICT(site_id) DO UPDATE SET enabled=excluded.enabled,clicks=excluded.clicks,retention=excluded.retention,revision=excluded.revision`, in.SiteID, in.Key, in.Enabled, in.Clicks, in.Retention, in.Revision)
	return in, err
}

func sameAnalyticsRequest(a, b AnalyticsConfig) bool {
	if a.AutoInjectHTML != nil {
		wanted := b.AutoInjectHTML != nil && *b.AutoInjectHTML
		if *a.AutoInjectHTML != wanted {
			return false
		}
	}
	a.AutoInjectHTML, b.AutoInjectHTML = nil, nil
	a.Key = ""
	b.Key = ""
	a.ProxyEndpoint = ""
	b.ProxyEndpoint = ""
	return a == b
}

// Older managed sites can have different generated proof hashes after a
// renderer upgrade. Ignore only those exact metadata values, never arbitrary
// directives, health responses, or edits elsewhere in the server block.
func sameManagedAnalyticsBaseline(current, candidate, siteID string) bool {
	maskHash := func(line, prefix, suffix string) string {
		if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, suffix) {
			return line
		}
		hash := strings.TrimSuffix(strings.TrimPrefix(line, prefix), suffix)
		if len(hash) != 64 {
			return line
		}
		for _, c := range hash {
			if !strings.ContainsRune("0123456789abcdef", c) {
				return line
			}
		}
		return prefix + "<generated-proof>" + suffix
	}
	normalize := func(config string) string {
		lines := strings.Split(strings.TrimSpace(config), "\n")
		for i, line := range lines {
			line = maskHash(line, "  location = /__panel_health_"+siteID+` { default_type text/plain; access_log off; return 200 "panel:`+siteID+":", `"; }`)
			lines[i] = maskHash(line, `  add_header X-Panel-Config "`, `" always;`)
		}
		return strings.Join(lines, "\n")
	}
	return normalize(current) == normalize(candidate)
}

func (a *Server) configureAnalyticsProxy(w http.ResponseWriter, r *http.Request, u identity) {
	var in AnalyticsConfig
	if !decode(w, r, &in) {
		return
	}
	in.SiteID = r.PathValue("id")
	in.Key = ""
	in.ProxyEndpoint = ""
	site, err := a.Store.Site(in.SiteID)
	if err != nil {
		fail(w, 404, "网站不存在")
		return
	}
	if in.Retention < 1 || in.Retention > 90 || in.Revision < 0 {
		fail(w, 400, "保留天数为 1–90，版本必须有效")
		return
	}
	if in.AutoInjectHTML != nil && *in.AutoInjectHTML && !in.Enabled {
		fail(w, 400, "先开启浏览器采集，再启用 HTML 自动接入")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 {
		fail(w, 400, "请提供有效的配置幂等键")
		return
	}
	// A lost acknowledgement can be retried after the job has already committed.
	var oldID, oldSite, oldKind, payload string
	err = a.Store.DB.QueryRow(`SELECT id,site_id,kind,payload FROM jobs WHERE idempotency_key=?`, key).Scan(&oldID, &oldSite, &oldKind, &payload)
	if err == nil {
		var p JobPayload
		if json.Unmarshal([]byte(payload), &p) != nil || oldSite != in.SiteID || oldKind != "configure_site" || p.Analytics == nil || !sameAnalyticsRequest(in, *p.Analytics) {
			fail(w, 409, "幂等键已被不同请求使用")
			return
		}
		send(w, 202, map[string]string{"job_id": oldID})
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		fail(w, 500, "读取配置任务失败")
		return
	}
	var module struct {
		Status SoftwareAppStatus `json:"status"`
	}
	if err = a.Executor.Call(r.Context(), "GET", "/v1/app-modules/website-analytics", nil, &module); err != nil || !module.Status.Installed {
		fail(w, 409, "请先安装网站分析应用")
		return
	}
	if in.Enabled && site.Status != "running" {
		fail(w, 409, "请先启用网站，再开启浏览器采集")
		return
	}
	endpoint := a.Config.Listen
	if err = ValidateAnalyticsEndpoint(endpoint); err != nil {
		fail(w, 409, err.Error())
		return
	}
	settings := site.Settings
	if in.AutoInjectHTML != nil {
		settings.AnalyticsInjectHTML = *in.AutoInjectHTML
	}
	if !in.Enabled {
		settings.AnalyticsInjectHTML = false
	}
	if settings.AnalyticsInjectHTML && module.Status.Version != "2.3.0" {
		fail(w, 409, "请先在应用商店签名升级网站分析到 2.3.0；安装清单不代替新版面板能力")
		return
	}
	requestedInjection := settings.AnalyticsInjectHTML
	in.AutoInjectHTML = &requestedInjection
	var baseline struct {
		Current   string `json:"current"`
		Candidate string `json:"candidate"`
		ConfigSHA string `json:"config_sha"`
	}
	// Read-only old-config comparison must still work when an optional HTML
	// engine failed, so the operator can opt out. Candidate preview and actual
	// apply each independently enforce readiness before enabling injection.
	if err = a.Executor.Call(r.Context(), "POST", "/v1/sites/preview?analytics_baseline=1", site, &baseline); err != nil {
		fail(w, 409, "无法核对原网站配置："+err.Error())
		return
	}
	// Do not silently regenerate and discard edits made outside the managed
	// website settings model. The normal preview flow must reconcile them first.
	if !sameManagedAnalyticsBaseline(baseline.Current, baseline.Candidate, site.ID) {
		fail(w, 409, "网站配置含有手工修改，已保留原文件；请先在网站设置中核对配置预览后再启停采集")
		return
	}
	settings.AnalyticsEndpoint = ""
	if in.Enabled {
		settings.AnalyticsEndpoint = endpoint
	}
	candidate := site
	candidate.Settings = settings
	var preview struct {
		ConfigSHA string `json:"config_sha"`
	}
	if err = a.Executor.Call(r.Context(), "POST", "/v1/sites/preview", candidate, &preview); err != nil {
		fail(w, 409, "采集代理预览失败："+err.Error())
		return
	}
	if preview.ConfigSHA != baseline.ConfigSHA {
		fail(w, 409, "预览期间网站配置已变化，请刷新后重试")
		return
	}
	job, err := a.Store.queueSiteSettings(site.ID, settings, site.SettingsRevision, preview.ConfigSHA, key, u.Username, &in)
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	_ = a.Store.Audit(u.Username, "analytics.configure", site.ID, "queued")
	send(w, 202, map[string]string{"job_id": job})
}
