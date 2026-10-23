package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"local/panel/internal/appcatalog"
	"net/http"
	"strings"
)

type SoftwareAppCatalogItem struct {
	ID           string         `json:"id"`
	Family       string         `json:"family"`
	Name         string         `json:"name"`
	Category     string         `json:"category"`
	Version      string         `json:"version"`
	Description  string         `json:"description"`
	Source       string         `json:"source"`
	Capabilities []string       `json:"capabilities"`
	Defaults     map[string]any `json:"defaults"`
}

type SoftwareAppStatus struct {
	ID             string         `json:"id"`
	StateUnknown   bool           `json:"state_unknown,omitempty"`
	Installed      bool           `json:"installed"`
	Enabled        bool           `json:"enabled"`
	Healthy        bool           `json:"healthy"`
	Version        string         `json:"version,omitempty"`
	InstallationID string         `json:"installation_id,omitempty"`
	Detail         string         `json:"detail"`
	Settings       map[string]any `json:"settings,omitempty"`
}

type SoftwareAppsPage struct {
	Catalog []SoftwareAppCatalogItem `json:"catalog"`
	Status  []SoftwareAppStatus      `json:"status"`
}

type WAFEvent struct {
	SiteID    string `json:"site_id,omitempty"`
	Path      string `json:"path,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Action    string `json:"action,omitempty"`
	Time      string `json:"time"`
	Site      string `json:"site"`
	IP        string `json:"ip"`
	Peer      string `json:"peer,omitempty"`
	Status    int    `json:"status"`
	Method    string `json:"method"`
	BadMethod string `json:"bad_method"`
	BadArgs   string `json:"bad_args"`
	BadURI    string `json:"bad_uri"`
	BadAgent  string `json:"bad_agent"`
	Rate      string `json:"rate"`
}

type WAFEventsPage struct {
	Events  []WAFEvent `json:"events"`
	HasMore bool       `json:"has_more"`
}

var softwareAppCatalog = []SoftwareAppCatalogItem{
	{ID: "nginx-waf", Family: "waf", Name: "Nginx 请求防火墙", Category: "security", Version: WAFVersion, Description: "独立防护工作台：站点策略、名单与 CC；可核验的独立请求体引擎、开源 CRS、隐私日志及中断恢复", Source: "云栈独立规则与可分发开源 ModSecurity / OWASP CRS", Capabilities: []string{"分类防护规则", "IPv4/IPv6 名单", "站点独立策略", "单 URL CC", "独立请求体引擎", "开源 CRS", "规则命中报表", "有界日志及恢复", "Nginx 校验与回滚"}, Defaults: map[string]any{"profile": "balanced", "rate_per_second": 20}},
	{ID: "system-hardening", Family: "hardening", Name: "系统基线加固", Category: "security", Version: HardeningAppVersion, Description: "实际内核、配置与原值逐项核对；可逆基线切换、持久事务及显式恢复", Source: "云栈固定 Linux sysctl 基线", Capabilities: []string{"15项参数核对", "真实原值与偏差", "可逆BPF禁用", "持久事务回执", "中断显式恢复", "卸载恢复原值"}, Defaults: map[string]any{"profile": "baseline"}},
	{ID: "intrusion-prevention", Family: "intrusion", Name: "SSH 防入侵", Category: "security", Version: IntrusionAppVersion, Description: "核对实际 SSH 监听与 Fail2ban 作用域；持久事务调整限额，保留既存封禁，支持原事务显式恢复", Source: "系统签名仓库 Fail2ban 与云栈受限事务执行器", Capabilities: []string{"实际 SSH 端口核对", "运行限额与内核范围", "持久事务与原始回执", "中断显式恢复", "封禁 IP 查询与解封", "卸载恢复底层策略"}, Defaults: map[string]any{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}},
}

func SoftwareAppCatalog() []SoftwareAppCatalogItem {
	out := make([]SoftwareAppCatalogItem, len(softwareAppCatalog))
	copy(out, softwareAppCatalog)
	return append(out, moduleSoftwareCatalog()...)
}

func findSoftwareApp(id string) (SoftwareAppCatalogItem, bool) {
	for _, app := range SoftwareAppCatalog() {
		if app.ID == id {
			return app, true
		}
	}
	return SoftwareAppCatalogItem{}, false
}

// Candidate capability implemented by this program. An installed app must still
// pass its independent signed registry receipt and installation-instance checks.
const DiskAnalysisAppVersion = "1.4.0"
const HardeningAppVersion = "1.1.0"
const IntrusionAppVersion = "1.1.0"

// Module implementations ship in the signed panel executor, not arbitrary
// GitHub scripts. A newer catalog cannot claim code this executor lacks.
func SoftwareImplementationVersion(id string) string {
	app, _ := findSoftwareApp(id)
	return app.Version
}

func ValidateSoftwareUpdate(id, version string) error {
	if id == "mobile-pwa" {
		if !appcatalog.NativeMobileUpdateVersionAllowed(version) {
			return errors.New("原生移动端新交付仅允许固定完整1.3.2，拒绝别名及未审核版本")
		}
	}
	if id == "intrusion-prevention" && version != IntrusionAppVersion {
		return errors.New("防入侵事务更新仅允许固定完整1.1.0，拒绝旧标签、别名及未审核版本")
	}
	if id == "system-hardening" {
		base, _, _ := strings.Cut(version, "-")
		if comparison, valid := appcatalog.CompareVersions(base, HardeningAppVersion); valid && comparison >= 0 && version != HardeningAppVersion {
			return errors.New("持久加固版本仅允许固定完整1.1.0，拒绝未审核别名")
		}
	}
	if id == "website-analytics" {
		base, _, _ := strings.Cut(version, "-")
		if comparison, valid := appcatalog.CompareVersions(base, AnalyticsSessionAppVersion); valid && comparison >= 0 && version != AnalyticsSessionAppVersion {
			return errors.New("浏览器分析会话修订仅允许固定完整版本2.3.1，拒绝别名或未审核修订")
		}
	}
	if id == "disk-analysis" {
		base, _, _ := strings.Cut(version, "-")
		if comparison, valid := appcatalog.CompareVersions(base, "1.3.0"); valid && comparison >= 0 && version != "1.3.0" && version != DiskAnalysisAppVersion {
			return errors.New("磁盘分析新版本仅允许固定完整版本1.3.0或1.4.0，拒绝别名或未审核修订")
		}
	}
	if id == "platform-ops" {
		base, _, _ := strings.Cut(version, "-")
		if comparison, valid := appcatalog.CompareVersions(base, PlatformMaintenanceAppVersion); valid && comparison >= 0 && version != PlatformMaintenanceAppVersion {
			return errors.New("维护新版本仅允许固定完整版本1.3.0，拒绝别名或未审核修订")
		}
	}
	if id == "website-statistics-v2" {
		base, _, _ := strings.Cut(version, "-")
		if comparison, valid := appcatalog.CompareVersions(base, "2.5.0"); valid && comparison >= 0 && version != "2.5.0" && version != "2.6.0" {
			return errors.New("统计新格式仅允许完整固定版本2.5.0或2.6.0，拒绝别名或未审核修订")
		}
	}
	cmp, valid := appcatalog.CompareVersions(version, SoftwareImplementationVersion(id))
	if !valid || cmp > 0 {
		return errors.New("新版应用需要先升级面板，当前受限处理器尚未提供该版本")
	}
	return nil
}

func normalizeSoftwareSettings(id string, raw map[string]any) (map[string]any, error) {
	if id == "apache-waf" {
		cfg, err := DecodeApacheWAFConfig(raw)
		return WAFSettings(cfg), err
	}
	if _, ok := FindAppModule(id); ok {
		return validateModuleSettings(raw)
	}
	app, ok := findSoftwareApp(id)
	if !ok {
		return nil, errors.New("软件不在受管目录中")
	}
	if raw == nil {
		raw = app.Defaults
	}
	copyJSON, _ := json.Marshal(raw)
	var v map[string]any
	if json.Unmarshal(copyJSON, &v) != nil {
		return nil, errors.New("软件配置无效")
	}
	number := func(key string, min, max int) (int, error) {
		n, ok := v[key].(float64)
		if !ok || n != float64(int(n)) || int(n) < min || int(n) > max {
			return 0, errors.New("软件配置参数超出允许范围")
		}
		return int(n), nil
	}
	only := func(keys ...string) error {
		allowed := map[string]bool{}
		for _, key := range keys {
			allowed[key] = true
		}
		for key := range v {
			if !allowed[key] {
				return errors.New("软件配置包含未允许的字段")
			}
		}
		return nil
	}
	switch id {
	case "nginx-waf":
		cfg, e := DecodeWAFConfig(v)
		if e != nil {
			return nil, e
		}
		if _, advanced := v["policy"]; !advanced {
			// Legacy clients submit only these two knobs. Every advanced
			// field requires explicit policy/revision; never acknowledge a
			// trusted-proxy, engine or cleanup intent then silently discard it.
			for field := range v {
				if field != "profile" && field != "rate_per_second" {
					return nil, errors.New("高级 WAF 参数必须同时提交完整 policy 配置和当前修订号；未保存或忽略部分配置")
				}
			}
			return map[string]any{"profile": cfg.Profile, "rate_per_second": cfg.Rate}, nil
		}
		return WAFSettings(cfg), nil
	case "system-hardening":
		if e := only("profile"); e != nil {
			return nil, e
		}
		profile, _ := v["profile"].(string)
		if profile != "baseline" && profile != "strict" {
			return nil, errors.New("系统加固等级只能是 baseline 或 strict")
		}
		return map[string]any{"profile": profile}, nil
	case "intrusion-prevention":
		if e := only("max_retry", "find_time_minutes", "ban_time_minutes"); e != nil {
			return nil, e
		}
		retry, e := number("max_retry", 2, 20)
		if e != nil {
			return nil, e
		}
		find, e := number("find_time_minutes", 1, 1440)
		if e != nil {
			return nil, e
		}
		ban, e := number("ban_time_minutes", 10, 10080)
		if e != nil {
			return nil, e
		}
		return map[string]any{"max_retry": retry, "find_time_minutes": find, "ban_time_minutes": ban}, nil
	}
	return nil, errors.New("软件配置无效")
}

func (s *Store) QueueSoftwareAction(id, action string, settings map[string]any, key, actor string) (string, error) {
	return s.queueSoftwareAction(id, action, settings, "", key, actor)
}

func (s *Store) queueSoftwareAction(id, action string, settings map[string]any, version, key, actor string) (string, error) {
	return s.queueSoftwareActionBound(id, action, settings, version, key, actor, nil)
}

// The registry binding is committed with the job, never after an executor can
// finish it. Other lifecycle callers retain their existing queue contract.
func (s *Store) queueSoftwareActionBound(id, action string, settings map[string]any, version, key, actor string, bind func(*sql.Tx, string, bool) error) (string, error) {
	if _, ok := findSoftwareApp(id); !ok {
		return "", errors.New("软件不在受管目录中")
	}
	if action != "install" && action != "configure" && action != "uninstall" && action != "update" && !((id == "system-hardening" || id == "intrusion-prevention") && action == "recover") {
		return "", errors.New("软件生命周期操作无效")
	}
	if action == "install" && id == "platform-ops" && version == "" {
		return "", errors.New("维护应用安装需签名应用的明确版本，不能由旧直接安装接口启用新授权")
	}
	if id == "intrusion-prevention" && action == "install" && version != IntrusionAppVersion {
		return "", errors.New("防入侵1.1.0安装需匹配的签名应用版本，不能直接安装或隐式提升旧包")
	}
	if action == "install" && (id == "website-statistics-v2" || id == "platform-ops") && version != "" {
		if err := ValidateSoftwareUpdate(id, version); err != nil {
			return "", err
		}
	}
	if action == "recover" {
		var err error
		if id == "intrusion-prevention" {
			settings, err = NormalizeIntrusionRecovery(settings)
		} else {
			settings, err = NormalizeHardeningRecovery(settings)
		}
		if err != nil {
			return "", err
		}
	} else if action == "update" {
		if err := ValidateSoftwareUpdate(id, version); err != nil {
			return "", err
		}
		settings = nil // never replace live configuration during an update
	} else if action != "uninstall" {
		var e error
		settings, e = normalizeSoftwareSettings(id, settings)
		if e != nil {
			return "", e
		}
	} else {
		settings = map[string]any{}
	}
	if id == "nginx-waf" && action != "uninstall" && action != "update" {
		cfg, e := DecodeWAFConfig(settings)
		if e != nil {
			return "", e
		}
		if e = s.validateWAFSites(cfg); e != nil {
			return "", e
		}
	}
	if id == "apache-waf" && action != "uninstall" && action != "update" {
		cfg, err := DecodeApacheWAFConfig(settings)
		if err != nil {
			return "", err
		}
		if err = s.validateApacheWAFSites(cfg); err != nil {
			return "", err
		}
	}
	if key == "" || len(key) > 128 {
		return "", errors.New("请提供有效的幂等键")
	}
	kind := "software_" + action
	payload, _ := json.Marshal(map[string]any{"settings": settings, "version": version})
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var oldID, oldTarget, oldKind, oldPayload string
	e = tx.QueryRow(`SELECT id,target_id,kind,payload FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&oldID, &oldTarget, &oldKind, &oldPayload)
	if e == nil {
		if oldTarget != id || oldKind != kind || oldPayload != string(payload) {
			return "", errors.New("幂等键已被不同请求使用")
		}
		if bind != nil {
			if e = bind(tx, oldID, true); e != nil {
				return "", e
			}
		}
		return oldID, tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return "", e
	}
	if id == "disk-analysis" {
		if e = checkHostDiskUpgrade(context.Background(), tx); e != nil {
			return "", e
		}
	}
	job := ID()
	if _, e = tx.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at) VALUES(?,?,?,'queued',?,?,?,?)`, job, id, kind, string(payload), key, Now(), Now()); e != nil {
		return "", errors.New("该软件已有正在执行的操作")
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,'queued',?)`, actor, "software."+action, id, Now()); e != nil {
		return "", e
	}
	if bind != nil {
		if e = bind(tx, job, false); e != nil {
			return "", e
		}
	}
	return job, tx.Commit()
}

func (a *Server) softwareAppRoutes(m *http.ServeMux) {
	a.hardeningRecoveryRoutes(m)
	a.intrusionInspectionRoutes(m)
	a.wafApplyTaskRoutes(m)
	a.wafApplyRecoveryRoutes(m)
	a.wafSiteRoutes(m)
	a.wafWorkspaceRoutes(m)
	m.HandleFunc("GET /api/software/nginx-waf/events", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var page WAFEventsPage
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/software/nginx-waf/events", nil, &page); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, page)
	}))
	m.HandleFunc("GET /api/software", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var statuses []SoftwareAppStatus
		if e := a.Executor.Call(r.Context(), http.MethodGet, "/v1/software", nil, &statuses); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, SoftwareAppsPage{Catalog: SoftwareAppCatalog(), Status: statuses})
	}))
	m.HandleFunc("POST /api/software/{id}/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Settings map[string]any `json:"settings"`
		}
		if !decode(w, r, &in) {
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		action := strings.TrimSpace(r.PathValue("action"))
		var job string
		var e error
		if wafApplyApp(id) && (action == "install" || action == "configure") {
			job, e = a.Store.queueWAFApplyRequest(id, action, in.Settings, r.Header.Get("Idempotency-Key"), u)
		} else {
			job, e = a.Store.QueueSoftwareAction(id, action, in.Settings, r.Header.Get("Idempotency-Key"), u.Username)
		}
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": job})
	}))
}
