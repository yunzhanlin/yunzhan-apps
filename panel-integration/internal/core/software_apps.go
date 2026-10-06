package core

import (
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
	ID        string         `json:"id"`
	Installed bool           `json:"installed"`
	Enabled   bool           `json:"enabled"`
	Healthy   bool           `json:"healthy"`
	Version   string         `json:"version,omitempty"`
	Detail    string         `json:"detail"`
	Settings  map[string]any `json:"settings,omitempty"`
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
	{ID: "nginx-waf", Family: "waf", Name: "Nginx 请求防火墙", Category: "security", Version: WAFVersion, Description: "独立防护工作台：站点策略、分类规则、IP/URL/UA 名单、CC、自定义字面规则与攻击日志", Source: "云栈独立开源规则", Capabilities: []string{"分类防护规则", "IPv4/IPv6 名单", "站点独立策略", "单 URL CC", "攻击报表", "Nginx 校验与回滚"}, Defaults: map[string]any{"profile": "balanced", "rate_per_second": 20}},
	{ID: "system-hardening", Family: "hardening", Name: "系统基线加固", Category: "security", Version: "1.0", Description: "固化链接、ptrace、内核日志与网络重定向等内核参数，支持偏差检测与恢复", Source: "面板内置 Debian sysctl 基线", Capabilities: []string{"内核参数预设", "实际值核对", "卸载恢复原值", "配置偏差告警"}, Defaults: map[string]any{"profile": "baseline"}},
	{ID: "intrusion-prevention", Family: "intrusion", Name: "SSH 防入侵", Category: "security", Version: "1.0", Description: "使用 Debian Fail2ban 的 systemd 日志后端保护 SSH，并保留面板现有解封与封禁查询", Source: "Debian 签名仓库 Fail2ban", Capabilities: []string{"SSHD Jail", "尝试窗口与封禁时长", "服务状态", "封禁 IP 查询与解封"}, Defaults: map[string]any{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}},
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

// Module implementations ship in the signed panel executor, not arbitrary
// GitHub scripts. A newer catalog cannot claim code this executor lacks.
func SoftwareImplementationVersion(id string) string {
	app, _ := findSoftwareApp(id)
	return app.Version
}

func ValidateSoftwareUpdate(id, version string) error {
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
	if _, ok := findSoftwareApp(id); !ok {
		return "", errors.New("软件不在受管目录中")
	}
	if action != "install" && action != "configure" && action != "uninstall" && action != "update" {
		return "", errors.New("软件生命周期操作无效")
	}
	if action == "update" {
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
		return oldID, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return "", e
	}
	job := ID()
	if _, e = tx.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at) VALUES(?,?,?,'queued',?,?,?,?)`, job, id, kind, string(payload), key, Now(), Now()); e != nil {
		return "", errors.New("该软件已有正在执行的操作")
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,'queued',?)`, actor, "software."+action, id, Now()); e != nil {
		return "", e
	}
	return job, tx.Commit()
}

func (a *Server) softwareAppRoutes(m *http.ServeMux) {
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
		job, e := a.Store.QueueSoftwareAction(id, action, in.Settings, r.Header.Get("Idempotency-Key"), u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": job})
	}))
}
