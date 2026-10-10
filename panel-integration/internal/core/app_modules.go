package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Module actions are fixed identifiers. Parameters never become shell source.
type AppModuleDefinition struct {
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	Actions []string         `json:"actions"`
	Fields  []AppModuleField `json:"fields"`
}
type AppModuleField struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
}
type AppModuleInput struct {
	SiteID               string                          `json:"site_id,omitempty"`
	TargetSiteID         string                          `json:"target_site_id,omitempty"`
	TargetProjectID      string                          `json:"target_project_id,omitempty"`
	RemoteTargetID       string                          `json:"remote_target_id,omitempty"`
	RemoteTargetRevision int64                           `json:"remote_target_revision,omitempty"`
	RemoteTarget         *RemoteSyncTarget               `json:"remote_target,omitempty"`
	RemotePrivateKey     string                          `json:"remote_private_key,omitempty"`
	RemoteRequestID      string                          `json:"remote_request_id,omitempty"`
	SiteIDs              []string                        `json:"site_ids,omitempty"`
	MenuIDs              []string                        `json:"menu_ids"`
	Path                 string                          `json:"path,omitempty"`
	Excludes             []string                        `json:"excludes,omitempty"`
	ExpectedSHA          string                          `json:"expected_sha,omitempty"`
	Username             string                          `json:"username,omitempty"`
	Password             string                          `json:"password,omitempty"`
	Role                 string                          `json:"role,omitempty"`
	ResourceID           string                          `json:"resource_id,omitempty"`
	Entry                string                          `json:"entry,omitempty"`
	PID                  int                             `json:"pid,omitempty"`
	StartTime            uint64                          `json:"start_time,omitempty"`
	Port                 int                             `json:"port,omitempty"`
	Domain               string                          `json:"domain,omitempty"`
	Nodes                []AppUpstream                   `json:"nodes,omitempty"`
	Sticky               bool                            `json:"sticky,omitempty"`
	HealthCheck          *LoadBalanceHTTPHealth          `json:"health_check,omitempty"`
	BackendTLS           *LoadBalanceBackendTLS          `json:"backend_tls,omitempty"`
	URL                  string                          `json:"url,omitempty"`
	Token                string                          `json:"token,omitempty"`
	Source               string                          `json:"source,omitempty"`
	ReadOnly             bool                            `json:"read_only,omitempty"`
	Interval             int                             `json:"interval,omitempty"`
	AutoRestore          bool                            `json:"auto_restore,omitempty"`
	Realtime             bool                            `json:"realtime"`
	Confirm              string                          `json:"confirm,omitempty"`
	DryRun               bool                            `json:"dry_run,omitempty"`
	FromTime             string                          `json:"from_time,omitempty"`
	ToTime               string                          `json:"to_time,omitempty"`
	Search               string                          `json:"search,omitempty"`
	StatusCode           int                             `json:"status_code,omitempty"`
	MinSeconds           float64                         `json:"min_seconds,omitempty"`
	OnlyBots             bool                            `json:"only_bots,omitempty"`
	Severity             string                          `json:"severity,omitempty"`
	Instances            int                             `json:"instances,omitempty"`
	MemoryMB             int                             `json:"memory_mb,omitempty"`
	EnvironmentPatch     map[string]*string              `json:"environment_patch,omitempty"`
	AllowInstallScripts  bool                            `json:"allow_install_scripts,omitempty"`
	BindAddress          string                          `json:"bind_address,omitempty"`
	PassiveAddress       string                          `json:"passive_address,omitempty"`
	PassiveStart         int                             `json:"passive_start,omitempty"`
	PassiveEnd           int                             `json:"passive_end,omitempty"`
	CertificateID        string                          `json:"certificate_id,omitempty"`
	MaxClients           int                             `json:"max_clients,omitempty"`
	MaxPerIP             int                             `json:"max_per_ip,omitempty"`
	IdleMinutes          int                             `json:"idle_minutes,omitempty"`
	QuotaMB              int                             `json:"quota_mb"`
	QuotaFiles           int                             `json:"quota_files"`
	UploadKB             int                             `json:"upload_kb"`
	DownloadKB           int                             `json:"download_kb"`
	MaxSessions          int                             `json:"max_sessions"`
	ClientAllow          []string                        `json:"client_allow"`
	ClientDeny           []string                        `json:"client_deny"`
	Enabled              bool                            `json:"enabled"`
	ExpectedRevision     int64                           `json:"expected_revision,omitempty"`
	NetworkInterface     string                          `json:"network_interface,omitempty"`
	HomeNetworks         []string                        `json:"home_networks,omitempty"`
	RuleProfile          *NetworkIDSRuleProfileSelection `json:"rule_profile,omitempty"`
	PrepareIDS           bool                            `json:"prepare_ids,omitempty"`
	Limit                int                             `json:"limit,omitempty"`
	Offset               int                             `json:"offset,omitempty"`
}
type AppUpstream struct {
	Address string `json:"address"`
	Weight  int    `json:"weight"`
	Backup  bool   `json:"backup"`
}

func AppModules() []AppModuleDefinition {
	site := AppModuleField{"site_id", "网站", "site"}
	path := AppModuleField{"path", "相对文件路径", "text"}
	definitions := []AppModuleDefinition{
		{"site-diagnosis", "网站诊断", []string{"run"}, []AppModuleField{site}},
		{"network-threat-detection", "网络威胁检测", []string{"run", "baseline"}, nil},
		{"website-analytics", "网站分析", []string{"run"}, []AppModuleField{site}},
		{"files-sync", "文件同步", []string{"preview", "sync"}, []AppModuleField{site, {"target_site_id", "目标网站（与应用项目二选一）", "site"}, {"target_project_id", "目标旧版 PHP 项目 ID", "text"}}},
		{"daily-report", "每日运维报告", []string{"run"}, nil},
		{"website-statistics-v2", "网站统计 v2", []string{"run"}, []AppModuleField{site}},
		{"enterprise-tamper-proof", "企业网站防篡改", []string{"baseline", "check", "restore"}, []AppModuleField{site, path, {"auto_restore", "自动恢复已备份文件", "boolean"}}},
		{"load-balance", "负载均衡", []string{"run", "save", "probe", "check-http", "remove", "recover"}, []AppModuleField{{"domain", "小写域名", "text"}, {"port", "回环入口端口", "number"}, {"nodes", "上游节点", "json"}, {"sticky", "IP 会话粘滞", "boolean"}, {"backend_tls", "HTTPS 后端业务转发（显式启用）", "backend-tls"}, {"health_check", "持续 HTTP 应用检查（只观测）", "http-health"}, {"expected_revision", "入口修订号（选择记录自动填写）", "identity"}}},
		{"mobile-pwa", "云栈移动端", []string{"run"}, nil},
		{"apache-waf", "Apache 请求防火墙", []string{"run"}, nil},
		{"php-code-security", "PHP 代码安全", []string{"run"}, []AppModuleField{site}},
		{"task-manager", "任务管理器", []string{"run", "terminate"}, []AppModuleField{{"pid", "进程 PID", "number"}, {"start_time", "进程启动序号", "number"}}},
		{"website-tamper-proof", "网站防篡改", []string{"baseline", "check", "restore"}, []AppModuleField{site, path}},
		{"user-manager", "面板用户管理", []string{"run", "create", "update", "revoke", "delete"}, []AppModuleField{{"username", "用户名", "text"}, {"password", "新密码", "password"}, {"role", "角色", "text"}, {"site_ids", "网站权限范围", "json"}, {"menu_ids", "菜单授权", "menus"}, {"expected_revision", "账户授权修订号", "identity"}}},
		{"file-monitor", "文件监控", []string{"baseline", "check"}, []AppModuleField{site, {"excludes", "排除路径前缀", "json"}}},
		{"disk-analysis", "磁盘分析", []string{"run"}, []AppModuleField{site}},
		{"platform-ops", "多主机运维", []string{"run", "add", "remove", "issue-token", "revoke-token"}, []AppModuleField{{"resource_id", "主机标识", "text"}, {"url", "主机 HTTPS API 地址", "text"}, {"token", "只读访问令牌", "password"}}},
		{"nfs-manager", "NFS 管理", []string{"run", "mount", "unmount"}, []AppModuleField{{"resource_id", "挂载名称", "text"}, {"source", "服务端:/绝对导出路径", "text"}, {"read_only", "只读挂载", "boolean"}}},
		{"pm2-manager", "PM2 进程管理", []string{"run", "create", "start", "stop", "restart", "logs", "delete"}, []AppModuleField{site, {"resource_id", "应用标识", "text"}, {"entry", "网站内 JS 入口", "text"}, {"port", "应用回环端口", "number"}}},
		{"pure-ftpd", "Pure-FTPd", []string{"run", "create", "delete"}, []AppModuleField{site, {"username", "FTP 用户名", "text"}, {"password", "FTP 密码", "password"}}},
	}
	for i := range definitions {
		switch definitions[i].ID {
		case "files-sync":
			definitions[i].Actions = append(definitions[i].Actions, "run", "schedule", "run-plan", "pause-plan", "resume-plan", "remove-plan", "history")
			definitions[i].Actions = append(definitions[i].Actions, "remote-targets", "save-remote", "probe-remote", "remote-preview", "queue-remote", "remote-jobs", "remote-job", "cancel-remote", "recover-remote")
			definitions[i].Actions = append(definitions[i].Actions, "remote-archive", "archive-remote-job")
			definitions[i].Actions = append(definitions[i].Actions, "remote-backups")
			definitions[i].Actions = append(definitions[i].Actions, "remote-backup-preview", "remote-backup-archive", "archive-remote-backup", "recover-remote-backup")
			definitions[i].Actions = append(definitions[i].Actions, "remote-plans", "schedule-remote-plan", "pause-remote-plan", "resume-remote-plan", "remove-remote-plan")
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"remote_target_revision", "所选连接修订号（与计划修订号独立）", "identity"})
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"expected_sha", "所选远端任务完整记录摘要（自动填写）", "identity"}, AppModuleField{"confirm", "归档精确确认：ARCHIVE REMOTE 任务标识", "text"}, AppModuleField{"limit", "远端归档每页条数（最多 32）", "number"}, AppModuleField{"offset", "远端归档分页起点（最多 2048）", "number"})
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"remote_target_id", "远端连接标识（小写字母数字或短横线）", "text"}, AppModuleField{"remote_target", "固定 IP、端口、用户名、主机公钥和远端路径", "remote-sync"}, AppModuleField{"password", "SFTP 密码（与私钥二选一，仅写入）", "password"}, AppModuleField{"remote_private_key", "SFTP 私钥（无口令，仅写入）", "secret-text"}, AppModuleField{"remote_request_id", "远端任务标识（提交自动生成，重试保留）", "identity"})
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"excludes", "排除路径前缀", "json"}, AppModuleField{"resource_id", "同步计划标识（小写字母数字）", "text"}, AppModuleField{"interval", "同步补查间隔（秒，60–86400）", "number"}, AppModuleField{"realtime", "启用 Linux 实时增量同步", "boolean"}, AppModuleField{"enabled", "启用同步计划", "boolean"}, AppModuleField{"expected_revision", "计划配置版本（选中计划自动填写）", "identity"})
		case "network-threat-detection":
			definitions[i].Actions = append(definitions[i].Actions, "ids-report", "ids-prepare", "ids-config", "ids-rules", "ids-start", "ids-stop", "ids-boot", "ids-recover", "ids-rotate")
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"network_interface", "真实网络接口", "text"}, AppModuleField{"home_networks", "本机 IPv4 / IPv6 CIDR（JSON 数组）", "json"}, AppModuleField{"prepare_ids", "显式准备或升级引擎（不启用采集）", "boolean"}, AppModuleField{"expected_revision", "IDS 配置修订号（刷新自动填写）", "identity"}, AppModuleField{"enabled", "开机启用（不改变当前运行状态）", "boolean"})
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"from_time", "告警开始时间", "datetime"}, AppModuleField{"to_time", "告警结束时间", "datetime"}, AppModuleField{"search", "规则、类别或 IP 筛选", "text"}, AppModuleField{"severity", "IDS 风险等级（1–4，留空全部）", "text"}, AppModuleField{"limit", "告警每页数量（最多 200）", "number"}, AppModuleField{"offset", "告警起点（最多 20000）", "number"})
		case "file-monitor", "website-tamper-proof", "enterprise-tamper-proof":
			definitions[i].Actions = append(definitions[i].Actions, "policies", "pause", "resume", "watch-mode", "history")
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"interval", "后台补查间隔（秒，60–86400）", "number"}, AppModuleField{"realtime", "启用 Linux 实时文件事件", "boolean"}, AppModuleField{"expected_revision", "策略修订号（选择策略自动填写）", "identity"})
			if definitions[i].ID != "file-monitor" {
				definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"excludes", "排除路径前缀", "json"}, AppModuleField{"expected_sha", "所选变更的当前摘要（自动填写）", "identity"})
			}
		case "website-analytics", "website-statistics-v2":
			definitions[i].Fields = append(definitions[i].Fields,
				AppModuleField{"from_time", "开始时间（可选）", "datetime"}, AppModuleField{"to_time", "结束时间（可选）", "datetime"},
				AppModuleField{"search", "路径或 IP 筛选", "text"}, AppModuleField{"status_code", "HTTP 状态码（0 为全部）", "number"},
				AppModuleField{"min_seconds", "慢请求阈值（秒，0 默认 1 秒）", "decimal"}, AppModuleField{"only_bots", "仅查看爬虫请求", "boolean"})
		case "disk-analysis":
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"path", "网站内子目录（留空扫描全部）", "text"})
		case "php-code-security":
			definitions[i].Actions = append(definitions[i].Actions, "quarantine-list", "quarantine", "restore-quarantine", "recover-quarantine")
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"excludes", "排除路径前缀", "json"}, AppModuleField{"search", "路径或规则筛选", "text"}, AppModuleField{"severity", "风险级别", "severity"})
			definitions[i].Fields = append(definitions[i].Fields, path, AppModuleField{"resource_id", "隔离记录标识（选择记录自动填写）", "identity"}, AppModuleField{"expected_sha", "已审查文件摘要（自动填写）", "identity"}, AppModuleField{"expected_revision", "隔离记录修订号（自动填写）", "identity"}, AppModuleField{"confirm", "隔离 / 恢复的精确确认", "text"}, AppModuleField{"limit", "隔离清单每页条数（最多 200）", "number"}, AppModuleField{"offset", "隔离清单分页起点", "number"})
		case "daily-report":
			definitions[i].Actions = append(definitions[i].Actions, "archive", "report")
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"resource_id", "报告日期（YYYY-MM-DD）", "text"})
		case "pure-ftpd":
			definitions[i].Actions = append(definitions[i].Actions, "password", "service-config", "recover-service", "start", "stop", "probe", "account-limits", "recount-quota")
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"quota_mb", "FTP 容量限制（MiB，0 不限制）", "number"}, AppModuleField{"quota_files", "FTP 文件与目录数量（0 不限制）", "number"}, AppModuleField{"upload_kb", "上传限速（KiB/s，0 不限制）", "number"}, AppModuleField{"download_kb", "下载限速（KiB/s，0 不限制）", "number"}, AppModuleField{"max_sessions", "账户并发会话（0 不限制）", "number"}, AppModuleField{"client_allow", "允许客户端 IPv4/CIDR（JSON 数组，空为全部）", "json"}, AppModuleField{"client_deny", "拒绝客户端 IPv4/CIDR（JSON 数组）", "json"}, AppModuleField{"expected_sha", "所选账户当前摘要（自动填写）", "identity"})
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"bind_address", "本机监听 IPv4（0.0.0.0 为全部接口）", "text"}, AppModuleField{"port", "FTPS 控制端口", "number"}, AppModuleField{"passive_start", "被动端口起始", "number"}, AppModuleField{"passive_end", "被动端口结束", "number"}, AppModuleField{"passive_address", "被动模式通告 IPv4（NAT 使用公网 IP）", "text"}, AppModuleField{"certificate_id", "域名 TLS 证书", "certificate"}, AppModuleField{"domain", "FTPS 证书域名", "text"}, AppModuleField{"max_clients", "最大并发连接数", "number"}, AppModuleField{"max_per_ip", "单 IP 最大连接数", "number"}, AppModuleField{"idle_minutes", "空闲超时（分钟）", "number"}, AppModuleField{"expected_revision", "服务配置修订号（刷新自动填写）", "identity"}, AppModuleField{"confirm", "非回环监听确认（EXPOSE FTPS IP:端口）", "text"})
		case "nfs-manager":
			definitions[i].Actions = append(definitions[i].Actions, "server-report", "server-start", "server-stop", "server-probe", "server-recover", "server-config", "export-save", "export-remove")
			definitions[i].Fields = append(definitions[i].Fields, site, path, AppModuleField{"bind_address", "NFS 本机监听 IPv4/IPv6", "text"}, AppModuleField{"port", "NFSv4 监听端口", "number"}, AppModuleField{"client_allow", "允许客户端 IP/CIDR（JSON 数组，必须明确指定）", "json"}, AppModuleField{"expected_revision", "共享服务修订号（刷新自动填写）", "identity"}, AppModuleField{"confirm", "网络暴露 / 可写导出确认", "text"})
		case "pm2-manager":
			definitions[i].Actions = append(definitions[i].Actions, "update", "dependencies", "deployment", "cancel-deployment", "recover-deployment", "archive-deployments")
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"instances", "PM2 进程数（1–8）", "number"}, AppModuleField{"memory_mb", "单进程内存重启阈值（MiB）", "number"}, AppModuleField{"expected_revision", "项目配置修订号（选择项目自动填写）", "identity"})
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"environment_patch", "环境变量增量（JSON，仅写入）", "secret-json"})
			definitions[i].Fields = append(definitions[i].Fields, AppModuleField{"allow_install_scripts", "允许安装脚本（网站用户，不是 root）", "boolean"})
		}
	}
	return definitions
}
func FindAppModule(id string) (AppModuleDefinition, bool) {
	for _, d := range AppModules() {
		if d.ID == id {
			return d, true
		}
	}
	return AppModuleDefinition{}, false
}
func ValidAppModuleAction(id, action string) bool {
	d, ok := FindAppModule(id)
	if !ok {
		return false
	}
	for _, a := range d.Actions {
		if a == action {
			return true
		}
	}
	return false
}

func (a *Server) appModuleRoutes(m *http.ServeMux) {
	a.networkIDSOperationRoutes(m)
	a.networkIDSRuleFeedRoutes(m)
	m.HandleFunc("GET /api/app-modules/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, ok := FindAppModule(r.PathValue("id")); !ok {
			fail(w, 404, "应用模块不存在")
			return
		}
		var out map[string]any
		if e := a.Executor.Call(r.Context(), "GET", "/v1/app-modules/"+r.PathValue("id"), nil, &out); e != nil {
			fail(w, 409, e.Error())
			return
		}
		if r.PathValue("id") == "daily-report" {
			var raw string
			if e := a.Store.DB.QueryRow(`SELECT report FROM app_daily_reports ORDER BY day DESC LIMIT 1`).Scan(&raw); e == nil {
				var report any
				if json.Unmarshal([]byte(raw), &report) == nil {
					out["report"] = report
				}
			}
		}
		out["workspace"] = ModuleWorkspace(r.PathValue("id"))
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/app-modules/{id}/history", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		if _, ok := FindAppModule(id); !ok {
			fail(w, 404, "应用模块不存在")
			return
		}
		var out any
		var err error
		filter, err := ParseModuleHistoryQuery(r.URL.Query())
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		if id == "daily-report" || id == "user-manager" || id == "platform-ops" {
			out, err = a.Store.appModuleHistory(id, filter)
		} else {
			err = a.Executor.Call(r.Context(), "GET", "/v1/app-modules/"+id+"/history?"+r.URL.Query().Encode(), nil, &out)
		}
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/app-modules/{id}/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id, action := r.PathValue("id"), r.PathValue("action")
		if !ValidAppModuleAction(id, action) {
			fail(w, 400, "应用操作不被支持")
			return
		}
		if id == "network-threat-detection" && NetworkIDSBackgroundAction(action) {
			a.submitNetworkIDSOperation(w, r, u, action)
			return
		}
		var in AppModuleInput
		if !decode(w, r, &in) {
			return
		}
		var out any
		var err error
		ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
		defer cancel()
		var module struct {
			Status SoftwareAppStatus `json:"status"`
		}
		if err = a.Executor.Call(ctx, "GET", "/v1/app-modules/"+id, nil, &module); err != nil || !module.Status.Installed {
			fail(w, 409, "请先安装此应用模块")
			return
		}
		if id == "user-manager" {
			out, err = a.manageAppUsers(u, action, in)
		} else if id == "platform-ops" {
			out, err = a.platformOperation(ctx, action, in)
		} else if id == "daily-report" {
			out, err = a.dailyReportOperation(ctx, action, in)
		} else {
			if id == "pure-ftpd" && action == "service-config" && in.CertificateID != "" {
				material, certificateErr := a.Store.CertificateMaterial(in.CertificateID)
				if certificateErr != nil {
					fail(w, 409, "FTP 证书不可读取，请先在证书管理中添加有效证书")
					return
				}
				var installed Certificate
				if certificateErr = a.Executor.Call(ctx, "POST", "/v1/certificates/install", material, &installed); certificateErr != nil {
					fail(w, 409, certificateErr.Error())
					return
				}
			}
			err = a.Executor.Call(ctx, "POST", "/v1/app-modules/"+id+"/"+action, in, &out)
		}
		if id == "daily-report" || id == "user-manager" || id == "platform-ops" {
			if e := a.Store.recordAppModuleEvent(id, action, u.Username, err); e != nil && err == nil {
				err = errors.New("业务可能已执行，但执行摘要保存失败，请刷新核对")
			}
		}
		if err != nil {
			_ = a.Store.Audit(u.Username, "app-module."+action, id, "failed")
			fail(w, 409, err.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "app-module."+action, id, "succeeded")
		send(w, 200, out)
	}))
}

func moduleSoftwareCatalog() []SoftwareAppCatalogItem {
	out := []SoftwareAppCatalogItem{}
	for _, d := range AppModules() {
		version := "1.2.0"
		switch d.ID {
		case "file-monitor", "website-tamper-proof", "enterprise-tamper-proof", "files-sync":
			version = "1.4.1"
			if d.ID == "files-sync" {
				version = "1.9.0"
			}
		case "daily-report":
			version = "1.4.0"
		case "mobile-pwa", "php-code-security":
			version = "1.3.0"
		case "load-balance":
			version = "1.6.0"
		case "user-manager":
			version = "1.3.1"
		case "website-analytics":
			version = "2.3.0"
		case "pure-ftpd":
			version = "1.0.54-compat6"
		case "nfs-manager":
			version = "1.3.0"
		case "network-threat-detection":
			version = "1.3.0"
		case "pm2-manager":
			version = "7.0.4-compat4"
		case "website-statistics-v2":
			version = "2.4.0"
		case "apache-waf":
			version = ApacheWAFVersion
		}
		out = append(out, SoftwareAppCatalogItem{ID: d.ID, Family: "module", Name: d.Name, Category: "professional", Version: version, Description: d.Name, Source: "云栈应用仓库", Capabilities: d.Actions, Defaults: map[string]any{}})
	}
	return out
}
func validateModuleSettings(raw map[string]any) (map[string]any, error) {
	if raw == nil {
		return map[string]any{}, nil
	}
	b, e := json.Marshal(raw)
	if e != nil || len(b) > 16384 {
		return nil, errors.New("配置过大")
	}
	var in AppModuleInput
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil {
		return nil, errors.New("模块配置字段无效")
	}
	if in.Password != "" || in.Token != "" || in.RemotePrivateKey != "" || in.RemoteTarget != nil || in.EnvironmentPatch != nil {
		return nil, errors.New("凭据和环境秘密只能通过对应业务操作写入，不能保存为安装配置")
	}
	return raw, nil
}
