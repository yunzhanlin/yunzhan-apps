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
	SiteID          string        `json:"site_id,omitempty"`
	TargetSiteID    string        `json:"target_site_id,omitempty"`
	TargetProjectID string        `json:"target_project_id,omitempty"`
	SiteIDs         []string      `json:"site_ids,omitempty"`
	Path            string        `json:"path,omitempty"`
	Excludes        []string      `json:"excludes,omitempty"`
	ExpectedSHA     string        `json:"expected_sha,omitempty"`
	Username        string        `json:"username,omitempty"`
	Password        string        `json:"password,omitempty"`
	Role            string        `json:"role,omitempty"`
	ResourceID      string        `json:"resource_id,omitempty"`
	Entry           string        `json:"entry,omitempty"`
	PID             int           `json:"pid,omitempty"`
	StartTime       uint64        `json:"start_time,omitempty"`
	Port            int           `json:"port,omitempty"`
	Domain          string        `json:"domain,omitempty"`
	Nodes           []AppUpstream `json:"nodes,omitempty"`
	Sticky          bool          `json:"sticky,omitempty"`
	URL             string        `json:"url,omitempty"`
	Token           string        `json:"token,omitempty"`
	Source          string        `json:"source,omitempty"`
	ReadOnly        bool          `json:"read_only,omitempty"`
	Interval        int           `json:"interval,omitempty"`
	AutoRestore     bool          `json:"auto_restore,omitempty"`
	Confirm         string        `json:"confirm,omitempty"`
	DryRun          bool          `json:"dry_run,omitempty"`
}
type AppUpstream struct {
	Address string `json:"address"`
	Weight  int    `json:"weight"`
	Backup  bool   `json:"backup"`
}

func AppModules() []AppModuleDefinition {
	site := AppModuleField{"site_id", "网站", "site"}
	path := AppModuleField{"path", "相对文件路径", "text"}
	return []AppModuleDefinition{
		{"site-diagnosis", "网站诊断", []string{"run"}, []AppModuleField{site}},
		{"network-threat-detection", "网络威胁检测", []string{"run", "baseline"}, nil},
		{"website-analytics", "网站分析", []string{"run"}, []AppModuleField{site}},
		{"files-sync", "文件同步", []string{"preview", "sync"}, []AppModuleField{site, {"target_site_id", "目标网站（与应用项目二选一）", "site"}, {"target_project_id", "目标旧版 PHP 项目 ID", "text"}}},
		{"daily-report", "每日运维报告", []string{"run"}, nil},
		{"website-statistics-v2", "网站统计 v2", []string{"run"}, []AppModuleField{site}},
		{"enterprise-tamper-proof", "企业网站防篡改", []string{"baseline", "check", "restore"}, []AppModuleField{site, path, {"auto_restore", "自动恢复已备份文件", "boolean"}}},
		{"load-balance", "负载均衡", []string{"save", "probe", "remove"}, []AppModuleField{{"domain", "域名", "text"}, {"port", "回环入口端口", "number"}, {"nodes", "上游节点 JSON", "json"}, {"sticky", "IP 会话粘滞", "boolean"}}},
		{"mobile-pwa", "云栈移动端", []string{"run"}, nil},
		{"apache-waf", "Apache 请求防火墙", []string{"run"}, nil},
		{"php-code-security", "PHP 代码安全", []string{"run"}, []AppModuleField{site}},
		{"task-manager", "任务管理器", []string{"run", "terminate"}, []AppModuleField{{"pid", "进程 PID", "number"}, {"start_time", "进程启动序号", "number"}}},
		{"website-tamper-proof", "网站防篡改", []string{"baseline", "check", "restore"}, []AppModuleField{site, path}},
		{"user-manager", "面板用户管理", []string{"run", "create", "update", "revoke", "delete"}, []AppModuleField{{"username", "用户名", "text"}, {"password", "新密码", "password"}, {"role", "角色 admin/operator/viewer", "text"}, {"site_ids", "网站权限范围 JSON", "json"}}},
		{"file-monitor", "文件监控", []string{"baseline", "check"}, []AppModuleField{site, {"excludes", "排除路径前缀 JSON", "json"}}},
		{"disk-analysis", "磁盘分析", []string{"run"}, []AppModuleField{site}},
		{"platform-ops", "多主机运维", []string{"run", "add", "remove", "issue-token", "revoke-token"}, []AppModuleField{{"resource_id", "主机标识", "text"}, {"url", "主机 HTTPS API 地址", "text"}, {"token", "只读访问令牌", "password"}}},
		{"nfs-manager", "NFS 管理", []string{"run", "mount", "unmount"}, []AppModuleField{{"resource_id", "挂载名称", "text"}, {"source", "服务端:/绝对导出路径", "text"}, {"read_only", "只读挂载", "boolean"}}},
		{"pm2-manager", "PM2 进程管理", []string{"run", "create", "start", "stop", "restart", "logs", "delete"}, []AppModuleField{site, {"resource_id", "应用标识", "text"}, {"entry", "网站内 JS 入口", "text"}, {"port", "应用回环端口", "number"}}},
		{"pure-ftpd", "Pure-FTPd", []string{"run", "create", "delete"}, []AppModuleField{site, {"username", "FTP 用户名", "text"}, {"password", "FTP 密码", "password"}}},
	}
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
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/app-modules/{id}/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id, action := r.PathValue("id"), r.PathValue("action")
		if !ValidAppModuleAction(id, action) {
			fail(w, 400, "应用操作不被支持")
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
			out, err = a.appDailyReport(ctx)
		} else {
			err = a.Executor.Call(ctx, "POST", "/v1/app-modules/"+id+"/"+action, in, &out)
		}
		if err != nil {
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
		out = append(out, SoftwareAppCatalogItem{ID: d.ID, Family: "module", Name: d.Name, Category: "professional", Version: "1.0", Description: d.Name, Source: "云栈应用仓库", Capabilities: d.Actions, Defaults: map[string]any{}})
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
	return raw, nil
}
