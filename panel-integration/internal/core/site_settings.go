package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type RewriteRule struct {
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement"`
	Flag        string `json:"flag"`
}
type SiteSettings struct {
	PublicIngress       bool          `json:"public_ingress,omitempty"`
	AnalyticsEndpoint   string        `json:"analytics_endpoint,omitempty"`
	AnalyticsInjectHTML bool          `json:"analytics_inject_html,omitempty"`
	WAFEnabled          *bool         `json:"waf_enabled,omitempty"`
	ACME                bool          `json:"acme,omitempty"`
	TLS                 *SiteTLS      `json:"tls,omitempty"`
	PHP                 *PHPSettings  `json:"php,omitempty"`
	Domains             []string      `json:"domains"`
	DocumentRoot        string        `json:"document_root"`
	IndexFiles          []string      `json:"index_files"`
	Mode                string        `json:"mode"`
	Rewrite             string        `json:"rewrite"`
	Rules               []RewriteRule `json:"rules"`
	ProxyURL            string        `json:"proxy_url"`
	ProxyPreserveHost   bool          `json:"proxy_preserve_host,omitempty"`
	RedirectURL         string        `json:"redirect_url"`
	RedirectCode        int           `json:"redirect_code"`
	PreserveURI         bool          `json:"preserve_uri"`
	WebServer           string        `json:"web_server,omitempty"`
}

// A missing value preserves the historical behavior for existing sites.
func SiteWAFEnabled(in SiteSettings) bool { return in.WAFEnabled == nil || *in.WAFEnabled }

func DefaultSiteSettings(in SiteSettings) SiteSettings {
	if in.Mode == "" {
		in.Mode = "files"
	}
	if in.WebServer == "" {
		in.WebServer = "nginx"
	}
	if in.Rewrite == "" {
		in.Rewrite = "none"
	}
	if len(in.IndexFiles) == 0 {
		in.IndexFiles = []string{"index.php", "index.html"}
	}
	if in.RedirectCode == 0 {
		in.RedirectCode = 302
	}
	if in.Domains == nil {
		in.Domains = []string{}
	}
	if in.Rules == nil {
		in.Rules = []RewriteRule{}
	}
	if in.PHP != nil && len(in.PHP.Extensions) > 1 {
		copy := *in.PHP
		copy.Extensions = append([]string{}, in.PHP.Extensions...)
		sort.Strings(copy.Extensions)
		in.PHP = &copy
	}
	return in
}

var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var documentPath = regexp.MustCompile(`^[A-Za-z0-9_.\-/]+$`)
var indexName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

func ValidDomain(value string) bool {
	if len(value) > 253 || value != strings.ToLower(value) || !strings.Contains(value, ".") || net.ParseIP(value) != nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !domainLabel.MatchString(label) {
			return false
		}
	}
	return true
}
func ValidateSiteSettings(in SiteSettings, primary, php string) error {
	in = DefaultSiteSettings(in)
	if in.AnalyticsEndpoint != "" {
		if e := ValidateAnalyticsEndpoint(in.AnalyticsEndpoint); e != nil {
			return e
		}
	}
	if in.AnalyticsInjectHTML && (in.AnalyticsEndpoint == "" || in.Mode != "files" || in.WebServer != "nginx") {
		return errors.New("HTML 自动接入仅支持已开启采集的 Nginx 文件/PHP 网站；代理、Apache 与跳转网站请使用手工标签")
	}
	if in.WebServer != "nginx" && in.WebServer != "apache" {
		return errors.New("网站服务只支持 Nginx 或 Apache")
	}
	if in.WebServer == "apache" && in.Mode != "files" {
		return errors.New("Apache 首版只承载网站文件；反向代理和重定向请使用 Nginx")
	}
	if in.TLS != nil && !ValidID(in.TLS.CertificateID) {
		return errors.New("请选择有效证书")
	}
	if e := ValidatePHPSettings(in.PHP); e != nil {
		return e
	}
	if len(in.Domains) > 20 {
		return errors.New("每个站点最多绑定 20 个附加域名")
	}
	used := map[string]bool{primary: true}
	for _, domain := range in.Domains {
		if !ValidDomain(domain) || used[domain] {
			return errors.New("域名需为不重复的小写完整域名，国际域名请使用 Punycode")
		}
		used[domain] = true
	}
	if in.DocumentRoot != "" && (!ValidFilePath(in.DocumentRoot, false) || !documentPath.MatchString(in.DocumentRoot)) {
		return errors.New("文档目录需为网站根目录内的相对路径，只允许字母、数字、点、下划线、连字符和斜线")
	}
	if len(in.IndexFiles) > 8 {
		return errors.New("默认首页最多 8 项")
	}
	seen := map[string]bool{}
	for _, name := range in.IndexFiles {
		if !indexName.MatchString(name) || seen[name] {
			return errors.New("首页需为不重复的文件名")
		}
		seen[name] = true
	}
	switch in.Mode {
	case "files", "proxy", "redirect":
	default:
		return errors.New("不支持的网站服务模式")
	}
	switch in.Rewrite {
	case "none", "spa":
	case "wordpress", "thinkphp":
		if php == "" {
			return errors.New("该伪静态模板需要先绑定 PHP")
		}
	case "custom":
		if len(in.Rules) == 0 {
			return errors.New("请填写至少一条伪静态规则")
		}
	default:
		return errors.New("不支持的伪静态模板")
	}
	if len(in.Rules) > 20 {
		return errors.New("伪静态规则最多 20 条")
	}
	for _, r := range in.Rules {
		if len(r.Pattern) > 256 || !strings.HasPrefix(r.Pattern, "^") || strings.ContainsAny(r.Pattern, "\r\n\x00\";#{}") {
			return errors.New("规则需使用以 ^ 开头、最长 256 字符的受限正则")
		}
		if _, e := regexp.Compile(r.Pattern); e != nil {
			return errors.New("规则正则无法解析，请使用 Go/RE2 支持的表达式")
		}
		if !strings.HasPrefix(r.Replacement, "/") || len(r.Replacement) > 512 || strings.ContainsAny(r.Replacement, "\r\n\t\x00\";#{}\\ ") {
			return errors.New("替换路径必须为站内路径，不能包含指令或空白")
		}
		variables := regexp.MustCompile(`\$[A-Za-z0-9_]+`).FindAllString(r.Replacement, -1)
		rest := r.Replacement
		for _, v := range variables {
			if v != "$uri" && v != "$args" && v != "$query_string" && v != "$is_args" && !(len(v) == 2 && v[1] >= '1' && v[1] <= '9') {
				return errors.New("替换路径仅支持 $1–$9、$uri、$args、$query_string、$is_args")
			}
			rest = strings.ReplaceAll(rest, v, "")
		}
		if strings.Contains(rest, "$") {
			return errors.New("替换路径变量格式无效")
		}
		if r.Flag != "last" && r.Flag != "break" {
			return errors.New("伪静态规则动作只允许 last 或 break")
		}
	}
	if in.Mode == "proxy" {
		if e := validateWebsiteURL(in.ProxyURL, true); e != nil {
			return e
		}
	}
	if in.Mode == "redirect" {
		if e := validateWebsiteURL(in.RedirectURL, false); e != nil {
			return e
		}
		switch in.RedirectCode {
		case 301, 302, 307, 308:
		default:
			return errors.New("重定向状态码只允许 301、302、307、308")
		}
		if in.PreserveURI {
			u, _ := url.Parse(in.RedirectURL)
			if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
				return errors.New("保留访问路径时，目标只填写协议和域名/端口")
			}
		}
	}
	return nil
}
func validateWebsiteURL(value string, proxy bool) error {
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, "\r\n\t\x00\";#{}\\ $") {
		return errors.New("请填写有效的 HTTP 或 HTTPS 地址，不含凭证、片段或指令")
	}
	u, e := url.Parse(value)
	if e != nil || u.User != nil || u.Fragment != "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("请填写有效的 HTTP 或 HTTPS 地址")
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if ip == nil && !ValidDomain(host) && host != "localhost" {
		return errors.New("目标主机名无效")
	}
	if ip != nil && (ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
		return errors.New("目标不能为未指定、组播或链路本地地址")
	}
	port := u.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return errors.New("目标端口无效")
		}
	}
	if proxy {
		if u.RawQuery != "" || u.ForceQuery {
			return errors.New("代理上游地址不包含查询参数")
		}
		if port == "19100" || port == "19101" || port == "19102" {
			return errors.New("代理目标不能指向面板或网站入口自身")
		}
	}
	return nil
}
func (s *Store) migrateSiteSettings() error {
	var n int
	if e := s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=4`).Scan(&n); e != nil {
		return e
	}
	if n > 0 {
		return nil
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`ALTER TABLE sites ADD COLUMN settings_json TEXT NOT NULL DEFAULT '{}';
 ALTER TABLE sites ADD COLUMN settings_revision INTEGER NOT NULL DEFAULT 0;
 CREATE TABLE site_domains(domain TEXT PRIMARY KEY,site_id TEXT NOT NULL REFERENCES sites(id),source_job TEXT NOT NULL DEFAULT '');
 INSERT INTO site_domains(domain,site_id) SELECT domain,id FROM sites;
 INSERT INTO schema_migrations VALUES(4,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) QueueSiteSettings(id string, in SiteSettings, revision int64, configSHA, key, actor string) (string, error) {
	return s.queueSiteSettings(id, in, revision, configSHA, key, actor, nil)
}
func (s *Store) queueSiteSettings(id string, in SiteSettings, revision int64, configSHA, key, actor string, analytics *AnalyticsConfig) (string, error) {
	site, e := s.Site(id)
	if e != nil {
		return "", errors.New("站点不存在")
	}
	// Ordinary site editors (including older clients) cannot change this
	// internal upstream; preserve it through PHP, TLS and website changes.
	if analytics == nil {
		in.AnalyticsEndpoint = site.Settings.AnalyticsEndpoint
		in.AnalyticsInjectHTML = site.Settings.AnalyticsInjectHTML
	} else if analytics.SiteID != site.ID || (analytics.AutoInjectHTML != nil && in.AnalyticsInjectHTML != *analytics.AutoInjectHTML) {
		return "", errors.New("采集任务的网站或自动接入意图与候选配置不一致，未入队")
	}
	in = DefaultSiteSettings(in)
	sort.Strings(in.Domains)
	if e = ValidateSiteSettings(in, site.Domain, site.PHPVersionID); e != nil {
		return "", e
	}
	if in.WebServer == "apache" && !s.RuntimeInstalled("apache-2.4.68") {
		return "", errors.New("请先在软件商店安装 Apache 2.4.68")
	}
	if e = s.validatePHPExtensions(site.PHPVersionID, in.PHP); e != nil {
		return "", e
	}
	if e = s.validateSiteCertificate(site.Domain, in); e != nil {
		return "", e
	}
	if key == "" || len(key) > 128 || len(configSHA) != 64 || revision < 0 {
		return "", errors.New("请先生成配置预览，并提供有效版本与幂等键")
	}
	if site.Status == "provisioning" {
		return "", errors.New("站点尚未创建完成")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var oldID, oldPayload, oldSite, oldKind string
	e = tx.QueryRow(`SELECT id,payload,site_id,kind FROM jobs WHERE idempotency_key=?`, key).Scan(&oldID, &oldPayload, &oldSite, &oldKind)
	if e == nil {
		var p JobPayload
		_ = json.Unmarshal([]byte(oldPayload), &p)
		b, _ := json.Marshal(in)
		other, _ := json.Marshal(p.Settings)
		analyticsSame := analytics == nil && p.Analytics == nil || analytics != nil && p.Analytics != nil && sameAnalyticsRequest(*analytics, *p.Analytics)
		if oldSite != id || oldKind != "configure_site" || p.ExpectedRevision != revision || p.ExpectedConfigSHA != configSHA || string(b) != string(other) || !analyticsSame {
			return "", errors.New("幂等键已被不同请求使用")
		}
		return oldID, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return "", e
	}
	if analytics != nil {
		currentAnalytics, err := analyticsConfigInTx(tx, id)
		if err != nil {
			return "", err
		}
		if analytics.SiteID != id || analytics.Revision != currentAnalytics.Revision || analytics.Retention < 1 || analytics.Retention > 90 {
			return "", errors.New("统计配置已变化，请刷新后重试")
		}
		analytics.Key = currentAnalytics.Key
		if analytics.Key == "" {
			analytics.Key = ID()
		}
	}
	var current int64
	var status string
	if e = tx.QueryRow(`SELECT settings_revision,status FROM sites WHERE id=?`, id).Scan(&current, &status); e != nil {
		return "", e
	}
	if current != revision {
		return "", errors.New("网站设置已被修改，请重新读取并预览")
	}
	if status != "running" && status != "stopped" {
		var payload string
		_ = tx.QueryRow(`SELECT payload FROM jobs WHERE site_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1`, id).Scan(&payload)
		var p JobPayload
		_ = json.Unmarshal([]byte(payload), &p)
		status = p.PreviousStatus
		if status != "stopped" {
			status = "running"
		}
	}
	job := ID()
	p := JobPayload{Settings: &in, ExpectedRevision: revision, ExpectedConfigSHA: configSHA, PreviousStatus: status, Analytics: analytics}
	payload, _ := json.Marshal(p)
	if _, e = tx.Exec(`INSERT INTO jobs(id,site_id,payload,kind,state,idempotency_key,created_at,updated_at) VALUES(?,?,?,'configure_site','queued',?,?,?)`, job, id, string(payload), key, Now(), Now()); e != nil {
		return "", errors.New("站点已有执行中的任务")
	}
	for _, domain := range append([]string{site.Domain}, in.Domains...) {
		var owner string
		e = tx.QueryRow(`SELECT site_id FROM site_domains WHERE domain=?`, domain).Scan(&owner)
		if e == nil {
			if owner != id {
				return "", fmt.Errorf("域名 %s 已被其他站点绑定或预留", domain)
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return "", e
		}
		if _, e = tx.Exec(`INSERT INTO site_domains(domain,site_id,source_job) VALUES(?,?,?)`, domain, id, job); e != nil {
			return "", e
		}
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'site.configure',?,'queued',?)`, actor, id, Now()); e != nil {
		return "", e
	}
	return job, tx.Commit()
}
func finishSiteSettings(tx *sql.Tx, j Job) error {
	var p JobPayload
	if e := json.Unmarshal([]byte(j.Payload), &p); e != nil {
		return e
	}
	if p.Settings == nil {
		return errors.New("网站设置任务缺少目标配置")
	}
	b, _ := json.Marshal(p.Settings)
	result, e := tx.Exec(`UPDATE sites SET settings_json=?,settings_revision=settings_revision+1 WHERE id=? AND settings_revision=?`, string(b), j.SiteID, p.ExpectedRevision)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("网站设置版本冲突，需要核对已应用配置")
	}
	if p.Analytics != nil {
		if p.Analytics.SiteID != j.SiteID || (p.Settings.AnalyticsEndpoint != "") != p.Analytics.Enabled {
			return errors.New("采集配置任务身份不匹配")
		}
		if p.Analytics.AutoInjectHTML != nil && p.Settings.AnalyticsInjectHTML != *p.Analytics.AutoInjectHTML {
			return errors.New("HTML 接入策略与采集任务不一致")
		}
		if _, e = saveAnalyticsConfigTx(tx, *p.Analytics); e != nil {
			return e
		}
	}
	var release string
	if e = tx.QueryRow(`SELECT php_version_id FROM sites WHERE id=?`, j.SiteID).Scan(&release); e != nil {
		return e
	}
	if e = bindPHP(tx, j.SiteID, release); e != nil {
		return e
	}
	var primary string
	if e = tx.QueryRow(`SELECT domain FROM sites WHERE id=?`, j.SiteID).Scan(&primary); e != nil {
		return e
	}
	if _, e = tx.Exec(`DELETE FROM site_domains WHERE site_id=?`, j.SiteID); e != nil {
		return e
	}
	for _, domain := range append([]string{primary}, p.Settings.Domains...) {
		if _, e = tx.Exec(`INSERT INTO site_domains(domain,site_id) VALUES(?,?)`, domain, j.SiteID); e != nil {
			return e
		}
	}
	return finishAppSiteBinding(tx, j.SiteID, *p.Settings)
}
func (a *Server) siteSettingsRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/sites/{id}/settings", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		site, e := a.Store.Site(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "站点不存在")
			return
		}
		send(w, 200, site)
	}))
	m.HandleFunc("POST /api/sites/{id}/settings/preview", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Settings         SiteSettings `json:"settings"`
			ExpectedRevision int64        `json:"expected_revision"`
		}
		if !decode(w, r, &in) {
			return
		}
		site, e := a.Store.Site(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "站点不存在")
			return
		}
		in.Settings = DefaultSiteSettings(in.Settings)
		in.Settings.AnalyticsEndpoint = site.Settings.AnalyticsEndpoint
		in.Settings.AnalyticsInjectHTML = site.Settings.AnalyticsInjectHTML
		if site.SettingsRevision != in.ExpectedRevision {
			fail(w, 409, "网站设置已变化，请重新读取")
			return
		}
		if e = ValidateSiteSettings(in.Settings, site.Domain, site.PHPVersionID); e != nil {
			fail(w, 400, e.Error())
			return
		}
		if in.Settings.WebServer == "apache" && !a.Store.RuntimeInstalled("apache-2.4.68") {
			fail(w, 409, "请先在软件商店安装 Apache 2.4.68")
			return
		}
		if e = a.Store.validatePHPExtensions(site.PHPVersionID, in.Settings.PHP); e != nil {
			fail(w, 409, e.Error())
			return
		}
		if e = a.Store.validateSiteCertificate(site.Domain, in.Settings); e != nil {
			fail(w, 409, e.Error())
			return
		}
		sort.Strings(in.Settings.Domains)
		site.Settings = in.Settings
		var result any
		if e = a.Executor.Call(r.Context(), "POST", "/v1/sites/preview", site, &result); e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, result)
	}))
	m.HandleFunc("POST /api/sites/{id}/settings", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Settings          SiteSettings `json:"settings"`
			ExpectedRevision  int64        `json:"expected_revision"`
			ExpectedConfigSHA string       `json:"expected_config_sha"`
		}
		if !decode(w, r, &in) {
			return
		}
		job, e := a.Store.QueueSiteSettings(r.PathValue("id"), in.Settings, in.ExpectedRevision, in.ExpectedConfigSHA, r.Header.Get("Idempotency-Key"), u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": job})
	}))
	m.HandleFunc("GET /api/sites/{id}/logs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, e := a.Store.Site(r.PathValue("id")); e != nil {
			fail(w, 404, "站点不存在")
			return
		}
		var out any
		e := a.Executor.Call(r.Context(), "GET", "/v1/sites/"+r.PathValue("id")+"/logs?kind="+url.QueryEscape(r.URL.Query().Get("kind")), nil, &out)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "site.logs.read", r.PathValue("id"), "success")
		send(w, 200, out)
	}))
}
