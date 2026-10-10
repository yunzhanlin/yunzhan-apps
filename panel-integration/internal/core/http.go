package core

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Config struct{ DataDir, WebDir, Origin, Socket, Listen string }
type Server struct {
	Store              *Store
	Executor           *ExecutorClient
	AppCatalog         *appcatalog.Client
	Config             Config
	mux                *http.ServeMux
	mu                 sync.Mutex
	attempts           map[string][]time.Time
	terminalMu         sync.Mutex
	securityScanMu     sync.Mutex
	terminalGrants     map[string]terminalGrant
	terminalSessions   map[string]terminalSessionOwner
	accountSecretKey   []byte
	bootstrap          string
	analyticsRateMu    sync.Mutex
	analyticsRates     map[string]analyticsRate
	analyticsGlobal    analyticsRate
	outboundMu         sync.Mutex
	outboundCollectMu  sync.Mutex
	outboundDispatchMu sync.Mutex
	outboundCancels    map[string]context.CancelFunc
}
type identity struct{ ID, Username, CSRF string }

func NewServer(s *Store, c Config) (*Server, error) {
	a := &Server{Store: s, Executor: NewExecutorClient(c.Socket), AppCatalog: appcatalog.Default(), Config: c, attempts: map[string][]time.Time{}, terminalGrants: map[string]terminalGrant{}, terminalSessions: map[string]terminalSessionOwner{}}
	key, err := s.accountKey(c.DataDir)
	if err != nil {
		return nil, err
	}
	a.accountSecretKey = key
	s.encryptionKey = append([]byte{}, key...)
	if s.UserCount() == 0 {
		p := filepath.Join(c.DataDir, "bootstrap-token")
		b, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			b = []byte(Token())
			err = os.WriteFile(p, b, 0600)
		}
		if err != nil {
			return nil, err
		}
		a.bootstrap = strings.TrimSpace(string(b))
	}
	m := http.NewServeMux()
	m.HandleFunc("GET /api/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var result map[string]string
		if e := a.Executor.Call(ctx, "GET", "/v1/health", nil, &result); e != nil || result["status"] != "ok" {
			fail(w, 503, "执行器尚未就绪")
			return
		}
		send(w, 200, map[string]string{"status": "ok", "executor": "ready"})
	})
	a.mux = m
	a.databaseRoutes(m)
	a.databaseMetricRoutes(m)
	a.databaseConnectionRoutes(m)
	a.fileRoutes(m)
	a.systemFileRoutes(m)
	a.siteSettingsRoutes(m)
	a.siteTrafficRoutes(m)
	a.runtimeReferenceRoutes(m)
	a.runtimeLifecycleRoutes(m)
	a.phpExtensionRoutes(m)
	a.accountRoutes(m)
	a.certificateRoutes(m)
	a.acmeRoutes(m)
	a.monitoringRoutes(m)
	a.monitorProcessRoutes(m)
	a.scheduleRoutes(m)
	a.backupRoutes(m)
	a.systemBackupRoutes(m)
	a.remoteBackupRoutes(m)
	a.panelAccessRoutes(m)
	a.securityRoutes(m)
	a.loginEventRoutes(m)
	a.siteSecurityScanRoutes(m)
	a.fail2banRoutes(m)
	a.terminalRoutes(m)
	a.sftpRoutes(m)
	a.dockerRoutes(m)
	a.redisRoutes(m)
	a.mariadbRoutes(m)
	a.nodeRoutes(m)
	a.phpWorkerRoutes(m)
	a.notificationRoutes(m)
	a.outboundNotificationRoutes(m)
	a.sessionPolicyRoutes(m)
	a.softwareAppRoutes(m)
	a.appRegistryRoutes(m)
	a.appModuleRoutes(m)
	a.analyticsRoutes(m)
	m.HandleFunc("GET /api/platform/agent", a.platformAgent)
	m.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		send(w, 200, map[string]any{"status": "ok", "version": "0.1.0-dev", "environment": "debian-vm-development"})
	})
	m.HandleFunc("GET /api/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		send(w, 200, map[string]bool{"initialized": s.UserCount() > 0})
	})
	m.HandleFunc("POST /api/bootstrap", a.initialize)
	m.HandleFunc("POST /api/login", a.login)
	m.HandleFunc("GET /api/me", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		access, e := s.UserAccess(u.ID)
		if e != nil {
			fail(w, 403, "账户授权不可用")
			return
		}
		send(w, 200, map[string]any{"user_id": u.ID, "username": u.Username, "csrf": u.CSRF, "version": "0.1.0-dev", "role": access.Role, "menu_ids": access.MenuIDs, "menu_catalog": MenuPermissionCatalog(), "permission_revision": access.Revision})
	}))
	m.HandleFunc("POST /api/logout", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		c, _, _ := a.sessionCookie(r)
		_, _ = s.DB.Exec(`DELETE FROM sessions WHERE token_hash=?`, Hash(c.Value))
		_ = s.Audit(u.Username, "auth.logout", "session", "success")
		a.cookie(w, r, "", -1)
		send(w, 200, map[string]bool{"ok": true})
	}))
	m.HandleFunc("GET /api/overview", a.authorize(a.overview))
	m.HandleFunc("GET /api/sites", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		xs, err := s.Sites()
		if err != nil {
			fail(w, 500, "读取站点失败")
			return
		}
		send(w, 200, a.scopeSites(u, xs))
	}))
	m.HandleFunc("POST /api/sites", a.authorize(a.createSite))
	m.HandleFunc("DELETE /api/sites/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmDomain string `json:"confirm_domain"`
		}
		if !decode(w, r, &in) {
			return
		}
		id := r.PathValue("id")
		// Archived-key replay remains resolved by the store: archived sites are
		// no longer visible to Site(), and do not need another native preflight.
		if site, err := a.Store.Site(id); err == nil {
			if site.Domain != in.ConfirmDomain {
				fail(w, 409, "请填写完整主域名")
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			var check struct {
				SiteID    string `json:"site_id"`
				Clear     bool   `json:"waf_reference_clear"`
				Unchanged bool   `json:"no_site_files_changed"`
			}
			if err := a.Executor.Call(ctx, "GET", "/v1/sites/"+id+"/archive-check", nil, &check); err != nil {
				fail(w, 409, err.Error())
				return
			}
			if check.SiteID != id || !check.Clear || !check.Unchanged {
				fail(w, 409, "网站归档预检未确认，未排队或修改网站")
				return
			}
		}
		job, e := a.Store.QueueSiteArchive(id, in.ConfirmDomain, r.Header.Get("Idempotency-Key"), u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": job})
	}))
	m.HandleFunc("POST /api/sites/{id}/{action}", a.authorize(a.siteAction))
	m.HandleFunc("GET /api/sites/{id}/config", a.authorize(a.siteConfig))
	m.HandleFunc("GET /api/jobs", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		xs, err := s.Jobs()
		if err != nil {
			fail(w, 500, "读取任务失败")
			return
		}
		send(w, 200, xs)
	}))
	m.HandleFunc("GET /api/jobs/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		j, e := a.Store.Job(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "任务不存在")
			return
		}
		send(w, 200, j)
	}))
	m.HandleFunc("GET /api/jobs/{id}/log", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var n int
		_ = s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE id=?`, r.PathValue("id")).Scan(&n)
		if n != 1 {
			fail(w, 404, "安装任务不存在")
			return
		}
		var out map[string]string
		if e := a.Executor.Call(r.Context(), "GET", "/v1/runtimes/jobs/"+r.PathValue("id")+"/log", nil, &out); e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, out)
	}))

	m.HandleFunc("POST /api/jobs/{id}/retry", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var n int
		_ = s.DB.QueryRow(`SELECT count(*) FROM mysql_jobs WHERE id=?`, r.PathValue("id")).Scan(&n)
		var retryErr error
		var acmeCount int
		_ = s.DB.QueryRow(`SELECT count(*) FROM acme_orders WHERE id=?`, r.PathValue("id")).Scan(&acmeCount)
		if acmeCount == 1 {
			retryErr = s.RetryACME(r.PathValue("id"), u.Username)
		} else if n == 1 {
			retryErr = s.RetryDatabase(r.PathValue("id"), u.Username)
		} else {
			retryErr = s.Retry(r.PathValue("id"), u.Username)
		}
		if err := retryErr; err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 202, map[string]bool{"ok": true})
	}))
	m.HandleFunc("GET /api/audit", a.authorize(a.audit))
	m.HandleFunc("GET /api/runtimes", a.authorize(a.runtimes))
	m.HandleFunc("POST /api/runtimes/install", a.authorize(a.installRuntime))
	m.HandleFunc("POST /api/runtimes/install-bundle", a.authorize(a.installRuntimeBundle))
	m.HandleFunc("POST /api/runtimes/nginx/switch", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ReleaseID string `json:"release_id"`
		}
		if !decode(w, r, &in) {
			return
		}
		id, e := a.Store.QueueNginx(in.ReleaseID, r.Header.Get("Idempotency-Key"), u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": id})
	}))

	m.HandleFunc("POST /api/sites/{id}/php", a.authorize(a.switchPHP))
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, "接口不存在") })
	files := panelStaticHandler(c.WebDir)
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, 405, "请求方法不被允许")
			return
		}
		files.ServeHTTP(w, r)
	})
	return a, nil
}
func (a *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
	// Only the two explicit public telemetry endpoints have their own origin and
	// payload policy. This does not relax the admin API or its CSRF checks.
	if r.URL.Path == "/collect/analytics/tracker.js" || r.URL.Path == "/collect/analytics/event" {
		a.mux.ServeHTTP(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Cache-Control", "no-store")
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		origin := r.Header.Get("Origin")
		if origin != "" && !a.originAllowed(r, origin) {
			fail(w, 403, "请求来源不被允许")
			return
		}
		isUpload := r.Method == "POST" && ((strings.HasPrefix(r.URL.Path, "/api/sites/") && strings.HasSuffix(r.URL.Path, "/files/upload")) || (strings.HasPrefix(r.URL.Path, "/api/databases/imports/") && strings.HasSuffix(r.URL.Path, "/upload")) || (strings.HasPrefix(r.URL.Path, "/api/mariadb/databases/") && strings.HasSuffix(r.URL.Path, "/import"))) && strings.HasPrefix(r.Header.Get("Content-Type"), "application/octet-stream")
		if !isUpload && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			fail(w, 415, "请使用 JSON 请求")
			return
		}
	}
	a.mux.ServeHTTP(w, r)
}
func send(w http.ResponseWriter, status int, x any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(x)
}
func fail(w http.ResponseWriter, status int, message string) {
	send(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, x any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(x); err != nil {
		fail(w, 400, "请求格式错误或字段不被支持")
		return false
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		fail(w, 400, "请求必须只包含一个 JSON 对象")
		return false
	}
	return true
}
func (a *Server) originAllowed(r *http.Request, origin string) bool {
	for _, allowed := range strings.Split(a.Config.Origin, ",") {
		if strings.TrimSpace(allowed) == origin {
			return true
		}
	}
	u, e := url.Parse(origin)
	if e != nil || u.Host != r.Host {
		return false
	}
	if u.Scheme == "https" && r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}
	return u.Scheme == "http" && r.Header.Get("X-Forwarded-Proto") == "http" && r.Header.Get("X-Panel-Connection") == "public-http"
}
func (a *Server) cookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{Name: a.sessionCookieName(), Value: value, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}
func (a *Server) allowed(r *http.Request) bool {
	return a.allowedScope(r, "login")
}
func (a *Server) allowedScope(r *http.Request, scope string) bool {
	ip := scope + ":" + clientRemoteIP(r)
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := time.Now().Add(-time.Minute)
	for k, ts := range a.attempts {
		if len(ts) == 0 || ts[len(ts)-1].Before(cutoff) {
			delete(a.attempts, k)
		}
	}
	if len(a.attempts) > 1024 {
		return false
	}
	recent := []time.Time{}
	for _, t := range a.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 8 {
		return false
	}
	a.attempts[ip] = append(recent, time.Now())
	return true
}
func (a *Server) initialize(w http.ResponseWriter, r *http.Request) {
	if !a.allowed(r) {
		fail(w, 429, "请求过于频繁，请稍后再试")
		return
	}
	var v struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	if !decode(w, r, &v) {
		return
	}
	if a.Store.UserCount() > 0 {
		fail(w, 409, "面板已初始化")
		return
	}
	if a.bootstrap == "" || subtle.ConstantTimeCompare([]byte(v.Token), []byte(a.bootstrap)) != 1 {
		fail(w, 403, "初始化令牌无效")
		return
	}
	if !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{2,31}$`).MatchString(v.Username) || len(v.Password) < 12 || len(v.Password) > 72 {
		fail(w, 400, "用户名需为 3–32 位字母/数字；密码需为 12–72 字节")
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(v.Password), 12)
	if err != nil {
		fail(w, 500, "初始化失败")
		return
	}
	tx, err := a.Store.DB.Begin()
	if err != nil {
		fail(w, 500, "数据库暂不可用")
		return
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM users`).Scan(&count); err != nil || count > 0 {
		fail(w, 409, "面板已初始化")
		return
	}
	if _, err = tx.Exec(`INSERT INTO users(id,username,password_hash,created_at) VALUES(?,?,?,?)`, ID(), v.Username, h, Now()); err != nil {
		fail(w, 500, "保存管理员失败")
		return
	}
	if _, err = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'auth.initialize','panel','success',?)`, v.Username, Now()); err != nil {
		fail(w, 500, "保存审计失败")
		return
	}
	if err = tx.Commit(); err != nil {
		fail(w, 500, "初始化失败")
		return
	}
	_ = os.Remove(filepath.Join(a.Config.DataDir, "bootstrap-token"))
	send(w, 201, map[string]bool{"ok": true})
}
func (a *Server) login(w http.ResponseWriter, r *http.Request) {
	if !a.allowed(r) {
		_ = a.Store.RecordLoginEvent("unknown", clientRemoteIP(r), "rate_limited")
		fail(w, 429, "登录过于频繁，请稍后再试")
		return
	}
	var v struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decode(w, r, &v) {
		return
	}
	session, e := a.Store.authenticateAccount(v.Username, v.Password, v.Code, a.accountSecretKey, time.Now())
	if e != nil {
		_ = a.Store.Audit("anonymous", "auth.login", "panel", "denied")
		_ = a.Store.RecordLoginEvent(v.Username, clientRemoteIP(r), "denied")
		if errors.Is(e, errCredentials) {
			fail(w, 401, e.Error())
		} else {
			fail(w, 500, "登录暂不可用")
		}
		return
	}
	_ = a.Store.RecordLoginEvent(session.Username, clientRemoteIP(r), "success")
	a.cookie(w, r, session.Token, 43200)
	send(w, 200, session)
}
func (a *Server) authorize(next func(http.ResponseWriter, *http.Request, identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, legacy, err := a.sessionCookie(r)
		if err != nil {
			fail(w, 401, "请先登录")
			return
		}
		var u identity
		now := time.Now()
		tokenHash := Hash(c.Value)
		u, err = a.Store.sessionIdentity(tokenHash, now)
		if err != nil {
			fail(w, 401, "会话已失效，请重新登录")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(u.CSRF)) != 1 {
			fail(w, 403, "安全校验失败，请刷新页面")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if err = a.Store.touchSession(tokenHash, now); err != nil {
				fail(w, 401, "会话已失效，请重新登录")
				return
			}
		}
		if !a.appRoleAllowed(u, r) {
			fail(w, 403, "当前角色不允许访问该资源")
			return
		}
		if legacy {
			a.migrateSessionCookie(w, r, c)
		}
		next(w, r, u)
	}
}
func (a *Server) createSite(w http.ResponseWriter, r *http.Request, u identity) {
	var v struct {
		Name         string `json:"name"`
		Slug         string `json:"slug"`
		Domain       string `json:"domain"`
		PHPVersionID string `json:"php_version_id"`
	}
	if !decode(w, r, &v) {
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) > 128 {
		fail(w, 400, "幂等键过长")
		return
	}
	id, err := a.Store.CreateSiteAtDomain(strings.TrimSpace(v.Name), v.Slug, v.Domain, key, u.Username, v.PHPVersionID)
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	send(w, 202, map[string]string{"job_id": id})
}
func (a *Server) siteAction(w http.ResponseWriter, r *http.Request, u identity) {
	act := r.PathValue("action")
	if act != "enable" && act != "disable" {
		fail(w, 404, "操作不存在")
		return
	}
	id, err := a.Store.QueueSiteAction(r.PathValue("id"), act+"_site", u.Username)
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	send(w, 202, map[string]string{"job_id": id})
}
func (a *Server) siteConfig(w http.ResponseWriter, r *http.Request, u identity) {
	site, err := a.Store.Site(r.PathValue("id"))
	if err != nil {
		fail(w, 404, "站点不存在")
		return
	}
	var result map[string]any
	if err = a.Executor.Call(r.Context(), "POST", "/v1/sites/config", map[string]string{"id": site.ID}, &result); err != nil {
		fail(w, 503, err.Error())
		return
	}
	send(w, 200, result)
}
func (a *Server) overview(w http.ResponseWriter, r *http.Request, u identity) {
	// Health polling must not inherit the long timeout used for installation
	// and other executor operations. A stalled executor is not a healthy sample.
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	var result map[string]any
	if err := a.Executor.Call(ctx, "GET", "/v1/overview", nil, &result); err != nil {
		fail(w, 503, err.Error())
		return
	}
	counts := map[string]int{}
	for key, q := range map[string]string{"sites": "SELECT count(*) FROM sites WHERE status!='archived'", "running_sites": "SELECT count(*) FROM sites WHERE status='running'", "pending_jobs": "SELECT count(*) FROM jobs WHERE state IN ('queued','running')", "attention_jobs": "SELECT count(*) FROM jobs WHERE state IN ('failed','needs_attention')"} {
		var n int
		_ = a.Store.DB.QueryRow(q).Scan(&n)
		counts[key] = n
	}
	var runtimePending, runtimeAttention int
	_ = a.Store.DB.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE state IN ('queued','running')`).Scan(&runtimePending)
	_ = a.Store.DB.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE state IN ('failed','needs_attention')`).Scan(&runtimeAttention)
	var databasePending, databaseAttention int
	_ = a.Store.DB.QueryRow(`SELECT count(*) FROM mysql_jobs WHERE state IN ('queued','running')`).Scan(&databasePending)
	_ = a.Store.DB.QueryRow(`SELECT count(*) FROM mysql_jobs WHERE state IN ('failed','needs_attention')`).Scan(&databaseAttention)
	counts["pending_jobs"] += databasePending
	counts["attention_jobs"] += databaseAttention
	counts["pending_jobs"] += runtimePending
	counts["attention_jobs"] += runtimeAttention
	result["counts"] = counts
	send(w, 200, result)
}
func (a *Server) audit(w http.ResponseWriter, r *http.Request, u identity) {
	rows, err := a.Store.DB.Query(`SELECT id,actor,action,target,result,created_at FROM audit_logs ORDER BY id DESC LIMIT 200`)
	if err != nil {
		fail(w, 500, "读取审计失败")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var actor, action, target, result, created string
		if err = rows.Scan(&id, &actor, &action, &target, &result, &created); err != nil {
			fail(w, 500, "读取审计失败")
			return
		}
		out = append(out, map[string]any{"id": id, "actor": actor, "action": action, "target": target, "result": result, "created_at": created})
	}
	send(w, 200, out)
}
func (a *Server) runtimes(w http.ResponseWriter, r *http.Request, u identity) {
	var actual map[string]any
	if err := a.Executor.Call(r.Context(), "GET", "/v1/runtimes", nil, &actual); err != nil {
		fail(w, 503, err.Error())
		return
	}
	if installed, ok := actual["installed"].([]any); ok {
		for _, item := range installed {
			if rt, ok := item.(map[string]any); ok && rt["id"] != "nginx-system" && rt["status"] == "installed" {
				id, _ := rt["id"].(string)
				arch, _ := rt["architecture"].(string)
				if r, ok := runtimecatalog.Find(id); ok {
					if er := a.Store.RecordObservedInstallation(r, arch); er != nil {
						fail(w, 500, "保存运行时版本清单失败")
						return
					}
				}
			}
			if rt, ok := item.(map[string]any); ok && rt["id"] == "nginx-system" {
				v, _ := rt["package_version"].(string)
				arch, _ := rt["architecture"].(string)
				if err := a.Store.RecordNginxInventory(v, arch); err != nil {
					fail(w, 500, "保存运行环境清单失败")
					return
				}
			}
		}
	}
	if id, ok := actual["active_nginx"].(string); ok {
		if er := a.Store.RecordNginxActive(id); er != nil {
			fail(w, 500, er.Error())
			return
		}
	}
	catalog := []map[string]any{
		{"family": "nginx", "name": "Nginx", "versions": []string{"Stable", "Mainline"}, "description": "全局网站入口 · 切换前校验全部站点与模块", "state": "available", "releases": runtimecatalog.Nginx},
		{"family": "apache", "name": "Apache", "versions": []string{"2.4 Stable"}, "description": "兼容型 Web 服务 · 独立目录安装，不占用 Nginx 全局入口", "state": "available", "releases": runtimecatalog.Apache},
		{"family": "mysql", "name": "MySQL", "versions": []string{"8.0", "8.4"}, "description": "独立实例与数据目录 · 8.4 LTS 优先，8.0 用于兼容迁移", "state": "available", "releases": runtimecatalog.MySQL()},
	}
	if releases := runtimecatalog.MariaDB(); len(releases) > 0 {
		catalog = append(catalog, map[string]any{"family": "mariadb", "name": "MariaDB", "versions": []string{"11.4 LTS", "11.8 LTS"}, "description": "MySQL 兼容数据库 · 两个 LTS 精确版本独立安装", "state": "available", "releases": releases})
	}
	catalog = append(catalog,
		map[string]any{"family": "redis", "name": "Redis", "versions": []string{"7.4", "8.2"}, "description": "多版本缓存服务 · 独立目录安装并启用 TLS 构建", "state": "available", "releases": runtimecatalog.Redis},
		map[string]any{"family": "docker", "name": "Docker", "versions": []string{"26", "29"}, "description": "容器、镜像与 Compose 项目 · 使用当前 Debian 的固定签名软件包", "state": func() string {
			if runtimecatalog.DockerAvailableOn(runtimecatalog.HostPlatform()) {
				return "available"
			}
			return "unavailable"
		}(), "releases": runtimecatalog.DockerReleaseOn(runtimecatalog.HostPlatform())},
		map[string]any{"family": "php", "name": "PHP", "versions": []string{"8.2", "8.3", "8.4", "8.5"}, "description": "多个 PHP-FPM 版本共存 · 每站独立绑定版本与扩展", "state": "available", "releases": runtimecatalog.PHP},
		map[string]any{"family": "node", "name": "Node.js", "versions": []string{"22 LTS", "24 LTS"}, "description": "官方 LTS 二进制 · node 与 npm 随版本共存", "state": "available", "releases": runtimecatalog.Node()},
	)
	actual["catalog"] = catalog
	send(w, 200, actual)
}

func (a *Server) installRuntime(w http.ResponseWriter, r *http.Request, u identity) {
	var in struct {
		ReleaseID string `json:"release_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	id, e := a.Store.QueueInstall(in.ReleaseID, r.Header.Get("Idempotency-Key"), u.Username)
	if e != nil {
		fail(w, 409, e.Error())
		return
	}
	send(w, 202, map[string]string{"job_id": id})
}
func (a *Server) installRuntimeBundle(w http.ResponseWriter, r *http.Request, u identity) {
	var in struct {
		ReleaseIDs []string `json:"release_ids"`
	}
	if !decode(w, r, &in) {
		return
	}
	result, e := a.Store.QueueInstallBundle(in.ReleaseIDs, r.Header.Get("Idempotency-Key"), u.Username)
	if e != nil {
		fail(w, 409, e.Error())
		return
	}
	send(w, 202, result)
}
func (a *Server) switchPHP(w http.ResponseWriter, r *http.Request, u identity) {
	var in struct {
		ReleaseID string `json:"release_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	id, e := a.Store.QueuePHP(r.PathValue("id"), in.ReleaseID, u.Username)
	if e != nil {
		fail(w, 409, e.Error())
		return
	}
	send(w, 202, map[string]string{"job_id": id})
}
