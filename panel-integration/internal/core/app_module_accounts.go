package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func (s *Store) migrateAppModules() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS app_user_roles(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,role TEXT NOT NULL,site_ids TEXT NOT NULL DEFAULT '[]');
 CREATE TABLE IF NOT EXISTS app_platform_hosts(id TEXT PRIMARY KEY,url TEXT NOT NULL,token BLOB NOT NULL,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS app_platform_tokens(token_hash TEXT PRIMARY KEY,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS app_daily_reports(day TEXT PRIMARY KEY,report TEXT NOT NULL,created_at TEXT NOT NULL);
 INSERT OR IGNORE INTO schema_migrations VALUES(38,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}
func (s *Store) appUserRole(id string) (string, []string, error) {
	var role, raw string
	e := s.DB.QueryRow(`SELECT role,site_ids FROM app_user_roles WHERE user_id=?`, id).Scan(&role, &raw)
	if errors.Is(e, sql.ErrNoRows) {
		return "admin", nil, nil
	}
	var ids []string
	if e == nil {
		e = json.Unmarshal([]byte(raw), &ids)
	}
	return role, ids, e
}
func (a *Server) appRoleAllowed(u identity, r *http.Request) bool {
	role, sites, e := a.Store.appUserRole(u.ID)
	if e != nil {
		return false
	}
	if role == "admin" {
		return true
	}
	if r.URL.Path == "/api/me" || r.URL.Path == "/api/logout" || r.URL.Path == "/api/account" || strings.HasPrefix(r.URL.Path, "/api/account/") {
		return true
	}
	read := r.Method == "GET" || r.Method == "HEAD"
	if read && (r.URL.Path == "/api/overview" || strings.HasPrefix(r.URL.Path, "/api/monitor/") || r.URL.Path == "/api/sites") {
		return true
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/"), "/")
	if len(parts) >= 2 && parts[0] == "sites" && ValidID(parts[1]) {
		for _, id := range sites {
			if id == parts[1] {
				return read || role == "operator" && r.Method != "DELETE"
			}
		}
	}
	return false
}
func (a *Server) scopeSites(u identity, sites []Site) []Site {
	role, ids, e := a.Store.appUserRole(u.ID)
	if e != nil {
		return []Site{}
	}
	if role == "admin" {
		return sites
	}
	allowed := map[string]bool{}
	for _, id := range ids {
		allowed[id] = true
	}
	out := []Site{}
	for _, site := range sites {
		if allowed[site.ID] {
			out = append(out, site)
		}
	}
	return out
}

func (a *Server) manageAppUsers(actor identity, action string, in AppModuleInput) (any, error) {
	role, _, e := a.Store.appUserRole(actor.ID)
	if e != nil || role != "admin" {
		return nil, errors.New("需要管理员角色")
	}
	if action == "run" {
		rows, e := a.Store.DB.Query(`SELECT u.id,u.username,COALESCE(r.role,'admin'),COALESCE(r.site_ids,'[]'),EXISTS(SELECT 1 FROM account_security s WHERE s.user_id=u.id AND length(s.totp_secret)>0),(SELECT count(*) FROM sessions s WHERE s.user_id=u.id AND expires_at>?) FROM users u LEFT JOIN app_user_roles r ON r.user_id=u.id ORDER BY u.created_at`, time.Now().Unix())
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		users := []map[string]any{}
		for rows.Next() {
			var id, name, role, scopes string
			var totp, sessions int
			if e = rows.Scan(&id, &name, &role, &scopes, &totp, &sessions); e != nil {
				return nil, e
			}
			var ids []string
			_ = json.Unmarshal([]byte(scopes), &ids)
			users = append(users, map[string]any{"id": id, "username": name, "role": role, "site_ids": ids, "totp_enabled": totp == 1, "sessions": sessions})
		}
		return map[string]any{"users": users}, rows.Err()
	}
	if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{2,31}$`).MatchString(in.Username) {
		return nil, errors.New("用户名应为 3–32 位字母数字")
	}
	if action == "create" || action == "update" {
		if in.Role != "admin" && in.Role != "operator" && in.Role != "viewer" {
			return nil, errors.New("角色应为 admin/operator/viewer")
		}
		for _, id := range in.SiteIDs {
			if _, e = a.Store.Site(id); e != nil {
				return nil, errors.New("资源范围中的网站不存在")
			}
		}
	}
	if action == "create" || (action == "update" && in.Password != "") {
		if len(in.Password) < 16 || len(in.Password) > 72 {
			return nil, errors.New("密码应为 16–72 字节")
		}
	}
	tx, e := a.Store.DB.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	var id, oldrole string
	if action != "create" {
		if e = tx.QueryRow(`SELECT u.id,COALESCE(r.role,'admin') FROM users u LEFT JOIN app_user_roles r ON r.user_id=u.id WHERE u.username=?`, in.Username).Scan(&id, &oldrole); e != nil {
			return nil, errors.New("用户不存在")
		}
		if (action == "delete" || action == "update" && in.Role != "admin") && oldrole == "admin" {
			var admins int
			_ = tx.QueryRow(`SELECT count(*) FROM users u LEFT JOIN app_user_roles r ON r.user_id=u.id WHERE COALESCE(r.role,'admin')='admin'`).Scan(&admins)
			if admins <= 1 {
				return nil, errors.New("不能删除或降级最后一个管理员")
			}
		}
		if action == "delete" && id == actor.ID {
			return nil, errors.New("不能删除当前账户")
		}
	}
	raw, _ := json.Marshal(in.SiteIDs)
	switch action {
	case "create":
		hash, e := bcrypt.GenerateFromPassword([]byte(in.Password), 12)
		if e != nil {
			return nil, e
		}
		id = ID()
		if _, e = tx.Exec(`INSERT INTO users(id,username,password_hash,created_at) VALUES(?,?,?,?)`, id, in.Username, hash, Now()); e != nil {
			return nil, errors.New("用户名已存在")
		}
		_, e = tx.Exec(`INSERT INTO app_user_roles(user_id,role,site_ids) VALUES(?,?,?)`, id, in.Role, string(raw))
	case "update":
		_, e = tx.Exec(`INSERT INTO app_user_roles(user_id,role,site_ids) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET role=excluded.role,site_ids=excluded.site_ids`, id, in.Role, string(raw))
		if e == nil && in.Password != "" {
			hash, er := bcrypt.GenerateFromPassword([]byte(in.Password), 12)
			if er != nil {
				return nil, er
			}
			_, e = tx.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, id)
		}
		if e == nil {
			_, e = tx.Exec(`DELETE FROM sessions WHERE user_id=?`, id)
		}
	case "revoke":
		_, e = tx.Exec(`DELETE FROM sessions WHERE user_id=?`, id)
	case "delete":
		for _, table := range []string{"sessions", "account_recovery", "account_security", "account_profiles", "app_user_roles"} {
			if _, e = tx.Exec(`DELETE FROM `+table+` WHERE user_id=?`, id); e != nil {
				return nil, e
			}
		}
		_, e = tx.Exec(`DELETE FROM users WHERE id=?`, id)
	default:
		return nil, errors.New("用户操作不被支持")
	}
	if e != nil {
		return nil, e
	}
	return map[string]any{"username": in.Username, "action": action, "ok": true}, tx.Commit()
}
func (a *Server) appDailyReport(ctx context.Context) (any, error) {
	out := map[string]any{"created_at": Now()}
	var overview map[string]any
	if e := a.Executor.Call(ctx, "GET", "/v1/overview", nil, &overview); e != nil {
		return nil, e
	}
	out["resources"] = overview
	for name, q := range map[string]string{"sites": "SELECT count(*) FROM sites", "running_sites": "SELECT count(*) FROM sites WHERE status='running'", "failed_site_jobs": "SELECT count(*) FROM jobs WHERE state IN ('failed','needs_attention')", "failed_runtime_jobs": "SELECT count(*) FROM runtime_jobs WHERE state IN ('failed','needs_attention')", "audit_events_24h": "SELECT count(*) FROM audit_logs WHERE julianday(created_at)>=julianday('now','-1 day')"} {
		var n int
		if e := a.Store.DB.QueryRow(q).Scan(&n); e != nil {
			return nil, e
		}
		out[name] = n
	}
	for _, item := range []struct{ name, path string }{{"traffic", "/v1/sites/traffic"}, {"security", "/v1/software"}} {
		var report any
		var in any
		method := "GET"
		if item.name == "traffic" {
			sites, _ := a.Store.Sites()
			ids := []string{}
			for _, site := range sites {
				ids = append(ids, site.ID)
			}
			method = "POST"
			in = map[string]any{"site_ids": ids}
		}
		if e := a.Executor.Call(ctx, method, item.path, in, &report); e == nil {
			out[item.name] = report
		} else {
			out[item.name+"_error"] = e.Error()
		}
	}
	var count int
	certs, err := a.Store.Certificates()
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		expires, err := time.Parse(time.RFC3339, c.NotAfter)
		if err != nil {
			return nil, err
		}
		if expires.Before(time.Now().AddDate(0, 0, 14)) {
			count++
		}
	}
	out["certificates_due_14_days"] = count
	raw, _ := json.Marshal(out)
	day := time.Now().In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01-02")
	_, e := a.Store.DB.Exec(`INSERT INTO app_daily_reports(day,report,created_at) VALUES(?,?,?) ON CONFLICT(day) DO UPDATE SET report=excluded.report,created_at=excluded.created_at`, day, string(raw), Now())
	return out, e
}
func (a *Server) platformOperation(ctx context.Context, action string, in AppModuleInput) (any, error) {
	if action == "revoke-token" {
		if len(in.Token) != 64 {
			return nil, errors.New("只读令牌无效")
		}
		_, e := a.Store.DB.Exec(`DELETE FROM app_platform_tokens WHERE token_hash=?`, Hash(in.Token))
		return map[string]any{"revoked": true}, e
	}
	if action == "issue-token" {
		token := Token()
		_, e := a.Store.DB.Exec(`INSERT INTO app_platform_tokens(token_hash,created_at) VALUES(?,?)`, Hash(token), Now())
		return map[string]any{"token": token, "scope": "health-read-only", "endpoint": "/api/platform/agent"}, e
	}
	if action == "add" {
		var count int
		if e := a.Store.DB.QueryRow(`SELECT count(*) FROM app_platform_hosts`).Scan(&count); e != nil {
			return nil, e
		}
		if count >= 12 {
			return nil, errors.New("最多管理 12 个主机")
		}
		u, e := url.Parse(in.URL)
		if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || len(in.Token) != 64 || !regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`).MatchString(in.ResourceID) {
			return nil, errors.New("主机必须使用 HTTPS 地址和只读令牌")
		}
		encrypted, e := encryptCredential(a.accountSecretKey, "app-host:"+in.ResourceID, []byte(in.Token))
		if e != nil {
			return nil, e
		}
		_, e = a.Store.DB.Exec(`INSERT INTO app_platform_hosts(id,url,token,created_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET url=excluded.url,token=excluded.token`, in.ResourceID, strings.TrimRight(in.URL, "/"), encrypted, Now())
		return map[string]any{"id": in.ResourceID, "url": in.URL}, e
	}
	if action == "remove" {
		_, e := a.Store.DB.Exec(`DELETE FROM app_platform_hosts WHERE id=?`, in.ResourceID)
		return map[string]any{"removed": in.ResourceID}, e
	}
	rows, e := a.Store.DB.Query(`SELECT id,url,token FROM app_platform_hosts ORDER BY id`)
	if e != nil {
		return nil, e
	}
	type host struct {
		id, url string
		token   []byte
	}
	hosts := []host{}
	for rows.Next() {
		var h host
		if e = rows.Scan(&h.id, &h.url, &h.token); e != nil {
			rows.Close()
			return nil, e
		}
		hosts = append(hosts, h)
	}
	rows.Close()
	out := []map[string]any{}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, h := range hosts {
		entry := map[string]any{"id": h.id, "url": h.url, "healthy": false}
		secret, e := decryptCredential(a.accountSecretKey, "app-host:"+h.id, h.token)
		if e != nil {
			return nil, e
		}
		req, e := http.NewRequestWithContext(ctx, "GET", h.url+"/api/platform/agent", nil)
		if e != nil {
			return nil, e
		}
		req.Header.Set("Authorization", "Bearer "+string(secret))
		resp, e := client.Do(req)
		if e != nil {
			entry["error"] = e.Error()
		} else {
			var data any
			decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&data)
			resp.Body.Close()
			entry["healthy"] = resp.StatusCode == 200 && decodeErr == nil
			entry["status"] = resp.StatusCode
			entry["report"] = data
		}
		out = append(out, entry)
	}
	return map[string]any{"hosts": out, "checked_at": Now()}, nil
}
func (a *Server) platformAgent(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		fail(w, 401, "需要 Bearer 只读令牌")
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var count int
	if len(token) != 64 || a.Store.DB.QueryRow(`SELECT count(*) FROM app_platform_tokens WHERE token_hash=?`, Hash(token)).Scan(&count) != nil || count != 1 {
		fail(w, 401, "只读令牌无效")
		return
	}
	var out map[string]any
	if e := a.Executor.Call(r.Context(), "GET", "/v1/overview", nil, &out); e != nil {
		fail(w, 503, e.Error())
		return
	}
	send(w, 200, map[string]any{"health": out, "version": "app-modules-1", "time": Now()})
}

func (a *Server) StartAppDailyWorker(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var page []SoftwareAppStatus
				if a.Executor.Call(ctx, "GET", "/v1/software", nil, &page) != nil {
					continue
				}
				installed := false
				for _, v := range page {
					if v.ID == "daily-report" && v.Installed {
						installed = true
					}
				}
				if !installed {
					continue
				}
				day := time.Now().In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01-02")
				var n int
				_ = a.Store.DB.QueryRow(`SELECT count(*) FROM app_daily_reports WHERE day=?`, day).Scan(&n)
				if n == 0 {
					_, _ = a.appDailyReport(ctx)
				}
			}
		}
	}()
}
