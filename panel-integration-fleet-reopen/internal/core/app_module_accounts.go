package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func (s *Store) migrateAppModules() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS app_user_roles(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,role TEXT NOT NULL,site_ids TEXT NOT NULL DEFAULT '[]');
 CREATE TABLE IF NOT EXISTS app_user_menus(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,menu_ids TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0));
 CREATE TABLE IF NOT EXISTS app_platform_hosts(id TEXT PRIMARY KEY,url TEXT NOT NULL,token BLOB NOT NULL,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS app_platform_tokens(token_hash TEXT PRIMARY KEY,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS app_daily_reports(day TEXT PRIMARY KEY,report TEXT NOT NULL,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS app_module_events(id TEXT PRIMARY KEY,module_id TEXT NOT NULL,action TEXT NOT NULL,actor TEXT NOT NULL,outcome TEXT NOT NULL,created_at TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS app_module_events_module ON app_module_events(module_id);
 INSERT OR IGNORE INTO schema_migrations VALUES(38,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
 INSERT OR IGNORE INTO schema_migrations VALUES(40,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if e != nil {
		return e
	}
	return s.migratePlatformMaintenance()
}
func (s *Store) appUserRole(id string) (string, []string, error) {
	access, e := s.UserAccess(id)
	return access.Role, access.SiteIDs, e
}
func (a *Server) appRoleAllowed(u identity, r *http.Request) bool {
	access, e := a.Store.UserAccess(u.ID)
	if e != nil || !accessAllowsMenus(access, r) {
		return false
	}
	role, sites := access.Role, access.SiteIDs
	if role == "admin" {
		return true
	}
	if r.URL.Path == "/api/me" || r.URL.Path == "/api/logout" || r.URL.Path == "/api/account" || strings.HasPrefix(r.URL.Path, "/api/account/") || r.URL.Path == "/api/session/activity" {
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

func (a *Server) manageAppUsers(ctx context.Context, actor identity, action string, in AppModuleInput) (any, error) {
	actorAccess, e := readUserAccessContext(ctx, a.Store.DB, actor.ID)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if e != nil || actorAccess.Role != "admin" || !containsMenu(actorAccess.MenuIDs, "panel-access") {
		return nil, errors.New("需要管理员角色")
	}
	if action == "run" {
		rows, e := a.Store.DB.QueryContext(ctx, `SELECT u.id,u.username,COALESCE(r.role,'admin'),COALESCE(r.site_ids,'[]'),COALESCE(m.menu_ids,'null'),COALESCE(m.revision,1),EXISTS(SELECT 1 FROM account_security s WHERE s.user_id=u.id AND length(s.totp_secret)>0),(SELECT count(*) FROM sessions s WHERE s.user_id=u.id AND expires_at>?) FROM users u LEFT JOIN app_user_roles r ON r.user_id=u.id LEFT JOIN app_user_menus m ON m.user_id=u.id ORDER BY u.created_at`, time.Now().Unix())
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		users := []map[string]any{}
		for rows.Next() {
			var id, name, role, scopes, menus string
			var revision int64
			var totp, sessions int
			if e = rows.Scan(&id, &name, &role, &scopes, &menus, &revision, &totp, &sessions); e != nil {
				return nil, e
			}
			var ids []string
			_ = json.Unmarshal([]byte(scopes), &ids)
			menuIDs, err := parseMenuIDs(role, menus)
			if err != nil {
				return nil, err
			}
			users = append(users, map[string]any{"id": id, "username": name, "role": role, "site_ids": ids, "menu_ids": menuIDs, "revision": revision, "full_admin": fullAdministrator(UserAccess{Role: role, MenuIDs: menuIDs}), "totp_enabled": totp == 1, "sessions": sessions})
		}
		return map[string]any{"users": users, "menu_catalog": MenuPermissionCatalog()}, rows.Err()
	}
	if action != "create" && action != "update" && action != "revoke" && action != "delete" {
		return nil, errors.New("用户操作不被支持")
	}
	if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{2,31}$`).MatchString(in.Username) {
		return nil, errors.New("用户名应为 3–32 位字母数字")
	}
	if action == "create" || action == "update" {
		if in.Role != "admin" && in.Role != "operator" && in.Role != "viewer" {
			return nil, errors.New("角色应为 admin/operator/viewer")
		}
	}
	var passwordHash []byte
	if action == "create" || (action == "update" && in.Password != "") {
		if len(in.Password) < 16 || len(in.Password) > 72 {
			return nil, errors.New("密码应为 16–72 字节")
		}
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		// Fixed-cost hashing is done before opening a transaction. It cannot be
		// interrupted by bcrypt, but cancelled work never writes account data.
		passwordHash, e = bcrypt.GenerateFromPassword([]byte(in.Password), 12)
		if e != nil {
			return nil, e
		}
	}
	tx, e := a.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	// Re-read inside the same write transaction that changes the target.
	actorAccess, e = readUserAccessContext(ctx, tx, actor.ID)
	if e != nil || actorAccess.Role != "admin" || !containsMenu(actorAccess.MenuIDs, "panel-access") {
		return nil, errors.New("账户授权已变化")
	}
	if action == "create" || action == "update" {
		for _, siteID := range in.SiteIDs {
			var exists bool
			if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sites WHERE id=? AND status!='archived')`, siteID).Scan(&exists); e != nil {
				return nil, e
			}
			if !exists {
				return nil, errors.New("资源范围中的网站不存在")
			}
		}
	}
	var id, oldrole string
	var previous UserAccess
	if action == "create" {
		var exists bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE username=?)`, in.Username).Scan(&exists); e != nil {
			return nil, e
		}
		if exists {
			return nil, errors.New("用户名已存在")
		}
	} else {
		if e = tx.QueryRowContext(ctx, `SELECT u.id,COALESCE(r.role,'admin') FROM users u LEFT JOIN app_user_roles r ON r.user_id=u.id WHERE u.username=?`, in.Username).Scan(&id, &oldrole); e != nil {
			return nil, errors.New("用户不存在")
		}
		previous, e = readUserAccessContext(ctx, tx, id)
		if e != nil {
			return nil, e
		}
		if !menuSubset(previous.MenuIDs, actorAccess.MenuIDs) {
			return nil, errors.New("不能管理菜单权限高于自身的账户")
		}
		if in.ExpectedRevision != 0 && in.ExpectedRevision != previous.Revision {
			return nil, errors.New("账户授权已被修改，请刷新后重试")
		}
		if action == "update" && in.MenuIDs != nil && in.ExpectedRevision != previous.Revision {
			return nil, errors.New("修改菜单授权需要当前修订号")
		}
		if (action == "delete" || action == "update" && in.Role != "admin") && oldrole == "admin" {
			var admins int
			if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM users u LEFT JOIN app_user_roles r ON r.user_id=u.id WHERE COALESCE(r.role,'admin')='admin'`).Scan(&admins); e != nil {
				return nil, e
			}
			if admins <= 1 {
				return nil, errors.New("不能删除或降级最后一个管理员")
			}
		}
		if action == "delete" && id == actor.ID {
			return nil, errors.New("不能删除当前账户")
		}
	}
	var menuIDs []string
	if action == "create" || action == "update" {
		requested := in.MenuIDs
		if action == "update" && requested == nil {
			// An old client omitting the new field may not reset existing grants.
			requested = []string{}
			defaults, _ := normalizeMenuIDs(in.Role, nil)
			for _, menu := range previous.MenuIDs {
				if containsMenu(defaults, menu) {
					requested = append(requested, menu)
				}
			}
		}
		menuIDs, e = normalizeMenuIDs(in.Role, requested)
		if e != nil {
			return nil, e
		}
		if !menuSubset(menuIDs, actorAccess.MenuIDs) {
			return nil, errors.New("不能授予高于自身的菜单权限")
		}
	}
	if (action == "delete" || action == "update" && !fullAdministrator(UserAccess{Role: in.Role, MenuIDs: menuIDs})) && fullAdministrator(previous) {
		count, err := completeAdminCount(ctx, tx)
		if err != nil {
			return nil, err
		}
		if count <= 1 {
			return nil, errors.New("不能删除、降级或限制最后一个完整权限管理员")
		}
	}
	raw, _ := json.Marshal(in.SiteIDs)
	switch action {
	case "create":
		id = ID()
		if _, e = tx.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,created_at) VALUES(?,?,?,?)`, id, in.Username, passwordHash, Now()); e != nil {
			return nil, errors.New("账户创建写入失败；未提交，请刷新核对原账户及存储")
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO app_user_roles(user_id,role,site_ids) VALUES(?,?,?)`, id, in.Role, string(raw))
	case "update":
		_, e = tx.ExecContext(ctx, `INSERT INTO app_user_roles(user_id,role,site_ids) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET role=excluded.role,site_ids=excluded.site_ids`, id, in.Role, string(raw))
		if e == nil && in.Password != "" {
			_, e = tx.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=?`, passwordHash, id)
		}
		if e == nil {
			_, e = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id)
		}
	case "revoke":
		_, e = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id)
	case "delete":
		for _, table := range []string{"sessions", "account_recovery", "account_security", "account_profiles", "app_user_roles", "app_user_menus"} {
			if _, e = tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE user_id=?`, id); e != nil {
				return nil, e
			}
		}
		_, e = tx.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	default:
		return nil, errors.New("用户操作不被支持")
	}
	if e != nil {
		return nil, e
	}
	if action == "create" || action == "update" {
		menus, _ := json.Marshal(menuIDs)
		revision := int64(1)
		if action == "update" {
			revision = previous.Revision + 1
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO app_user_menus(user_id,menu_ids,revision) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET menu_ids=excluded.menu_ids,revision=excluded.revision`, id, string(menus), revision); e != nil {
			return nil, e
		}
	}
	if e = recordAppUserOutcomeTx(ctx, tx, actor.Username, action, nil); e != nil {
		return nil, errors.New("账户改动与审计未共同提交；拒绝提交，请核对原账户及存储")
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return map[string]any{"username": in.Username, "action": action, "ok": true}, nil
}
func (a *Server) appDailyReport(ctx context.Context) (any, error) {
	return a.appDailyReportAt(ctx, time.Now())
}

func (a *Server) appDailyReportAt(ctx context.Context, at time.Time) (any, error) {
	out := map[string]any{"created_at": at.UTC().Format(time.RFC3339)}
	var overview map[string]any
	if e := a.Executor.Call(ctx, "GET", "/v1/overview", nil, &overview); e != nil {
		return nil, e
	}
	out["resources"] = overview
	for name, q := range map[string]string{"sites": "SELECT count(*) FROM sites", "running_sites": "SELECT count(*) FROM sites WHERE status='running'", "failed_site_jobs": "SELECT count(*) FROM jobs WHERE state IN ('failed','needs_attention')", "failed_runtime_jobs": "SELECT count(*) FROM runtime_jobs WHERE state IN ('failed','needs_attention')", "audit_events_24h": "SELECT count(*) FROM audit_logs WHERE julianday(created_at)>=julianday('now','-1 day')"} {
		var n int
		if e := a.Store.DB.QueryRowContext(ctx, q).Scan(&n); e != nil {
			return nil, e
		}
		out[name] = n
	}
	for _, item := range []struct{ name, path string }{{"traffic", "/v1/sites/traffic"}, {"security", "/v1/software"}} {
		var report any
		var in any
		method := "GET"
		if item.name == "traffic" {
			ids, siteErr := a.Store.dailyTrafficSiteIDs(ctx)
			if siteErr != nil {
				out["traffic_error"] = "网站清单不可核对，未采集或当作零流量"
				continue
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
	if count, err := a.Store.dailyCertificatesDue(ctx, at); err == nil {
		out["certificates_due_14_days"] = count
	} else {
		out["certificates_error"] = "保存的证书清单或有效期无法完整核对；未按零个到期证书统计"
	}
	day := at.In(time.FixedZone("Asia/Shanghai", 8*3600)).Format("2006-01-02")
	return out, a.Store.saveDailyReportRecord(ctx, day, out)
}
func (a *Server) platformOperation(ctx context.Context, actor identity, action string, in AppModuleInput) (any, error) {
	access, err := readUserAccessContext(ctx, a.Store.DB, actor.ID)
	if err != nil {
		return nil, err
	}
	if access.Role != "admin" || !containsMenu(access.MenuIDs, "system-tools") {
		return nil, errors.New("需要当前管理员的系统工具授权")
	}
	if action == "token-list" {
		return a.Store.platformTokenList(ctx)
	}
	if action != "run" {
		if action != "issue-token" && action != "revoke-token" && action != "add" && action != "remove" {
			return nil, errors.New("多主机操作不被支持")
		}
		if action == "add" && !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(in.Token) {
			return nil, errors.New("只读令牌应为 64 位小写十六进制字符")
		}
		if action == "revoke-token" && (in.Token == "" && in.TokenID == "" || in.Token != "" && in.TokenID != "" || in.Token != "" && !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(in.Token) || in.TokenID != "" && !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(in.TokenID)) {
			return nil, errors.New("撤销须提供一个明确的 64 位授权标识或原令牌；不能同时填写")
		}
		if (action == "add" || action == "remove") && !regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`).MatchString(in.ResourceID) {
			return nil, errors.New("主机标识应为 3–32 位小写字母数字或短横线")
		}
		if (action == "add" || action == "remove") && in.ExpectedSHA != "" && !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(in.ExpectedSHA) {
			return nil, errors.New("原主机配置摘要无效，请只读刷新并选择原记录")
		}
		var encrypted []byte
		if action == "add" {
			u, err := url.Parse(in.URL)
			if err != nil || len(in.URL) > 2048 || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" {
				return nil, errors.New("主机必须使用无账号、查询或片段的 HTTPS 地址和只读令牌")
			}
			encrypted, err = encryptCredential(a.accountSecretKey, "app-host:"+in.ResourceID, []byte(in.Token))
			if err != nil {
				return nil, err
			}
		}
		tx, err := a.Store.DB.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		access, err = readUserAccessContext(ctx, tx, actor.ID)
		if err != nil {
			return nil, err
		}
		if access.Role != "admin" || !containsMenu(access.MenuIDs, "system-tools") {
			return nil, errors.New("多主机操作授权已变化")
		}
		if action == "add" || action == "remove" {
			var address, created string
			var original []byte
			err = tx.QueryRowContext(ctx, `SELECT url,token,created_at FROM app_platform_hosts WHERE id=?`, in.ResourceID).Scan(&address, &original, &created)
			if err != nil && err != sql.ErrNoRows {
				return nil, err
			}
			if err == nil && in.ExpectedSHA != platformHostIdentity(in.ResourceID, address, original, created) || err == sql.ErrNoRows && in.ExpectedSHA != "" {
				return nil, errors.New("原主机配置已变化、消失或尚未选择；拒绝覆盖或删除，请只读刷新核对")
			}
			err = nil
		}
		var out any
		switch action {
		case "issue-token":
			var count int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM app_platform_tokens`).Scan(&count); err != nil {
				return nil, err
			}
			if count >= 128 {
				return nil, errors.New("已达 128 个保留只读令牌上限；不自动删除旧授权，请先明确撤销")
			}
			token := Token()
			_, err = tx.ExecContext(ctx, `INSERT INTO app_platform_tokens(token_hash,created_at) VALUES(?,?)`, Hash(token), Now())
			out = map[string]any{"token": token, "token_id": Hash(token), "scope": "health-read-only", "endpoint": "/api/platform/agent"}
		case "revoke-token":
			tokenID := in.TokenID
			if in.Token != "" {
				tokenID = Hash(in.Token)
			}
			result, deleteErr := tx.ExecContext(ctx, `DELETE FROM app_platform_tokens WHERE token_hash=?`, tokenID)
			if deleteErr != nil {
				return nil, deleteErr
			}
			n, rowsErr := result.RowsAffected()
			if rowsErr != nil {
				return nil, rowsErr
			}
			out = map[string]any{"revoked": true, "token_id": tokenID, "already_absent": n == 0}
		case "add":
			var count int
			var exists bool
			if err = tx.QueryRowContext(ctx, `SELECT count(*),EXISTS(SELECT 1 FROM app_platform_hosts WHERE id=?) FROM app_platform_hosts`, in.ResourceID).Scan(&count, &exists); err != nil {
				return nil, err
			}
			if count > 12 || count == 12 && !exists {
				return nil, errors.New("最多管理 12 个主机；满额时仍可更新已登记主机，不自动删除原记录")
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO app_platform_hosts(id,url,token,created_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET url=excluded.url,token=excluded.token`, in.ResourceID, strings.TrimRight(in.URL, "/"), encrypted, Now())
			if err != nil {
				return nil, err
			}
			var created string
			if err = tx.QueryRowContext(ctx, `SELECT created_at FROM app_platform_hosts WHERE id=?`, in.ResourceID).Scan(&created); err != nil {
				return nil, err
			}
			out = map[string]any{"id": in.ResourceID, "url": in.URL, "expected_sha": platformHostIdentity(in.ResourceID, strings.TrimRight(in.URL, "/"), encrypted, created)}
		case "remove":
			result, deleteErr := tx.ExecContext(ctx, `DELETE FROM app_platform_hosts WHERE id=?`, in.ResourceID)
			if deleteErr != nil {
				return nil, deleteErr
			}
			n, rowsErr := result.RowsAffected()
			if rowsErr != nil {
				return nil, rowsErr
			}
			out = map[string]any{"removed": in.ResourceID, "already_absent": n == 0}
		}
		if err != nil {
			return nil, err
		}
		if err = recordCoreModuleOutcomeTx(ctx, tx, "platform-ops", actor.Username, action, nil); err != nil {
			return nil, errors.New("多主机改动与审计未共同提交；拒绝提交，请核对原记录及存储")
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return out, nil
	}
	rows, e := a.Store.DB.QueryContext(ctx, `SELECT id,url,token,created_at FROM app_platform_hosts ORDER BY id LIMIT 13`)
	if e != nil {
		return nil, e
	}
	hosts := []platformHealthHost{}
	for rows.Next() {
		var h platformHealthHost
		if e = rows.Scan(&h.id, &h.url, &h.token, &h.created); e != nil {
			rows.Close()
			return nil, e
		}
		hosts = append(hosts, h)
	}
	if e = rows.Err(); e != nil {
		rows.Close()
		return nil, e
	}
	rows.Close()
	client := platformHealthClient()
	defer client.CloseIdleConnections()
	out, err := readPlatformHealthFleet(ctx, hosts, func(ctx context.Context, h platformHealthHost) map[string]any {
		secret, e := decryptCredential(a.accountSecretKey, "app-host:"+h.id, h.token)
		if e != nil {
			return map[string]any{"id": h.id, "url": h.url, "expected_sha": platformHostIdentity(h.id, h.url, h.token, h.created), "healthy": false, "telemetry_complete": false, "error": "登记令牌无法解密；保留原记录，未发出请求"}
		}
		entry := readPlatformHealth(ctx, client, h.id, h.url, string(secret))
		entry["expected_sha"] = platformHostIdentity(h.id, h.url, h.token, h.created)
		return entry
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"hosts": out, "checked_at": Now(), "scope": "healthy 仅代表本次可信 HTTPS 与健康协议通过；指标可用性另行展示，不等于全部业务、网站或告警正常"}, nil
}
func (a *Server) platformAgent(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		fail(w, 401, "需要 Bearer 只读令牌")
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var count int
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(token) || a.Store.DB.QueryRowContext(r.Context(), `SELECT count(*) FROM app_platform_tokens WHERE token_hash=?`, Hash(token)).Scan(&count) != nil || count != 1 {
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
