package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"
)

type MenuPermission struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	AdminOnly bool   `json:"admin_only"`
}

// A menu grant is a ceiling, never an extension of the existing role/site scope.
func MenuPermissionCatalog() []MenuPermission {
	return []MenuPermission{{"overview", "概览", false}, {"sites", "网站", false}, {"databases", "数据库", true}, {"files", "文件", false}, {"security", "安全", true}, {"runtimes", "软件商店", true}, {"schedules", "计划任务", true}, {"monitor", "监控", false}, {"terminal", "终端", true}, {"panel-access", "面板设置与账户授权", true}, {"audit", "日志", true}, {"system-tools", "系统工具", true}}
}

type UserAccess struct {
	Role     string   `json:"role"`
	SiteIDs  []string `json:"site_ids"`
	MenuIDs  []string `json:"menu_ids"`
	Revision int64    `json:"revision"`
}

func normalizeMenuIDs(role string, input []string) ([]string, error) {
	if role != "admin" && role != "operator" && role != "viewer" {
		return nil, errors.New("账户角色无效，拒绝授权")
	}
	if len(input) > len(MenuPermissionCatalog()) {
		return nil, errors.New("菜单权限超过上限")
	}
	wanted := map[string]bool{}
	if input != nil {
		for _, id := range input {
			if wanted[id] {
				return nil, errors.New("菜单权限重复")
			}
			wanted[id] = true
		}
	}
	result := []string{}
	for _, menu := range MenuPermissionCatalog() {
		if input == nil {
			wanted[menu.ID] = role == "admin" || !menu.AdminOnly
		}
		if wanted[menu.ID] {
			if menu.AdminOnly && role != "admin" {
				return nil, errors.New("菜单不能扩大原角色权限")
			}
			result = append(result, menu.ID)
		}
		delete(wanted, menu.ID)
	}
	if len(wanted) != 0 {
		return nil, errors.New("未知菜单权限")
	}
	return result, nil
}

func parseMenuIDs(role, raw string) ([]string, error) {
	if len(raw) > 1024 {
		return nil, errors.New("菜单授权记录超过上限")
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil, errors.New("菜单授权记录损坏，拒绝访问")
	}
	return normalizeMenuIDs(role, ids)
}

type accessReader interface{ QueryRow(string, ...any) *sql.Row }

func readUserAccess(db accessReader, id string) (UserAccess, error) {
	var access UserAccess
	var sites, menus string
	err := db.QueryRow(`SELECT COALESCE(r.role,'admin'),COALESCE(r.site_ids,'[]'),COALESCE(m.menu_ids,'null'),COALESCE(m.revision,1) FROM users u LEFT JOIN app_user_roles r ON r.user_id=u.id LEFT JOIN app_user_menus m ON m.user_id=u.id WHERE u.id=?`, id).Scan(&access.Role, &sites, &menus, &access.Revision)
	if err != nil {
		return access, err
	}
	if err = json.Unmarshal([]byte(sites), &access.SiteIDs); err != nil {
		return access, err
	}
	access.MenuIDs, err = parseMenuIDs(access.Role, menus)
	return access, err
}
func (s *Store) UserAccess(id string) (UserAccess, error) { return readUserAccess(s.DB, id) }
func containsMenu(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
func menuSubset(ids, ceiling []string) bool {
	for _, id := range ids {
		if !containsMenu(ceiling, id) {
			return false
		}
	}
	return true
}
func fullAdministrator(access UserAccess) bool {
	return access.Role == "admin" && len(access.MenuIDs) == len(MenuPermissionCatalog())
}

func ModuleMenu(id string) string {
	switch id {
	case "user-manager":
		return "panel-access"
	case "site-diagnosis", "website-analytics", "website-statistics-v2":
		return "sites"
	case "daily-report":
		return "audit"
	case "file-monitor", "website-tamper-proof", "enterprise-tamper-proof", "network-threat-detection", "nginx-waf", "apache-waf", "php-code-security", "system-hardening", "intrusion-prevention", "anti-intrusion":
		return "security"
	case "files-sync", "load-balance", "task-manager", "disk-analysis", "platform-ops", "nfs-manager", "pm2-manager", "docker-manager":
		return "system-tools"
	case "pure-ftpd":
		return "files"
	case "mobile-pwa", "mobile":
		return "runtimes"
	}
	return ""
}

// Exact roots, not substring tests: an unknown future route is denied to a
// limited administrator. The legacy unrestricted administrator remains usable.
func requestMenus(r *http.Request) ([]string, bool) {
	p := r.URL.Path
	if path.Clean(p) != p {
		return nil, false
	}
	if p == "/api/me" || p == "/api/logout" || p == "/api/account" || strings.HasPrefix(p, "/api/account/") || p == "/api/session/activity" {
		return []string{}, false
	}
	parts := strings.Split(strings.TrimPrefix(p, "/api/"), "/")
	if !strings.HasPrefix(p, "/api/") || len(parts) == 0 {
		return nil, false
	}
	root := parts[0]
	if root == "sites" {
		if len(parts) == 1 && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			return []string{"sites", "files"}, true
		}
		if len(parts) >= 3 && ValidID(parts[1]) {
			switch parts[2] {
			case "files":
				return []string{"files"}, false
			case "logs":
				return []string{"audit"}, false
			case "waf":
				return []string{"security"}, false
			}
		}
		return []string{"sites"}, false
	}
	if root == "app-modules" && len(parts) >= 2 {
		if menu := ModuleMenu(parts[1]); menu != "" {
			return []string{menu}, false
		}
		return nil, false
	}
	if root == "software" || root == "app-registry" {
		ids := []string{"runtimes"}
		if len(parts) >= 2 {
			if menu := ModuleMenu(parts[1]); menu != "" && menu != "runtimes" {
				ids = append(ids, menu)
			}
		}
		return ids, false
	}
	switch root {
	case "overview":
		return []string{"overview"}, false
	case "monitor":
		return []string{"monitor"}, false
	case "databases", "mariadb", "redis":
		return []string{"databases"}, false
	case "filesystem", "sftp":
		return []string{"files"}, false
	case "security":
		return []string{"security"}, false
	case "runtimes", "php":
		return []string{"runtimes"}, false
	case "schedules":
		return []string{"schedules"}, false
	case "terminal":
		return []string{"terminal"}, false
	case "panel-access", "notification-settings", "notification-channels", "session-policy":
		return []string{"panel-access"}, false
	case "audit", "jobs", "notifications":
		return []string{"audit"}, false
	case "backups", "docker", "node":
		return []string{"system-tools"}, false
	case "certificates", "acme", "analytics":
		return []string{"sites"}, false
	case "system":
		if len(parts) >= 2 && parts[1] == "files" {
			return []string{"files"}, false
		}
		return []string{"system-tools"}, false
	}
	return nil, false
}

func accessAllowsMenus(access UserAccess, r *http.Request) bool {
	menus, any := requestMenus(r)
	if menus == nil {
		return fullAdministrator(access) && path.Clean(r.URL.Path) == r.URL.Path
	}
	if any {
		for _, menu := range menus {
			if containsMenu(access.MenuIDs, menu) {
				return true
			}
		}
		return false
	}
	return menuSubset(menus, access.MenuIDs)
}

func completeAdminCount(tx *sql.Tx) (int, error) {
	rows, err := tx.Query(`SELECT COALESCE(r.role,'admin'),COALESCE(m.menu_ids,'null') FROM users u LEFT JOIN app_user_roles r ON r.user_id=u.id LEFT JOIN app_user_menus m ON m.user_id=u.id`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var role, raw string
		if err = rows.Scan(&role, &raw); err != nil {
			return 0, err
		}
		ids, parseErr := parseMenuIDs(role, raw)
		if parseErr == nil && fullAdministrator(UserAccess{Role: role, MenuIDs: ids}) {
			count++
		}
	}
	return count, rows.Err()
}
