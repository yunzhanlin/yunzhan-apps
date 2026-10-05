package core

import (
	"database/sql"
	"errors"
	"fmt"
)

func (s *Store) migrateAppSites() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS app_site_bindings(
site_id TEXT PRIMARY KEY REFERENCES sites(id),
project_id TEXT NOT NULL UNIQUE,
host_port INTEGER NOT NULL CHECK(host_port BETWEEN 1024 AND 65535),
created_at TEXT NOT NULL);
INSERT OR IGNORE INTO schema_migrations VALUES(28,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

func (s *Store) CreateAppProxySite(name, slug, domain, projectID string, port int, key, actor string) (string, error) {
	if !ValidID(projectID) || port < 1024 || port > 65535 || key == "" || len(key) > 128 {
		return "", errors.New("应用项目、回环端口或幂等键无效")
	}
	if !ValidDomain(domain) {
		return "", errors.New("请填写有效的网站主域名")
	}
	settings := SiteSettings{Mode: "proxy", ProxyURL: fmt.Sprintf("http://127.0.0.1:%d", port), ProxyPreserveHost: true, WebServer: "nginx"}
	return s.createSiteAtDomain(name, slug, domain, key, actor, "", &settings, projectID, port)
}

func (s *Store) ProjectSiteReference(projectID string) (string, error) {
	if !ValidID(projectID) {
		return "", errors.New("应用项目标识无效")
	}
	var name string
	e := s.DB.QueryRow(`SELECT s.name FROM app_site_bindings b JOIN sites s ON s.id=b.site_id WHERE b.project_id=?`, projectID).Scan(&name)
	if errors.Is(e, sql.ErrNoRows) {
		return "", nil
	}
	return name, e
}

func finishAppSiteBinding(tx *sql.Tx, siteID string, settings SiteSettings) error {
	var port int
	e := tx.QueryRow(`SELECT host_port FROM app_site_bindings WHERE site_id=?`, siteID).Scan(&port)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	if settings.Mode == "proxy" && settings.WebServer == "nginx" && settings.ProxyURL == fmt.Sprintf("http://127.0.0.1:%d", port) && settings.ProxyPreserveHost {
		return nil
	}
	_, e = tx.Exec(`DELETE FROM app_site_bindings WHERE site_id=?`, siteID)
	return e
}
