package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

type SiteArchiveRequest struct {
	Site  Site   `json:"site"`
	JobID string `json:"job_id"`
}

func (s *Store) migrateSiteArchives() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS site_archives(
site_id TEXT PRIMARY KEY REFERENCES sites(id),
original_slug TEXT NOT NULL,
original_domain TEXT NOT NULL,
php_version_id TEXT NOT NULL,
runtime_instance_id TEXT NOT NULL,
archived_at TEXT NOT NULL);
INSERT OR IGNORE INTO schema_migrations VALUES(29,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

func (s *Store) QueueSiteArchive(id, confirmDomain, key, actor string) (string, error) {
	if !ValidID(id) || key == "" || len(key) > 128 {
		return "", errors.New("网站或幂等键无效")
	}
	var oldID, oldSite, oldKind, oldPayload string
	e := s.DB.QueryRow(`SELECT id,site_id,kind,payload FROM jobs WHERE idempotency_key=?`, key).Scan(&oldID, &oldSite, &oldKind, &oldPayload)
	if e == nil {
		var p JobPayload
		if json.Unmarshal([]byte(oldPayload), &p) == nil && oldSite == id && oldKind == "archive_site" && p.ArchiveDomain == confirmDomain {
			return oldID, nil
		}
		return "", errors.New("幂等键已被不同请求使用")
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return "", e
	}
	site, e := s.Site(id)
	if e != nil {
		return "", errors.New("网站不存在")
	}
	if site.Domain != confirmDomain || (site.Status != "running" && site.Status != "stopped") {
		return "", errors.New("请填写完整主域名，并先处理网站的未完成任务")
	}
	if site.Settings.WebServer != "nginx" {
		return "", errors.New("Apache 网站归档尚未开放，请先在网站设置中切回 Nginx")
	}
	if site.PHPVersionID != "" {
		return "", errors.New("PHP 网站归档尚未开放，请先解绑站点 PHP")
	}
	dependencies := []struct{ table, where, label string }{
		{"sftp_accounts", "site_id=?", "SFTP 用户"},
		{"site_backups", "site_id=?", "网站备份"},
		{"acme_orders", "site_id=?", "ACME 证书订单"},
		{"acme_renewals", "site_id=?", "自动续期"},
		{"site_schedule_cleanup_jobs", "site_id=? AND state='pending'", "待清理的计划产物"},
		{"schedule_php_scripts", "site_id=? AND schedule_id IN (SELECT id FROM schedules WHERE deleted_at=0)", "网站 PHP 脚本计划"},
		{"schedules", "target_id=? AND kind IN ('site_backup','log_cleanup') AND deleted_at=0", "网站计划任务"},
	}
	for _, dep := range dependencies {
		var n int
		if e = s.DB.QueryRow(`SELECT count(*) FROM `+dep.table+` WHERE `+dep.where, id).Scan(&n); e != nil {
			return "", e
		}
		if n != 0 {
			return "", fmt.Errorf("请先处理该网站的%s，再归档网站", dep.label)
		}
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	jobID, now := ID(), Now()
	payload, _ := json.Marshal(JobPayload{ArchiveDomain: confirmDomain})
	if _, e = tx.Exec(`INSERT INTO jobs(id,site_id,kind,state,idempotency_key,created_at,updated_at,payload) VALUES(?,?,'archive_site','queued',?,?,?,?)`, jobID, id, key, now, now, string(payload)); e != nil {
		return "", errors.New("网站已有执行中的任务")
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'site.archive',?,'queued',?)`, actor, confirmDomain, now); e != nil {
		return "", e
	}
	return jobID, tx.Commit()
}

func finishSiteArchive(tx *sql.Tx, siteID string) error {
	var slug, domain, php, runtime string
	if e := tx.QueryRow(`SELECT slug,domain,php_version_id,runtime_instance_id FROM sites WHERE id=?`, siteID).Scan(&slug, &domain, &php, &runtime); e != nil {
		return e
	}
	if _, e := tx.Exec(`INSERT OR IGNORE INTO site_archives(site_id,original_slug,original_domain,php_version_id,runtime_instance_id,archived_at) VALUES(?,?,?,?,?,?)`, siteID, slug, domain, php, runtime, Now()); e != nil {
		return e
	}
	if _, e := tx.Exec(`DELETE FROM site_domains WHERE site_id=?`, siteID); e != nil {
		return e
	}
	if _, e := tx.Exec(`DELETE FROM app_site_bindings WHERE site_id=?`, siteID); e != nil {
		return e
	}
	_, e := tx.Exec(`UPDATE sites SET slug=?,domain=?,php_version_id='',runtime_instance_id='static' WHERE id=?`, "archived-"+siteID[:23], "archived-"+siteID+".invalid", siteID)
	return e
}
