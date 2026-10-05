package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"local/panel/internal/runtimecatalog"
	"strings"
)

type JobPayload struct {
	ArchiveDomain     string        `json:"archive_domain,omitempty"`
	SiteBackup        *SiteBackup   `json:"site_backup,omitempty"`
	Settings          *SiteSettings `json:"settings,omitempty"`
	ExpectedRevision  int64         `json:"expected_revision,omitempty"`
	ExpectedConfigSHA string        `json:"expected_config_sha,omitempty"`
	ReleaseID         string        `json:"release_id"`
	PreviousStatus    string        `json:"previous_status,omitempty"`
	AppProjectID      string        `json:"app_project_id,omitempty"`
	AppHostPort       int           `json:"app_host_port,omitempty"`
}

// This migration is additive: original sites and jobs remain in place.
func (s *Store) migrate() error {
	var n int
	if e := s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=2`).Scan(&n); e != nil {
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
	_, e = tx.Exec(`
 ALTER TABLE sites ADD COLUMN php_version_id TEXT NOT NULL DEFAULT '';
 ALTER TABLE jobs ADD COLUMN payload TEXT NOT NULL DEFAULT '{}';
 CREATE TABLE runtime_jobs(id TEXT PRIMARY KEY, target_id TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', steps TEXT NOT NULL DEFAULT '[]', idempotency_key TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
 CREATE UNIQUE INDEX one_active_runtime_job ON runtime_jobs(target_id) WHERE state IN ('queued','running');
 INSERT INTO schema_migrations VALUES(2,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
 `)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) RuntimeInstalled(id string) bool {
	var n int
	_ = s.DB.QueryRow(`SELECT count(*) FROM runtime_installations i WHERE id=? AND status='installed' AND NOT EXISTS(SELECT 1 FROM runtime_jobs j WHERE j.target_id=i.id AND j.kind IN ('retire_runtime','restore_runtime') AND j.state IN ('queued','running','needs_attention'))`, id).Scan(&n)
	return n == 1
}
func (s *Store) RecordInstallation(r runtimecatalog.Release, arch string) error {
	return s.recordInstallation(r, arch, true)
}
func (s *Store) RecordObservedInstallation(r runtimecatalog.Release, arch string) error {
	return s.recordInstallation(r, arch, false)
}
func (s *Store) recordInstallation(r runtimecatalog.Release, arch string, committed bool) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	verification := "sha256:" + r.SHA256
	if r.Family == "docker" {
		spec, ok := runtimecatalog.DockerSpecOn(runtimecatalog.HostDebianMajor())
		if !ok || !runtimecatalog.DockerAvailableOn(runtimecatalog.HostDebianMajor()) || spec.ReleaseID != r.ID {
			return errors.New("当前 Debian 版本尚未适配此 Docker 固定包")
		}
		verification = "debian-package:" + strings.Join(spec.Packages, ";")
	}
	_, e = tx.Exec(`INSERT INTO runtime_versions(id,family,version,channel,source_url,verification) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET verification=excluded.verification`, r.ID, r.Family, r.Version, r.Channel, r.URL, verification)
	if e != nil {
		return e
	}
	_, e = tx.Exec(`INSERT INTO runtime_installations(id,version_id,binary_path,architecture,detected_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET detected_at=excluded.detected_at,status=CASE WHEN ? THEN 'installed' ELSE runtime_installations.status END`, r.ID, r.ID, r.CLI(), arch, Now(), committed)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) QueueInstall(release, key, actor string) (string, error) {
	runtimeRelease, ok := runtimecatalog.Find(release)
	if !ok {
		return "", errors.New("该版本尚未支持安装")
	}
	if runtimeRelease.Family == "docker" {
		spec, available := runtimecatalog.DockerSpecOn(runtimecatalog.HostDebianMajor())
		if !available || !runtimecatalog.DockerAvailableOn(runtimecatalog.HostDebianMajor()) || spec.ReleaseID != runtimeRelease.ID {
			return "", errors.New("当前 Debian 版本尚未适配此 Docker 固定包")
		}
	}
	if key == "" || len(key) > 128 {
		return "", errors.New("请提供有效的幂等键")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var id, target, kind string
	e = tx.QueryRow(`SELECT id,target_id,kind FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&id, &target, &kind)
	if e == nil {
		if target != release || kind != "install_runtime" {
			return "", errors.New("幂等键已被不同请求使用")
		}
		return id, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return "", e
	}
	id = ID()
	_, e = tx.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,created_at,updated_at) VALUES(?,?,'install_runtime','queued',?,?,?)`, id, release, key, Now(), Now())
	if e != nil {
		return "", errors.New("该版本已有安装任务")
	}
	_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'runtime.install',?,'queued',?)`, actor, release, Now())
	if e != nil {
		return "", e
	}
	return id, tx.Commit()
}
func (s *Store) QueuePHP(id, release, actor string) (string, error) {
	if release != "" {
		if r, ok := runtimecatalog.Find(release); !ok || r.Family != "php" || !s.RuntimeInstalled(release) {
			return "", errors.New("请先安装所选 PHP 精确版本")
		}
	}
	site, e := s.Site(id)
	if e != nil {
		return "", errors.New("站点不存在")
	}
	if e = ValidateSiteSettings(site.Settings, site.Domain, release); e != nil {
		return "", e
	}
	if e = s.validatePHPExtensions(release, site.Settings.PHP); e != nil {
		return "", e
	}
	if e = s.validateSiteCertificate(site.Domain, site.Settings); e != nil {
		return "", e
	}
	if site.Status != "running" && site.Status != "stopped" {
		return "", errors.New("请先处理该站点已有异常或创建任务")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	jobID := ID()
	p, _ := json.Marshal(JobPayload{ReleaseID: release, PreviousStatus: site.Status})
	_, e = tx.Exec(`INSERT INTO jobs(id,site_id,payload,kind,state,created_at,updated_at) VALUES(?,?,?,'switch_php','queued',?,?)`, jobID, id, string(p), Now(), Now())
	if e != nil {
		return "", errors.New("该站点已有运行中的任务")
	}
	_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'site.php.switch',?,'queued',?)`, actor, site.Domain+" -> "+release, Now())
	if e != nil {
		return "", e
	}
	return jobID, tx.Commit()
}
func (s *Store) UpdateRuntimeSteps(id string, steps []Step) error {
	b, e := json.Marshal(steps)
	if e != nil {
		return e
	}
	_, e = s.DB.Exec(`UPDATE runtime_jobs SET steps=?,updated_at=? WHERE id=?`, string(b), Now(), id)
	return e
}
func (s *Store) FinishRuntime(j Job, detail string, steps []Step) error {
	return s.finishRuntime(j, detail, steps, false)
}
func (s *Store) finishRuntime(j Job, detail string, steps []Step, uncertain bool) error {
	state := "succeeded"
	if detail != "" {
		state = "failed"
	}
	if uncertain {
		state = "needs_attention"
	}
	b, _ := json.Marshal(steps)
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`UPDATE runtime_jobs SET state=?,error=?,steps=?,updated_at=? WHERE id=?`, state, detail, string(b), Now(), j.ID)
	if e != nil {
		return e
	}
	_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('executor',?,?,?,?)`, j.Kind, j.TargetID, state, Now())
	if e != nil {
		return e
	}
	if detail == "" {
		if e = finishRuntimeLifecycle(tx, j); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) NextRuntimeJob() (Job, error) {
	return s.nextRuntimeJob("")
}

func (s *Store) nextRuntimeInstallJob() (Job, error) {
	return s.nextRuntimeJob(" AND (kind IN ('install_runtime','install_php_extension') OR (kind='software_install' AND target_id IN ('pure-ftpd','pm2-manager','nfs-manager')))")
}

func (s *Store) nextRuntimeControlJob() (Job, error) {
	return s.nextRuntimeJob(" AND NOT (kind IN ('install_runtime','install_php_extension') OR (kind='software_install' AND target_id IN ('pure-ftpd','pm2-manager','nfs-manager')))")
}

// The predicates above are fixed internal SQL, never request parameters.
func (s *Store) nextRuntimeJob(predicate string) (Job, error) {
	var j Job
	e := s.DB.QueryRow(`SELECT id,target_id,kind,payload FROM runtime_jobs WHERE state='queued'`+predicate+` ORDER BY created_at,rowid LIMIT 1`).Scan(&j.ID, &j.TargetID, &j.Kind, &j.Payload)
	if e != nil {
		return j, e
	}
	r, e := s.DB.Exec(`UPDATE runtime_jobs SET state='running',updated_at=? WHERE id=? AND state='queued'`, Now(), j.ID)
	if e != nil {
		return j, e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return j, errors.New("任务已被领取")
	}
	return j, nil
}
func (s *Store) RetryRuntime(id, actor string) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.Exec(`UPDATE runtime_jobs SET state='queued',error='',updated_at=? WHERE id=? AND state IN ('failed','needs_attention')`, Now(), id)
	if e != nil {
		return errors.New("该版本已有进行中的任务")
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("任务不存在或当前状态不能重试")
	}
	_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'job.retry',?,'queued',?)`, actor, id, Now())
	if e != nil {
		return e
	}
	return tx.Commit()
}
func bindPHP(tx *sql.Tx, siteID, release string) error {
	instance := "static"
	if release != "" {
		if r, ok := runtimecatalog.Find(release); !ok || r.Family != "php" {
			return errors.New("无效版本")
		}
		var raw string
		if e := tx.QueryRow(`SELECT settings_json FROM sites WHERE id=?`, siteID).Scan(&raw); e != nil {
			return e
		}
		var settings SiteSettings
		if e := json.Unmarshal([]byte(raw), &settings); e != nil {
			return e
		}
		instance = PHPInstanceID(Site{ID: siteID, PHPVersionID: release, Settings: settings})
		_, e := tx.Exec(`INSERT INTO runtime_instances(id,installation_id,family,name,service_name,socket_path,data_dir,config_path) VALUES(?,?,'php',?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, instance, release, instance, "panel-php@"+instance+".service", "/run/panel-php-"+instance+"/fpm.sock", "/srv/panel/sites/"+siteID, "/etc/panel/php-sites/"+instance+"/fpm.conf")
		if e != nil {
			return e
		}
	}
	_, e := tx.Exec(`UPDATE sites SET php_version_id=?,runtime_instance_id=? WHERE id=?`, release, instance, siteID)
	return e
}

func (s *Store) QueueNginx(release, key, actor string) (string, error) {
	if release != "nginx-system" {
		r, ok := runtimecatalog.Find(release)
		if !ok || r.Family != "nginx" {
			return "", errors.New("请选择 Nginx 版本")
		}
	}
	if !s.RuntimeInstalled(release) {
		return "", errors.New("请先安装目标 Nginx 版本")
	}
	if key == "" || len(key) > 128 {
		return "", errors.New("请提供有效幂等键")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var existing, target, kind string
	e = tx.QueryRow(`SELECT id,target_id,kind FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&existing, &target, &kind)
	if e == nil {
		if target != release || kind != "switch_nginx" {
			return "", errors.New("幂等键已用于其他请求")
		}
		return existing, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return "", e
	}
	var n int
	if e = tx.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE kind='switch_nginx' AND state IN ('queued','running')`).Scan(&n); e != nil {
		return "", e
	}
	if n > 0 {
		return "", errors.New("已有 Nginx 入口切换任务")
	}
	id := ID()
	_, e = tx.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,created_at,updated_at) VALUES(?,?,'switch_nginx','queued',?,?,?)`, id, release, key, Now(), Now())
	if e != nil {
		return "", errors.New("该版本已有进行中的任务")
	}
	_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'nginx.switch',?,'queued',?)`, actor, release, Now())
	if e != nil {
		return "", e
	}
	return id, tx.Commit()
}
func (s *Store) RecordNginxActive(id string) error {
	if !s.RuntimeInstalled(id) {
		return errors.New("当前 Nginx 安装记录不存在")
	}
	_, e := s.DB.Exec(`UPDATE runtime_instances SET installation_id=? WHERE id='nginx-ingress'`, id)
	return e
}
