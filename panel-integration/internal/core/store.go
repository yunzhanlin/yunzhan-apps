package core

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/runtimecatalog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Site struct {
	Settings          SiteSettings `json:"settings"`
	SettingsRevision  int64        `json:"settings_revision"`
	PHPVersionID      string       `json:"php_version_id"`
	ID                string       `json:"id"`
	Name              string       `json:"name"`
	Domain            string       `json:"domain"`
	Slug              string       `json:"slug"`
	Status            string       `json:"status"`
	CreatedAt         string       `json:"created_at"`
	UpdatedAt         string       `json:"updated_at"`
	RuntimeInstanceID string       `json:"runtime_instance_id"`
}
type Step struct {
	Time    string `json:"time"`
	Message string `json:"message"`
}
type Job struct {
	TargetID     string `json:"target_id"`
	Payload      string `json:"-"`
	DatabaseName string `json:"database_name,omitempty"`
	BackupBytes  *int64 `json:"backup_bytes,omitempty"`
	ID           string `json:"id"`
	SiteID       string `json:"site_id"`
	SiteName     string `json:"site_name"`
	Kind         string `json:"kind"`
	State        string `json:"state"`
	Error        string `json:"error"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	Steps        []Step `json:"steps"`
}
type Store struct {
	DB            *sql.DB
	encryptionKey []byte
}

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)
var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func ValidID(s string) bool { return idPattern.MatchString(s) }
func ValidateSite(name, slug string) error {
	if len([]rune(strings.TrimSpace(name))) < 1 || len([]rune(name)) > 60 {
		return errors.New("站点名称应为 1–60 个字符")
	}
	if !slugPattern.MatchString(slug) {
		return errors.New("站点标识需为 3–32 位小写字母、数字或连字符，以字母开头")
	}
	return nil
}
func ID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func Token() string        { return ID() + ID() }
func Hash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func Now() string          { return time.Now().UTC().Format(time.RFC3339) }
func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash BLOB NOT NULL, created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS runtime_versions(id TEXT PRIMARY KEY, family TEXT NOT NULL, version TEXT NOT NULL, channel TEXT NOT NULL, source_url TEXT NOT NULL, verification TEXT NOT NULL, UNIQUE(family,version));
 CREATE TABLE IF NOT EXISTS runtime_installations(id TEXT PRIMARY KEY, version_id TEXT NOT NULL REFERENCES runtime_versions(id), binary_path TEXT NOT NULL, architecture TEXT NOT NULL, detected_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS runtime_instances(id TEXT PRIMARY KEY, installation_id TEXT REFERENCES runtime_installations(id), family TEXT NOT NULL, name TEXT NOT NULL, service_name TEXT NOT NULL, port INTEGER, socket_path TEXT, data_dir TEXT, config_path TEXT, UNIQUE(family,name));
 CREATE TABLE IF NOT EXISTS database_instances(id TEXT PRIMARY KEY REFERENCES runtime_instances(id), engine TEXT NOT NULL, credential_ref TEXT);
 CREATE TABLE IF NOT EXISTS sites(id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, domain TEXT NOT NULL UNIQUE, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, runtime_instance_id TEXT NOT NULL DEFAULT 'static');
 CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES sites(id), kind TEXT NOT NULL, state TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', steps TEXT NOT NULL DEFAULT '[]', idempotency_key TEXT UNIQUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
 CREATE UNIQUE INDEX IF NOT EXISTS one_active_site_job ON jobs(site_id) WHERE state IN ('queued','running');
 CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, result TEXT NOT NULL, created_at TEXT NOT NULL);
 INSERT OR IGNORE INTO schema_migrations VALUES(1, strftime('%Y-%m-%dT%H:%M:%SZ','now'));
 `)
	if err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{DB: db}
	if err = s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateDatabases(); err != nil {
		s.DB.Close()
		return nil, err
	}
	if err = s.migrateDatabaseConnectionHistory(); err != nil {
		s.DB.Close()
		return nil, err
	}
	if err = s.migrateSiteSettings(); err != nil {
		s.DB.Close()
		return nil, err
	}
	if err = s.migrateRuntimeLifecycle(); err != nil {
		s.DB.Close()
		return nil, err
	}
	if err = s.migratePHPExtensions(); err != nil {
		s.DB.Close()
		return nil, err
	}
	if err = s.migrateAccountSecurity(); err != nil {
		s.DB.Close()
		return nil, err
	}
	if err = s.migrateAccountProfile(); err != nil {
		s.DB.Close()
		return nil, err
	}
	if err = s.migrateSessionPolicy(); err != nil {
		s.DB.Close()
		return nil, err
	}
	if err = s.migrateCertificates(); err != nil {
		s.DB.Close()
		return nil, err
	}
	if err = s.migrateACME(); err != nil {
		s.DB.Close()
		return nil, err
	}
	if err = s.migrateDatabaseImports(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateDatabaseAccounts(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateDatabaseLifecycle(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateDatabaseOverwrite(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateMonitoring(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateMonitorDiskIO(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateSchedules(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateRemoteBackups(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migratePanelAccess(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateSecurity(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateSystemBackups(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateSFTP(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateNotifications(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateRuntimeBundles(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateAppSites(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateSiteArchives(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateLoginEvents(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrateSiteSecurityScan(); err != nil {
		db.Close()
		return nil, err
	}
	if err=s.migrateAppModules();err!=nil{db.Close();return nil,err}
	return s, nil
}
func (s *Store) Audit(actor, action, target, result string) error {
	_, err := s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,?,?)`, actor, action, target, result, Now())
	return err
}
func (s *Store) UserCount() int {
	var n int
	_ = s.DB.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n
}
func (s *Store) Site(id string) (Site, error) {
	var x Site
	var settings string
	err := s.DB.QueryRow(`SELECT id,name,domain,slug,status,created_at,updated_at,runtime_instance_id,php_version_id,settings_json,settings_revision FROM sites WHERE id=? AND status!='archived'`, id).Scan(&x.ID, &x.Name, &x.Domain, &x.Slug, &x.Status, &x.CreatedAt, &x.UpdatedAt, &x.RuntimeInstanceID, &x.PHPVersionID, &settings, &x.SettingsRevision)
	if err == nil {
		err = json.Unmarshal([]byte(settings), &x.Settings)
		x.Settings = DefaultSiteSettings(x.Settings)
	}
	return x, err
}
func (s *Store) Sites() ([]Site, error) {
	rows, err := s.DB.Query(`SELECT id,name,domain,slug,status,created_at,updated_at,runtime_instance_id,php_version_id,settings_json,settings_revision FROM sites WHERE status!='archived' ORDER BY created_at DESC,rowid DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Site{}
	for rows.Next() {
		var x Site
		var settings string
		if err = rows.Scan(&x.ID, &x.Name, &x.Domain, &x.Slug, &x.Status, &x.CreatedAt, &x.UpdatedAt, &x.RuntimeInstanceID, &x.PHPVersionID, &settings, &x.SettingsRevision); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(settings), &x.Settings); err != nil {
			return nil, err
		}
		x.Settings = DefaultSiteSettings(x.Settings)
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Store) CreateSite(name, slug, key, actor string, php ...string) (string, error) {
	return s.CreateSiteAtDomain(name, slug, "", key, actor, php...)
}
func (s *Store) CreateSiteAtDomain(name, slug, domain, key, actor string, php ...string) (string, error) {
	release := ""
	if len(php) > 0 {
		release = php[0]
	}
	return s.createSiteAtDomain(name, slug, domain, key, actor, release, nil, "", 0)
}
func (s *Store) createSiteAtDomain(name, slug, domain, key, actor, release string, initial *SiteSettings, appProjectID string, appHostPort int) (string, error) {
	if domain == "" {
		domain = slug + ".localhost"
	}
	if !ValidDomain(domain) {
		return "", errors.New("主域名需为小写完整域名，不含协议、端口或路径，国际域名请使用 Punycode")
	}
	if r, ok := runtimecatalog.Find(release); release != "" && (!ok || r.Family != "php" || !s.RuntimeInstalled(release)) {
		return "", errors.New("请先安装所选 PHP 版本")
	}
	if err := ValidateSite(name, slug); err != nil {
		return "", err
	}
	settingsJSON := "{}"
	if initial != nil {
		normalized := DefaultSiteSettings(*initial)
		if e := ValidateSiteSettings(normalized, domain, release); e != nil {
			return "", e
		}
		initial = &normalized
		encoded, e := json.Marshal(initial)
		if e != nil {
			return "", e
		}
		settingsJSON = string(encoded)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if key != "" {
		var id string
		var storedName, storedSlug, storedDomain, payload string
		err = tx.QueryRow(`SELECT jobs.id,sites.name,sites.slug,sites.domain,jobs.payload FROM jobs JOIN sites ON jobs.site_id=sites.id WHERE idempotency_key=?`, key).Scan(&id, &storedName, &storedSlug, &storedDomain, &payload)
		if err == nil {
			var p JobPayload
			_ = json.Unmarshal([]byte(payload), &p)
			storedSettings, _ := json.Marshal(p.Settings)
			requestedSettings, _ := json.Marshal(initial)
			if storedName != name || storedSlug != slug || storedDomain != domain || p.ReleaseID != release || string(storedSettings) != string(requestedSettings) || p.AppProjectID != appProjectID || p.AppHostPort != appHostPort {
				return "", errors.New("幂等键已被不同请求使用")
			}
			return id, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
	}
	siteID, jobID, now := ID(), ID(), Now()
	_, err = tx.Exec(`INSERT INTO sites(id,name,slug,domain,status,created_at,updated_at,settings_json) VALUES(?,?,?,?,?,?,?,?)`, siteID, name, slug, domain, "provisioning", now, now, settingsJSON)
	if err != nil {
		return "", errors.New("站点标识或域名已存在")
	}
	if _, err = tx.Exec(`INSERT INTO site_domains(domain,site_id) VALUES(?,?)`, domain, siteID); err != nil {
		return "", errors.New("域名已被其他站点绑定或预留")
	}
	if appProjectID != "" {
		if _, err = tx.Exec(`INSERT INTO app_site_bindings(site_id,project_id,host_port,created_at) VALUES(?,?,?,?)`, siteID, appProjectID, appHostPort, now); err != nil {
			return "", errors.New("该应用项目已绑定网站")
		}
	}
	var idem any
	if key != "" {
		idem = key
	}
	payload, _ := json.Marshal(JobPayload{ReleaseID: release, Settings: initial, AppProjectID: appProjectID, AppHostPort: appHostPort})
	_, err = tx.Exec(`INSERT INTO jobs(id,site_id,kind,state,idempotency_key,created_at,updated_at,payload) VALUES(?,?,'create_site','queued',?,?,?,?)`, jobID, siteID, idem, now, now, string(payload))
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'site.create',?,'queued',?)`, actor, domain, now)
	if err != nil {
		return "", err
	}
	return jobID, tx.Commit()
}
func (s *Store) QueueSiteAction(id, kind, actor string) (string, error) {
	if kind != "enable_site" && kind != "disable_site" {
		return "", errors.New("不支持的操作")
	}
	x, err := s.Site(id)
	if err != nil {
		return "", errors.New("站点不存在")
	}
	if x.Status == "provisioning" {
		return "", errors.New("站点尚未完成创建，请先处理创建任务")
	}
	if x.Status == "needs_attention" {
		return "", errors.New("请先核对并重试异常任务")
	}
	jobID, now := ID(), Now()
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO jobs(id,site_id,kind,state,created_at,updated_at) VALUES(?,?,?,'queued',?,?)`, jobID, id, kind, now, now)
	if err != nil {
		return "", errors.New("该站点已有运行中的任务")
	}
	_, err = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,'queued',?)`, actor, kind, x.Domain, now)
	if err != nil {
		return "", err
	}
	return jobID, tx.Commit()
}

const jobSelect = `SELECT j.id,j.site_id,s.name,j.kind,j.state,j.error,j.created_at,j.updated_at,j.steps,'' AS target_id,j.payload FROM jobs j JOIN sites s ON j.site_id=s.id UNION ALL SELECT id,'',target_id,kind,state,error,created_at,updated_at,steps,target_id,'{}' FROM runtime_jobs UNION ALL SELECT j.id,'',s.name,j.kind,j.state,j.error,j.created_at,j.updated_at,j.steps,j.target_id,j.payload FROM mysql_jobs j JOIN mysql_servers s ON s.id=j.target_id UNION ALL SELECT o.id,o.site_id,s.name,'acme_certificate',o.state,o.error,o.created_at,o.updated_at,o.steps,o.site_id,'{}' FROM acme_orders o JOIN sites s ON s.id=o.site_id`

func addDatabaseJobSummary(j *Job) {
	if j.Kind != "backup_database" {
		return
	}
	var payload struct {
		Database struct {
			Name string `json:"name"`
		} `json:"database"`
	}
	if json.Unmarshal([]byte(j.Payload), &payload) == nil && ValidDatabaseName(payload.Database.Name) {
		j.DatabaseName = payload.Database.Name
	}
}

func (s *Store) Jobs() ([]Job, error) {
	rows, err := s.DB.Query(jobSelect + ` ORDER BY created_at DESC,id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var j Job
		var steps string
		if err = rows.Scan(&j.ID, &j.SiteID, &j.SiteName, &j.Kind, &j.State, &j.Error, &j.CreatedAt, &j.UpdatedAt, &steps, &j.TargetID, &j.Payload); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(steps), &j.Steps)
		addDatabaseJobSummary(&j)
		out = append(out, j)
	}
	return out, rows.Err()
}
func (s *Store) Job(id string) (Job, error) {
	var j Job
	if !ValidID(id) {
		return j, sql.ErrNoRows
	}
	var steps string
	e := s.DB.QueryRow(`SELECT * FROM (`+jobSelect+`) WHERE id=?`, id).Scan(&j.ID, &j.SiteID, &j.SiteName, &j.Kind, &j.State, &j.Error, &j.CreatedAt, &j.UpdatedAt, &steps, &j.TargetID, &j.Payload)
	if e == nil {
		e = json.Unmarshal([]byte(steps), &j.Steps)
		addDatabaseJobSummary(&j)
	}
	return j, e
}

func (s *Store) Recover() error {
	_, err := s.DB.Exec(`UPDATE sites SET status='needs_attention' WHERE id IN (SELECT site_id FROM jobs WHERE state='running' AND kind!='backup_site'); UPDATE jobs SET state='queued',error='' WHERE state='running' AND kind='backup_site'; UPDATE jobs SET state='needs_attention',error='服务曾中断；请核对并重试，执行器将按资源标识检查已有结果。' WHERE state='running'; UPDATE runtime_jobs SET state='queued' WHERE state='running'; UPDATE mysql_jobs SET state='queued' WHERE state='running'; UPDATE acme_orders SET state='queued' WHERE state='running'`)
	return err
}
func (s *Store) NextJob() (Job, error) {
	var j Job
	err := s.DB.QueryRow(`SELECT id,site_id,kind,payload FROM jobs WHERE state='queued' AND kind!='backup_site' ORDER BY created_at,rowid LIMIT 1`).Scan(&j.ID, &j.SiteID, &j.Kind, &j.Payload)
	if err != nil {
		return j, err
	}
	result, err := s.DB.Exec(`UPDATE jobs SET state='running',updated_at=? WHERE id=? AND state='queued'`, Now(), j.ID)
	if err != nil {
		return j, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return j, errors.New("任务已被领取")
	}
	return j, nil
}
func (s *Store) Finish(j Job, status, detail string, steps []Step) error {
	state := "succeeded"
	if detail != "" {
		state = "failed"
	}
	raw, _ := json.Marshal(steps)
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE jobs SET state=?,error=?,steps=?,updated_at=? WHERE id=?`, state, detail, string(raw), Now(), j.ID); err != nil {
		return err
	}
	if detail == "" && (j.Kind == "switch_php" || j.Kind == "create_site") {
		var p JobPayload
		if err = json.Unmarshal([]byte(j.Payload), &p); err != nil {
			return err
		}
		if err = bindPHP(tx, j.SiteID, p.ReleaseID); err != nil {
			return err
		}
	}
	if detail == "" && j.Kind == "configure_site" {
		if err = finishSiteSettings(tx, j); err != nil {
			return err
		}
	}
	if detail == "" && j.Kind == "archive_site" {
		if err = finishSiteArchive(tx, j.SiteID); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`UPDATE sites SET status=?,updated_at=? WHERE id=?`, status, Now(), j.SiteID); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('executor',?,?,?,?)`, j.Kind, j.SiteID, state, Now()); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Retry(id, actor string) error {
	var count int
	_ = s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE id=?`, id).Scan(&count)
	if count > 0 {
		return s.RetryRuntime(id, actor)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var kind, payload string
	var revision int64
	if err = tx.QueryRow(`SELECT j.kind,j.payload,s.settings_revision FROM jobs j JOIN sites s ON s.id=j.site_id WHERE j.id=?`, id).Scan(&kind, &payload, &revision); err != nil {
		return err
	}
	if kind == "configure_site" {
		var p JobPayload
		_ = json.Unmarshal([]byte(payload), &p)
		if p.ExpectedRevision != revision {
			return errors.New("网站设置已更新，旧任务不能重试")
		}
	}
	r, err := tx.Exec(`UPDATE jobs SET state='queued',error='',updated_at=? WHERE id=? AND state IN ('failed','needs_attention')`, Now(), id)
	if err != nil {
		return errors.New("该站点已有运行中的任务")
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return fmt.Errorf("任务不存在或当前状态不能重试")
	}
	_, err = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'job.retry',?,'queued',?)`, actor, id, Now())
	if err != nil {
		return err
	}
	return tx.Commit()
}

// RecordNginxInventory persists only evidence obtained from the trusted executor.
func (s *Store) RecordNginxInventory(version, architecture string) error {
	if version == "" {
		return errors.New("missing detected Nginx version")
	}
	versionID := Hash("nginx:" + version)[:32]
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO runtime_versions(id,family,version,channel,source_url,verification) VALUES(?,'nginx',?,'distribution',?,'verified_base') ON CONFLICT(family,version) DO UPDATE SET source_url=excluded.source_url,verification='verified_base'`, versionID, version, runtimecatalog.NginxPackageURL(runtimecatalog.HostPlatform()))
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO runtime_installations(id,version_id,binary_path,architecture,detected_at) VALUES('nginx-system',?,'/usr/sbin/nginx',?,?) ON CONFLICT(id) DO UPDATE SET version_id=excluded.version_id,architecture=excluded.architecture,detected_at=excluded.detected_at`, versionID, architecture, Now())
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO runtime_instances(id,installation_id,family,name,service_name,port,config_path) VALUES('nginx-ingress','nginx-system','nginx','development-ingress','nginx',19101,'/etc/nginx/nginx.conf') ON CONFLICT(id) DO NOTHING`)
	if err != nil {
		return err
	}
	return tx.Commit()
}
