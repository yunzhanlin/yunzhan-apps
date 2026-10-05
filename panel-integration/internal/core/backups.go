package core

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func (s *Store) QueueSiteBackup(siteID, confirmName, key, actor string) (string, error) {
	if !ValidID(siteID) {
		return "", errors.New("网站标识无效")
	}
	site, err := s.Site(siteID)
	if err != nil || site.Name != confirmName || site.Status == "provisioning" || site.Status == "needs_attention" || site.Status == "archived" {
		return "", errors.New("网站不存在、名称不匹配或当前状态不能备份")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if key != "" {
		var jobID, kind, priorSite string
		err = tx.QueryRow(`SELECT id,kind,site_id FROM jobs WHERE idempotency_key=?`, key).Scan(&jobID, &kind, &priorSite)
		if err == nil {
			if kind != "backup_site" || priorSite != siteID {
				return "", errors.New("幂等键已被不同请求使用")
			}
			return jobID, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
	}
	jobID, now := ID(), Now()
	payload, _ := json.Marshal(JobPayload{SiteBackup: &SiteBackup{ID: ID(), SiteID: siteID}})
	var idem any
	if key != "" {
		idem = key
	}
	if _, err = tx.Exec(`INSERT INTO jobs(id,site_id,kind,state,idempotency_key,created_at,updated_at,payload) VALUES(?,?,'backup_site','queued',?,?,?,?)`, jobID, siteID, idem, now, now, string(payload)); err != nil {
		return "", errors.New("网站已有任务在执行")
	}
	if _, err = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'site.backup',?,'queued',?)`, actor, site.Name, now); err != nil {
		return "", err
	}
	return jobID, tx.Commit()
}

func (s *Store) NextSiteBackupJob() (Job, error) {
	var job Job
	err := s.DB.QueryRow(`SELECT id,site_id,kind,payload FROM jobs WHERE kind='backup_site' AND state='queued' ORDER BY created_at,rowid LIMIT 1`).Scan(&job.ID, &job.SiteID, &job.Kind, &job.Payload)
	if err != nil {
		return job, err
	}
	result, err := s.DB.Exec(`UPDATE jobs SET state='running',updated_at=? WHERE id=? AND state='queued'`, Now(), job.ID)
	if err != nil {
		return job, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return job, errors.New("备份任务已被领取")
	}
	return job, nil
}

func (s *Store) FinishSiteBackupJob(job Job, backup SiteBackup, backupErr error) error {
	var payload JobPayload
	if err := json.Unmarshal([]byte(job.Payload), &payload); err != nil || payload.SiteBackup == nil || payload.SiteBackup.SiteID != job.SiteID {
		return errors.New("网站备份任务身份无效")
	}
	if backup.ID != payload.SiteBackup.ID || backup.SiteID != job.SiteID {
		backupErr = errors.New("网站备份产物身份不匹配")
	}
	if backupErr == nil {
		if backup.Format != "zip" || backup.Bytes < 0 || backup.SourceBytes < 0 || backup.Files < 0 || len(backup.SHA256) != 64 || backup.CreatedAt == "" {
			backupErr = errors.New("网站备份产物无效")
		} else if _, err := hex.DecodeString(backup.SHA256); err != nil {
			backupErr = errors.New("网站备份摘要无效")
		}
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, detail := "succeeded", ""
	if backupErr != nil {
		state, detail = "failed", backupErr.Error()
		if len(detail) > 500 {
			detail = detail[:500]
		}
	} else {
		_, err = tx.Exec(`INSERT OR IGNORE INTO site_backups(id,site_id,format,files,source_bytes,bytes,sha256,created_at) VALUES(?,?,?,?,?,?,?,?)`, backup.ID, backup.SiteID, backup.Format, backup.Files, backup.SourceBytes, backup.Bytes, backup.SHA256, backup.CreatedAt)
		if err != nil {
			return err
		}
		var storedSite, storedHash string
		var storedBytes int64
		if err = tx.QueryRow(`SELECT site_id,bytes,sha256 FROM site_backups WHERE id=?`, backup.ID).Scan(&storedSite, &storedBytes, &storedHash); err != nil || storedSite != backup.SiteID || storedBytes != backup.Bytes || storedHash != backup.SHA256 {
			return errors.New("网站备份记录与产物不一致")
		}
	}
	updated, err := tx.Exec(`UPDATE jobs SET state=?,error=?,updated_at=? WHERE id=? AND state='running'`, state, detail, Now(), job.ID)
	if err != nil {
		return err
	}
	if affected, _ := updated.RowsAffected(); affected != 1 {
		return errors.New("网站备份任务状态已变化")
	}
	if _, err = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('executor','site.backup',?,?,?)`, job.SiteID, state, Now()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) QueueSiteRestore(backupID, confirm, key, actor string) (string, error) {
	backup, e := s.SiteBackup(backupID)
	if e != nil {
		return "", errors.New("网站备份不存在")
	}
	site, e := s.Site(backup.SiteID)
	if e != nil || site.Name != confirm {
		return "", errors.New("请输入完全一致的网站名称")
	}
	if site.Status == "provisioning" || site.Status == "needs_attention" {
		return "", errors.New("网站当前状态不能恢复")
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	if key != "" {
		var id, payload string
		e = tx.QueryRow(`SELECT id,payload FROM jobs WHERE idempotency_key=?`, key).Scan(&id, &payload)
		if e == nil {
			var old JobPayload
			if json.Unmarshal([]byte(payload), &old) != nil || old.SiteBackup == nil || old.SiteBackup.ID != backupID {
				return "", errors.New("幂等键已被不同请求使用")
			}
			return id, nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return "", e
		}
	}
	payload, _ := json.Marshal(JobPayload{SiteBackup: &backup, PreviousStatus: site.Status})
	jobID, now := ID(), Now()
	var idem any
	if key != "" {
		idem = key
	}
	_, e = tx.Exec(`INSERT INTO jobs(id,site_id,kind,state,idempotency_key,created_at,updated_at,payload) VALUES(?,?,'restore_site','queued',?,?,?,?)`, jobID, site.ID, idem, now, now, string(payload))
	if e != nil {
		return "", errors.New("网站已有任务在执行")
	}
	_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'site.restore',?,'queued',?)`, actor, site.Name+":"+backup.ID, now)
	if e != nil {
		return "", e
	}
	return jobID, tx.Commit()
}

type BackupItem struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	TargetID    string `json:"target_id"`
	TargetName  string `json:"target_name"`
	ParentName  string `json:"parent_name,omitempty"`
	Version     string `json:"version,omitempty"`
	Format      string `json:"format"`
	Files       int    `json:"files,omitempty"`
	SourceBytes int64  `json:"source_bytes,omitempty"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	Schedule    string `json:"schedule,omitempty"`
	CreatedAt   string `json:"created_at"`
}

func (s *Store) BackupItems() ([]BackupItem, error) {
	items := []BackupItem{}
	rows, e := s.DB.Query(`SELECT b.id,'database',b.database_id,d.name,ms.name,b.version,'sql',0,0,b.bytes,b.sha256,COALESCE(sc.name,''),b.created_at
FROM mysql_backups b JOIN mysql_databases d ON d.id=b.database_id JOIN mysql_servers ms ON ms.id=b.server_id
LEFT JOIN schedule_artifacts sa ON sa.artifact_id=b.id AND sa.kind='database_backup' LEFT JOIN schedules sc ON sc.id=sa.schedule_id`)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var v BackupItem
		if e = rows.Scan(&v.ID, &v.Kind, &v.TargetID, &v.TargetName, &v.ParentName, &v.Version, &v.Format, &v.Files, &v.SourceBytes, &v.Bytes, &v.SHA256, &v.Schedule, &v.CreatedAt); e != nil {
			rows.Close()
			return nil, e
		}
		items = append(items, v)
	}
	rows.Close()
	rows, e = s.DB.Query(`SELECT b.id,'mariadb',b.database_id,b.database_name,b.instance_name,substr(b.release_id,9),'sql',0,0,b.bytes,b.sha256,COALESCE(sc.name,''),b.created_at
FROM mariadb_schedule_backups b LEFT JOIN schedule_artifacts sa ON sa.artifact_id=b.id AND sa.kind='mariadb_backup' LEFT JOIN schedules sc ON sc.id=sa.schedule_id`)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var v BackupItem
		if e = rows.Scan(&v.ID, &v.Kind, &v.TargetID, &v.TargetName, &v.ParentName, &v.Version, &v.Format, &v.Files, &v.SourceBytes, &v.Bytes, &v.SHA256, &v.Schedule, &v.CreatedAt); e != nil {
			rows.Close()
			return nil, e
		}
		items = append(items, v)
	}
	rows.Close()
	rows, e = s.DB.Query(`SELECT b.id,'site',b.site_id,w.name,w.domain,'',b.format,b.files,b.source_bytes,b.bytes,b.sha256,COALESCE(sc.name,''),b.created_at
FROM site_backups b JOIN sites w ON w.id=b.site_id LEFT JOIN schedule_artifacts sa ON sa.artifact_id=b.id AND sa.kind='site_backup' LEFT JOIN schedules sc ON sc.id=sa.schedule_id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var v BackupItem
		if e = rows.Scan(&v.ID, &v.Kind, &v.TargetID, &v.TargetName, &v.ParentName, &v.Version, &v.Format, &v.Files, &v.SourceBytes, &v.Bytes, &v.SHA256, &v.Schedule, &v.CreatedAt); e != nil {
			return nil, e
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

func (s *Store) SiteBackup(id string) (SiteBackup, error) {
	var v SiteBackup
	e := s.DB.QueryRow(`SELECT id,site_id,format,files,source_bytes,bytes,sha256,created_at FROM site_backups WHERE id=?`, id).Scan(&v.ID, &v.SiteID, &v.Format, &v.Files, &v.SourceBytes, &v.Bytes, &v.SHA256, &v.CreatedAt)
	return v, e
}

func (a *Server) backupRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /api/backups/sites", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			SiteID      string `json:"site_id"`
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		jobID, err := a.Store.QueueSiteBackup(in.SiteID, in.ConfirmName, r.Header.Get("Idempotency-Key"), u.Username)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": jobID})
	}))
	m.HandleFunc("GET /api/backups", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		items, e := a.Store.BackupItems()
		if e != nil {
			fail(w, 500, "读取备份中心失败")
			return
		}
		send(w, 200, map[string]any{"backups": items})
	}))
	m.HandleFunc("GET /api/backups/sites/{id}/download", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		backup, e := a.Store.SiteBackup(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "网站备份不存在")
			return
		}
		q := url.Values{"bytes": {strconv.FormatInt(backup.Bytes, 10)}, "sha256": {backup.SHA256}}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
		sent, e := a.proxyStream(w, r, "/v1/sites/"+backup.SiteID+"/backups/"+backup.ID+"/download?"+q.Encode(), 30*time.Minute)
		result := "success"
		if e != nil {
			result = "failed"
			if !sent {
				fail(w, 502, e.Error())
			}
		}
		_ = a.Store.Audit(u.Username, "site.backup.download", backup.ID, result)
	}))
	m.HandleFunc("POST /api/backups/sites/{id}/restore", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmName string `json:"confirm_name"`
		}
		if !decode(w, r, &in) {
			return
		}
		jobID, e := a.Store.QueueSiteRestore(r.PathValue("id"), in.ConfirmName, r.Header.Get("Idempotency-Key"), u.Username)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": jobID})
	}))
}
