package core

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
)

var sftpUsernamePattern = regexp.MustCompile(`^psftp-[a-f0-9]{12}$`)

type SFTPAccount struct {
	ID        string `json:"id"`
	SiteID    string `json:"site_id"`
	SiteName  string `json:"site_name"`
	Domain    string `json:"domain"`
	Username  string `json:"username"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type SFTPJobRequest struct {
	JobID    string `json:"job_id"`
	Action   string `json:"action"`
	SiteID   string `json:"site_id"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
}

type SFTPJobResult struct {
	State    string `json:"state"`
	Username string `json:"username"`
	Message  string `json:"message"`
}

func (s *Store) migrateSFTP() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS sftp_accounts(
 id TEXT PRIMARY KEY,site_id TEXT NOT NULL REFERENCES sites(id),username TEXT NOT NULL UNIQUE,status TEXT NOT NULL CHECK(status IN ('enabled','disabled')),created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS sftp_accounts_site ON sftp_accounts(site_id,created_at);
 INSERT OR IGNORE INTO schema_migrations VALUES(22,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

func scanSFTP(row interface{ Scan(...any) error }) (SFTPAccount, error) {
	var v SFTPAccount
	e := row.Scan(&v.ID, &v.SiteID, &v.SiteName, &v.Domain, &v.Username, &v.Status, &v.CreatedAt, &v.UpdatedAt)
	return v, e
}

const sftpSelect = `SELECT a.id,a.site_id,s.name,s.domain,a.username,a.status,a.created_at,a.updated_at FROM sftp_accounts a JOIN sites s ON s.id=a.site_id`

func (s *Store) SFTPAccounts() ([]SFTPAccount, error) {
	rows, e := s.DB.Query(sftpSelect + ` ORDER BY a.created_at DESC,a.rowid DESC`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []SFTPAccount{}
	for rows.Next() {
		v, scanErr := scanSFTP(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) SFTPAccount(id string) (SFTPAccount, error) {
	return scanSFTP(s.DB.QueryRow(sftpSelect+` WHERE a.id=?`, id))
}

func validSFTPJob(v SFTPJobRequest) error {
	if !ValidID(v.JobID) || !ValidID(v.SiteID) || !sftpUsernamePattern.MatchString(v.Username) {
		return errors.New("SFTP 作业身份无效")
	}
	switch v.Action {
	case "create", "password":
		if len(v.Password) < 16 || len(v.Password) > 72 || strings.ContainsAny(v.Password, "\r\n:\x00") {
			return errors.New("SFTP 密码格式无效")
		}
	case "enable", "disable", "delete":
		if v.Password != "" {
			return errors.New("SFTP 作业包含多余密码")
		}
	default:
		return errors.New("SFTP 作业动作无效")
	}
	return nil
}

func (a *Server) runSFTPJob(r *http.Request, in SFTPJobRequest) (SFTPJobResult, error) {
	var out SFTPJobResult
	e := a.Executor.Call(r.Context(), http.MethodPost, "/v1/sftp/jobs", in, &out)
	return out, e
}

func (a *Server) sftpRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/sftp", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		items, e := a.Store.SFTPAccounts()
		if e != nil {
			fail(w, 500, "读取 SFTP 账户失败")
			return
		}
		send(w, 200, map[string]any{"accounts": items})
	}))
	m.HandleFunc("POST /api/sftp", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			SiteID string `json:"site_id"`
		}
		if !decode(w, r, &in) {
			return
		}
		site, e := a.Store.Site(in.SiteID)
		if e != nil {
			fail(w, 404, "站点不存在")
			return
		}
		id, username, password := ID(), "psftp-"+ID()[:12], Token()[:24]
		job := SFTPJobRequest{JobID: ID(), Action: "create", SiteID: site.ID, Username: username, Password: password}
		if _, e = a.runSFTPJob(r, job); e != nil {
			_ = a.Store.Audit(u.Username, "sftp.create", username, "failed")
			fail(w, 409, e.Error())
			return
		}
		now := Now()
		if _, e = a.Store.DB.Exec(`INSERT INTO sftp_accounts VALUES(?,?,?,?,?,?)`, id, site.ID, username, "enabled", now, now); e != nil {
			rollback := SFTPJobRequest{JobID: ID(), Action: "delete", SiteID: site.ID, Username: username}
			_, _ = a.runSFTPJob(r, rollback)
			fail(w, 409, "SFTP 系统账户已回滚，保存记录失败")
			return
		}
		_ = a.Store.Audit(u.Username, "sftp.create", username+":"+site.Domain, "success")
		account, _ := a.Store.SFTPAccount(id)
		send(w, 201, map[string]any{"account": account, "password": password})
	}))
	m.HandleFunc("POST /api/sftp/{id}/password", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		account, e := a.Store.SFTPAccount(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "SFTP 账户不存在")
			return
		}
		password := Token()[:24]
		job := SFTPJobRequest{JobID: ID(), Action: "password", SiteID: account.SiteID, Username: account.Username, Password: password}
		if _, e = a.runSFTPJob(r, job); e != nil {
			_ = a.Store.Audit(u.Username, "sftp.password", account.Username, "failed")
			fail(w, 409, e.Error())
			return
		}
		_ = a.Store.Audit(u.Username, "sftp.password", account.Username, "success")
		send(w, 200, map[string]string{"password": password})
	}))
	m.HandleFunc("PUT /api/sftp/{id}/status", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			Enabled bool `json:"enabled"`
		}
		if !decode(w, r, &in) {
			return
		}
		account, e := a.Store.SFTPAccount(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "SFTP 账户不存在")
			return
		}
		action, status := "disable", "disabled"
		if in.Enabled {
			action, status = "enable", "enabled"
		}
		if account.Status == status {
			send(w, 200, account)
			return
		}
		job := SFTPJobRequest{JobID: ID(), Action: action, SiteID: account.SiteID, Username: account.Username}
		if _, e = a.runSFTPJob(r, job); e != nil {
			_ = a.Store.Audit(u.Username, "sftp."+action, account.Username, "failed")
			fail(w, 409, e.Error())
			return
		}
		_, e = a.Store.DB.Exec(`UPDATE sftp_accounts SET status=?,updated_at=? WHERE id=?`, status, Now(), account.ID)
		if e != nil {
			fail(w, 500, "SFTP 状态已修改但记录更新失败，请立即核对")
			return
		}
		_ = a.Store.Audit(u.Username, "sftp."+action, account.Username, "success")
		updated, _ := a.Store.SFTPAccount(account.ID)
		send(w, 200, updated)
	}))
	m.HandleFunc("DELETE /api/sftp/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			ConfirmUsername string `json:"confirm_username"`
		}
		if !decode(w, r, &in) {
			return
		}
		account, e := a.Store.SFTPAccount(r.PathValue("id"))
		if e != nil {
			fail(w, 404, "SFTP 账户不存在")
			return
		}
		if in.ConfirmUsername != account.Username {
			fail(w, 409, "请输入完整 SFTP 用户名确认删除")
			return
		}
		job := SFTPJobRequest{JobID: ID(), Action: "delete", SiteID: account.SiteID, Username: account.Username}
		if _, e = a.runSFTPJob(r, job); e != nil {
			_ = a.Store.Audit(u.Username, "sftp.delete", account.Username, "failed")
			fail(w, 409, e.Error())
			return
		}
		tx, e := a.Store.DB.Begin()
		if e != nil {
			fail(w, 500, "数据库暂不可用")
			return
		}
		defer tx.Rollback()
		if _, e = tx.Exec(`DELETE FROM sftp_accounts WHERE id=?`, account.ID); e == nil {
			_, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'sftp.delete',?,'success',?)`, u.Username, account.Username, Now())
		}
		if e == nil {
			e = tx.Commit()
		}
		if e != nil {
			fail(w, 500, "系统账户已删除但记录提交失败，请立即核对")
			return
		}
		send(w, 200, map[string]bool{"ok": true})
	}))
}
