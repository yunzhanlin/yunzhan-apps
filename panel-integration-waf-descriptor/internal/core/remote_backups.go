package core

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

type BackupRemote struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	BaseURL     string `json:"base_url"`
	Username    string `json:"username"`
	PathPrefix  string `json:"path_prefix"`
	Enabled     bool   `json:"enabled"`
	PasswordSet bool   `json:"password_set"`
	LastTestAt  string `json:"last_test_at,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type BackupRemoteInput struct {
	Name       string `json:"name"`
	BaseURL    string `json:"base_url"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PathPrefix string `json:"path_prefix"`
	Enabled    bool   `json:"enabled"`
}

type RemoteBackupCopy struct {
	ID           string `json:"id"`
	RemoteID     string `json:"remote_id"`
	RemoteName   string `json:"remote_name"`
	ArtifactKind string `json:"artifact_kind"`
	ArtifactID   string `json:"artifact_id"`
	RemotePath   string `json:"remote_path,omitempty"`
	Bytes        int64  `json:"bytes"`
	SHA256       string `json:"sha256"`
	State        string `json:"state"`
	Attempts     int    `json:"attempts"`
	Error        string `json:"error,omitempty"`
	CreatedAt    string `json:"created_at"`
	CompletedAt  string `json:"completed_at,omitempty"`
}

type RemoteBackupRequest struct {
	CopyID   string          `json:"copy_id"`
	Remote   BackupRemote    `json:"remote"`
	Password string          `json:"password"`
	Kind     string          `json:"kind"`
	Database *DatabaseBackup `json:"database,omitempty"`
	MariaDB  *MariaDBBackup  `json:"mariadb,omitempty"`
	Site     *SiteBackup     `json:"site,omitempty"`
}

type RemoteBackupResult struct {
	RemotePath string `json:"remote_path"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
}

type RemoteConnectionRequest struct {
	Remote   BackupRemote `json:"remote"`
	Password string       `json:"password"`
}

type RemoteConnectionResult struct {
	Status string `json:"status"`
}

func (s *Store) migrateRemoteBackups() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS backup_remotes(
id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,base_url TEXT NOT NULL,username TEXT NOT NULL,password_cipher BLOB NOT NULL,path_prefix TEXT NOT NULL,enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),last_test_at TEXT NOT NULL DEFAULT '',last_error TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS backup_remote_copies(
id TEXT PRIMARY KEY,remote_id TEXT NOT NULL REFERENCES backup_remotes(id),artifact_kind TEXT NOT NULL CHECK(artifact_kind IN ('database','site')),artifact_id TEXT NOT NULL,remote_path TEXT NOT NULL DEFAULT '',bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','running','succeeded','failed')),attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,completed_at TEXT NOT NULL DEFAULT '',UNIQUE(remote_id,artifact_kind,artifact_id));
CREATE INDEX IF NOT EXISTS remote_copies_pending ON backup_remote_copies(state,next_attempt_at);
CREATE TABLE IF NOT EXISTS mariadb_remote_copies(
id TEXT PRIMARY KEY,remote_id TEXT NOT NULL REFERENCES backup_remotes(id),artifact_id TEXT NOT NULL,remote_path TEXT NOT NULL DEFAULT '',bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','running','succeeded','failed')),attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,completed_at TEXT NOT NULL DEFAULT '',UNIQUE(remote_id,artifact_id));
CREATE INDEX IF NOT EXISTS mariadb_remote_copies_pending ON mariadb_remote_copies(state,next_attempt_at);
CREATE TABLE IF NOT EXISTS schedule_remotes(schedule_id TEXT PRIMARY KEY REFERENCES schedules(id),remote_id TEXT NOT NULL REFERENCES backup_remotes(id));
INSERT OR IGNORE INTO schema_migrations VALUES(17,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
INSERT OR IGNORE INTO schema_migrations VALUES(18,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

var remotePathPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{0,128}$`)

func validateBackupRemote(in BackupRemoteInput) (BackupRemoteInput, error) {
	in.Name, in.BaseURL, in.Username = strings.TrimSpace(in.Name), strings.TrimSpace(in.BaseURL), strings.TrimSpace(in.Username)
	in.PathPrefix = strings.Trim(strings.TrimSpace(in.PathPrefix), "/")
	if len([]rune(in.Name)) < 1 || len([]rune(in.Name)) > 60 || len(in.Username) > 200 || len(in.Password) > 512 || !remotePathPattern.MatchString(in.PathPrefix) {
		return in, errors.New("远端备份名称、账号或目录无效")
	}
	for _, segment := range strings.Split(in.PathPrefix, "/") {
		if segment == ".." {
			return in, errors.New("远端目录不能包含上级路径")
		}
	}
	u, e := url.Parse(in.BaseURL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return in, errors.New("WebDAV 地址必须是无账号、查询或片段的 HTTP(S) URL")
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return in, errors.New("公网 WebDAV 必须使用 HTTPS；HTTP 只允许本机验收")
		}
	}
	u.Path = path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
	in.BaseURL = strings.TrimRight(u.String(), "/")
	return in, nil
}

func scanBackupRemote(row interface{ Scan(...any) error }) (BackupRemote, error) {
	var v BackupRemote
	var enabled int
	e := row.Scan(&v.ID, &v.Name, &v.BaseURL, &v.Username, &v.PathPrefix, &enabled, &v.LastTestAt, &v.LastError, &v.CreatedAt, &v.UpdatedAt)
	v.Enabled, v.PasswordSet = enabled == 1, true
	return v, e
}

const backupRemoteSelect = `SELECT id,name,base_url,username,path_prefix,enabled,last_test_at,last_error,created_at,updated_at FROM backup_remotes`

func (s *Store) BackupRemotes() ([]BackupRemote, error) {
	rows, e := s.DB.Query(backupRemoteSelect + ` ORDER BY created_at,rowid`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []BackupRemote{}
	for rows.Next() {
		v, er := scanBackupRemote(rows)
		if er != nil {
			return nil, er
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) BackupRemote(id string) (BackupRemote, error) {
	return scanBackupRemote(s.DB.QueryRow(backupRemoteSelect+` WHERE id=?`, id))
}

func (s *Store) SaveBackupRemote(id string, in BackupRemoteInput, actor string) (BackupRemote, error) {
	var empty BackupRemote
	var e error
	if in, e = validateBackupRemote(in); e != nil {
		return empty, e
	}
	create := id == ""
	if create {
		id = ID()
		if in.Password == "" {
			return empty, errors.New("请填写 WebDAV 密码")
		}
	} else if !ValidID(id) {
		return empty, errors.New("远端备份标识无效")
	}
	var encrypted []byte
	if in.Password != "" {
		encrypted, e = encryptCredential(s.encryptionKey, "panel-webdav:"+id, []byte(in.Password))
		if e != nil {
			return empty, errors.New("远端密码加密失败")
		}
	} else if e = s.DB.QueryRow(`SELECT password_cipher FROM backup_remotes WHERE id=?`, id).Scan(&encrypted); e != nil {
		return empty, errors.New("远端备份不存在")
	}
	now := Now()
	tx, e := s.DB.Begin()
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	if create {
		_, e = tx.Exec(`INSERT INTO backup_remotes(id,name,base_url,username,password_cipher,path_prefix,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, id, in.Name, in.BaseURL, in.Username, encrypted, in.PathPrefix, in.Enabled, now, now)
	} else {
		_, e = tx.Exec(`UPDATE backup_remotes SET name=?,base_url=?,username=?,password_cipher=?,path_prefix=?,enabled=?,last_test_at='',last_error='',updated_at=? WHERE id=?`, in.Name, in.BaseURL, in.Username, encrypted, in.PathPrefix, in.Enabled, now, id)
	}
	if e != nil {
		return empty, errors.New("远端备份名称已存在")
	}
	action := "backup.remote.update"
	if create {
		action = "backup.remote.create"
	}
	if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,'success',?)`, actor, action, id, now); e != nil {
		return empty, e
	}
	if e = tx.Commit(); e != nil {
		return empty, e
	}
	return s.BackupRemote(id)
}

func (s *Store) backupRemotePassword(id string) (string, error) {
	var cipher []byte
	if e := s.DB.QueryRow(`SELECT password_cipher FROM backup_remotes WHERE id=?`, id).Scan(&cipher); e != nil {
		return "", e
	}
	plain, e := decryptCredential(s.encryptionKey, "panel-webdav:"+id, cipher)
	if e != nil {
		return "", errors.New("WebDAV 密码无法解密")
	}
	return string(plain), nil
}

func (s *Store) RecordRemoteTest(id, message string, success bool) error {
	if len(message) > 500 {
		message = message[:500]
	}
	if success {
		message = ""
	}
	_, e := s.DB.Exec(`UPDATE backup_remotes SET last_test_at=?,last_error=?,updated_at=? WHERE id=?`, Now(), message, Now(), id)
	return e
}

func (s *Store) QueueRemoteCopy(remoteID, kind, artifactID, actor string) (RemoteBackupCopy, error) {
	var out RemoteBackupCopy
	remote, e := s.BackupRemote(remoteID)
	if e != nil || !remote.Enabled {
		return out, errors.New("远端存储不存在或已停用")
	}
	if kind != "database" && kind != "site" && kind != "mariadb" {
		return out, errors.New("备份类型无效")
	}
	// A retry reuses the copy ID and clears its failed state. Preserve the
	// failure notification before that transition, even if nobody opened UI.
	if e = s.syncNotifications(); e != nil {
		return out, e
	}
	var bytes int64
	var sha string
	if kind == "database" {
		v, er := s.DatabaseBackup(artifactID)
		e = er
		bytes, sha = v.Bytes, v.SHA256
	} else if kind == "site" {
		v, er := s.SiteBackup(artifactID)
		e = er
		bytes, sha = v.Bytes, v.SHA256
	} else {
		v, er := s.MariaDBScheduleBackup(artifactID)
		e = er
		bytes, sha = v.Bytes, v.SHA256
	}
	if e != nil {
		return out, errors.New("本地备份不存在")
	}
	now := Now()
	id := ID()
	if kind == "mariadb" {
		_, e = s.DB.Exec(`INSERT INTO mariadb_remote_copies(id,remote_id,artifact_id,bytes,sha256,state,created_at) VALUES(?,?,?,?,?,'pending',?) ON CONFLICT(remote_id,artifact_id) DO UPDATE SET state=CASE WHEN mariadb_remote_copies.state='failed' THEN 'pending' ELSE mariadb_remote_copies.state END,attempts=CASE WHEN mariadb_remote_copies.state='failed' THEN 0 ELSE mariadb_remote_copies.attempts END,next_attempt_at=0,error=CASE WHEN mariadb_remote_copies.state='failed' THEN '' ELSE mariadb_remote_copies.error END`, id, remoteID, artifactID, bytes, sha, now)
	} else {
		_, e = s.DB.Exec(`INSERT INTO backup_remote_copies(id,remote_id,artifact_kind,artifact_id,bytes,sha256,state,created_at) VALUES(?,?,?,?,?,?,'pending',?) ON CONFLICT(remote_id,artifact_kind,artifact_id) DO UPDATE SET state=CASE WHEN backup_remote_copies.state='failed' THEN 'pending' ELSE backup_remote_copies.state END,attempts=CASE WHEN backup_remote_copies.state='failed' THEN 0 ELSE backup_remote_copies.attempts END,next_attempt_at=0,error=CASE WHEN backup_remote_copies.state='failed' THEN '' ELSE backup_remote_copies.error END`, id, remoteID, kind, artifactID, bytes, sha, now)
	}
	if e != nil {
		return out, e
	}
	_ = s.Audit(actor, "backup.remote.queue", remoteID+":"+artifactID, "queued")
	return s.RemoteCopy(remoteID, kind, artifactID)
}

func scanRemoteCopy(row interface{ Scan(...any) error }) (RemoteBackupCopy, error) {
	var v RemoteBackupCopy
	e := row.Scan(&v.ID, &v.RemoteID, &v.RemoteName, &v.ArtifactKind, &v.ArtifactID, &v.RemotePath, &v.Bytes, &v.SHA256, &v.State, &v.Attempts, &v.Error, &v.CreatedAt, &v.CompletedAt)
	return v, e
}

const remoteCopySelect = `SELECT c.id,c.remote_id,r.name,c.artifact_kind,c.artifact_id,c.remote_path,c.bytes,c.sha256,c.state,c.attempts,c.error,c.created_at,c.completed_at FROM backup_remote_copies c JOIN backup_remotes r ON r.id=c.remote_id`

func (s *Store) RemoteCopy(remoteID, kind, artifactID string) (RemoteBackupCopy, error) {
	if kind == "mariadb" {
		return scanRemoteCopy(s.DB.QueryRow(`SELECT c.id,c.remote_id,r.name,'mariadb',c.artifact_id,c.remote_path,c.bytes,c.sha256,c.state,c.attempts,c.error,c.created_at,c.completed_at FROM mariadb_remote_copies c JOIN backup_remotes r ON r.id=c.remote_id WHERE c.remote_id=? AND c.artifact_id=?`, remoteID, artifactID))
	}
	return scanRemoteCopy(s.DB.QueryRow(remoteCopySelect+` WHERE c.remote_id=? AND c.artifact_kind=? AND c.artifact_id=?`, remoteID, kind, artifactID))
}
func (s *Store) RemoteCopies() ([]RemoteBackupCopy, error) {
	rows, e := s.DB.Query(remoteCopySelect + ` ORDER BY c.created_at DESC,c.rowid DESC LIMIT 500`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []RemoteBackupCopy{}
	for rows.Next() {
		v, er := scanRemoteCopy(rows)
		if er != nil {
			return nil, er
		}
		out = append(out, v)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	rows, e = s.DB.Query(`SELECT c.id,c.remote_id,r.name,'mariadb',c.artifact_id,c.remote_path,c.bytes,c.sha256,c.state,c.attempts,c.error,c.created_at,c.completed_at FROM mariadb_remote_copies c JOIN backup_remotes r ON r.id=c.remote_id ORDER BY c.created_at DESC,c.rowid DESC LIMIT 500`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		v, er := scanRemoteCopy(rows)
		if er != nil {
			return nil, er
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) executeRemoteBackupCopy(ctx context.Context, ex *ExecutorClient, now time.Time) error {
	if ex == nil {
		return nil
	}
	var id, remoteID, kind, artifactID string
	var attempts int
	e := s.DB.QueryRow(`SELECT id,remote_id,artifact_kind,artifact_id,attempts FROM backup_remote_copies WHERE state='pending' AND next_attempt_at<=? ORDER BY created_at,rowid LIMIT 1`, now.Unix()).Scan(&id, &remoteID, &kind, &artifactID, &attempts)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	remote, e := s.BackupRemote(remoteID)
	if e != nil {
		return e
	}
	password, e := s.backupRemotePassword(remoteID)
	if e != nil {
		return e
	}
	req := RemoteBackupRequest{CopyID: id, Remote: remote, Password: password, Kind: kind}
	if kind == "database" {
		v, er := s.DatabaseBackup(artifactID)
		e = er
		req.Database = &v
	} else {
		v, er := s.SiteBackup(artifactID)
		e = er
		req.Site = &v
	}
	if e != nil {
		return e
	}
	_, e = s.DB.Exec(`UPDATE backup_remote_copies SET state='running',attempts=attempts+1 WHERE id=? AND state='pending'`, id)
	if e != nil {
		return e
	}
	var result RemoteBackupResult
	e = ex.Call(ctx, http.MethodPost, "/v1/remote-backups/sync", req, &result)
	if e != nil {
		message := e.Error()
		if len(message) > 500 {
			message = message[:500]
		}
		attempts++
		state := "pending"
		next := now.Add(time.Duration(attempts) * 3 * time.Second).Unix()
		if attempts >= 3 {
			state = "failed"
			next = 0
		}
		_, updateErr := s.DB.Exec(`UPDATE backup_remote_copies SET state=?,next_attempt_at=?,error=? WHERE id=? AND state='running'`, state, next, message, id)
		return updateErr
	}
	if result.Bytes != reqCopyBytes(req) || result.SHA256 != reqCopySHA(req) {
		e = errors.New("远端核验结果与本地备份不一致")
		_, _ = s.DB.Exec(`UPDATE backup_remote_copies SET state='failed',error=? WHERE id=?`, e.Error(), id)
		return e
	}
	_, e = s.DB.Exec(`UPDATE backup_remote_copies SET state='succeeded',remote_path=?,error='',completed_at=? WHERE id=? AND state='running'`, result.RemotePath, Now(), id)
	return e
}

func reqCopyBytes(v RemoteBackupRequest) int64 {
	if v.Database != nil {
		return v.Database.Bytes
	}
	if v.Site != nil {
		return v.Site.Bytes
	}
	if v.MariaDB != nil {
		return v.MariaDB.Bytes
	}
	return 0
}
func reqCopySHA(v RemoteBackupRequest) string {
	if v.Database != nil {
		return v.Database.SHA256
	}
	if v.Site != nil {
		return v.Site.SHA256
	}
	if v.MariaDB != nil {
		return v.MariaDB.SHA256
	}
	return ""
}

func (s *Store) queueScheduleRemote(scheduleID, kind, artifactID string) error {
	var remoteID string
	e := s.DB.QueryRow(`SELECT remote_id FROM schedule_remotes WHERE schedule_id=?`, scheduleID).Scan(&remoteID)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	_, e = s.QueueRemoteCopy(remoteID, kind, artifactID, "scheduler")
	return e
}
