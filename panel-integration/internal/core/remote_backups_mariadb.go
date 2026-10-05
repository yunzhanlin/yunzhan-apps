package core

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"
)

func (s *Store) executeMariaDBRemoteBackupCopy(ctx context.Context, ex *ExecutorClient, now time.Time) error {
	if ex == nil {
		return nil
	}
	var id, remoteID, artifactID string
	var attempts int
	e := s.DB.QueryRow(`SELECT id,remote_id,artifact_id,attempts FROM mariadb_remote_copies WHERE state='pending' AND next_attempt_at<=? ORDER BY created_at,rowid LIMIT 1`, now.Unix()).Scan(&id, &remoteID, &artifactID, &attempts)
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
	backup, e := s.MariaDBScheduleBackup(artifactID)
	if e != nil {
		return e
	}
	req := RemoteBackupRequest{CopyID: id, Remote: remote, Password: password, Kind: "mariadb", MariaDB: &backup}
	res, e := s.DB.Exec(`UPDATE mariadb_remote_copies SET state='running',attempts=attempts+1 WHERE id=? AND state='pending'`, id)
	if e != nil {
		return e
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil
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
		_, updateErr := s.DB.Exec(`UPDATE mariadb_remote_copies SET state=?,next_attempt_at=?,error=? WHERE id=? AND state='running'`, state, next, message, id)
		return updateErr
	}
	if result.Bytes != backup.Bytes || result.SHA256 != backup.SHA256 {
		e = errors.New("MariaDB 远端核验结果与本地备份不一致")
		_, _ = s.DB.Exec(`UPDATE mariadb_remote_copies SET state='failed',error=? WHERE id=?`, e.Error(), id)
		return e
	}
	_, e = s.DB.Exec(`UPDATE mariadb_remote_copies SET state='succeeded',remote_path=?,error='',completed_at=? WHERE id=? AND state='running'`, result.RemotePath, Now(), id)
	return e
}
