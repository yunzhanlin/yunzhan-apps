package core

import (
	"database/sql"
	"time"
)

type Notification struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	Severity  string `json:"severity"`
	Source    string `json:"source"`
	SourceID  string `json:"source_id"`
	CreatedAt int64  `json:"created_at"`
	ReadAt    int64  `json:"read_at,omitempty"`
}

type NotificationSettings struct {
	ScheduleFailures bool   `json:"schedule_failures"`
	RemoteFailures   bool   `json:"remote_failures"`
	MonitorAlerts    bool   `json:"monitor_alerts"`
	RetentionDays    int    `json:"retention_days"`
	Revision         int64  `json:"revision"`
	UpdatedAt        string `json:"updated_at"`
}

func (s *Store) migrateNotifications() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS notifications(
id TEXT PRIMARY KEY,kind TEXT NOT NULL,title TEXT NOT NULL,message TEXT NOT NULL,severity TEXT NOT NULL CHECK(severity IN ('info','warning','critical')),
source TEXT NOT NULL,source_id TEXT NOT NULL,created_at INTEGER NOT NULL,read_at INTEGER NOT NULL DEFAULT 0,UNIQUE(source,source_id));
CREATE INDEX IF NOT EXISTS notifications_recent ON notifications(created_at DESC);
CREATE INDEX IF NOT EXISTS notifications_unread ON notifications(read_at,created_at DESC);
CREATE TABLE IF NOT EXISTS notification_settings(
id INTEGER PRIMARY KEY CHECK(id=1),schedule_failures INTEGER NOT NULL CHECK(schedule_failures IN (0,1)),remote_failures INTEGER NOT NULL CHECK(remote_failures IN (0,1)),monitor_alerts INTEGER NOT NULL CHECK(monitor_alerts IN (0,1)),retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 7 AND 365),revision INTEGER NOT NULL CHECK(revision>0),updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notification_exclusions(source TEXT NOT NULL,source_id TEXT NOT NULL,PRIMARY KEY(source,source_id));
INSERT OR IGNORE INTO notification_settings VALUES(1,1,1,1,90,1,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
INSERT OR IGNORE INTO schema_migrations VALUES(24,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
INSERT OR IGNORE INTO schema_migrations VALUES(25,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
INSERT OR IGNORE INTO schema_migrations VALUES(26,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

func (s *Store) syncNotifications() error {
	settings, e := s.NotificationSettings()
	if e != nil {
		return e
	}
	if settings.ScheduleFailures {
		_, e = s.DB.Exec(`INSERT OR IGNORE INTO notifications(id,kind,title,message,severity,source,source_id,created_at)
SELECT lower(hex(randomblob(16))),'schedule','计划任务失败',schedule_name||'：'||COALESCE(NULLIF(error,''),NULLIF(log,''),'执行失败'),'critical','schedule_run',id,scheduled_for
FROM schedule_runs WHERE state='failed' AND NOT EXISTS (SELECT 1 FROM notification_exclusions x WHERE x.source='schedule_run' AND x.source_id=schedule_runs.id)`)
	}
	if e == nil && settings.RemoteFailures {
		_, e = s.DB.Exec(`INSERT OR IGNORE INTO notifications(id,kind,title,message,severity,source,source_id,created_at)
SELECT lower(hex(randomblob(16))),'remote','远端备份失败',r.name||'：'||COALESCE(NULLIF(c.error,''),'传输失败'),'warning','remote_copy',c.id,CAST(strftime('%s',c.created_at) AS INTEGER)
FROM backup_remote_copies c JOIN backup_remotes r ON r.id=c.remote_id WHERE c.state='failed' AND NOT EXISTS (SELECT 1 FROM notification_exclusions x WHERE x.source='remote_copy' AND x.source_id=c.id);
INSERT OR IGNORE INTO notifications(id,kind,title,message,severity,source,source_id,created_at)
SELECT lower(hex(randomblob(16))),'remote','MariaDB 远端备份失败',r.name||'：'||COALESCE(NULLIF(c.error,''),'传输失败'),'warning','mariadb_remote_copy',c.id,CAST(strftime('%s',c.created_at) AS INTEGER)
FROM mariadb_remote_copies c JOIN backup_remotes r ON r.id=c.remote_id WHERE c.state='failed' AND NOT EXISTS (SELECT 1 FROM notification_exclusions x WHERE x.source='mariadb_remote_copy' AND x.source_id=c.id)`)
	}
	if e == nil && settings.MonitorAlerts {
		_, e = s.DB.Exec(`INSERT OR IGNORE INTO notifications(id,kind,title,message,severity,source,source_id,created_at)
SELECT lower(hex(randomblob(16))),'monitor','资源告警',metric||' 当前峰值 '||printf('%.1f',peak)||'，阈值 '||printf('%.1f',threshold),'critical','monitor_alert',id,started_at
		FROM monitor_alerts WHERE NOT EXISTS (SELECT 1 FROM notification_exclusions x WHERE x.source='monitor_alert' AND x.source_id=monitor_alerts.id)`)
	}
	if e == nil {
		_, e = s.DB.Exec(`DELETE FROM notifications WHERE read_at>0 AND created_at<?`, time.Now().AddDate(0, 0, -settings.RetentionDays).Unix())
	}
	return e
}

func (s *Store) NotificationSettings() (NotificationSettings, error) {
	var v NotificationSettings
	e := s.DB.QueryRow(`SELECT schedule_failures,remote_failures,monitor_alerts,retention_days,revision,updated_at FROM notification_settings WHERE id=1`).Scan(&v.ScheduleFailures, &v.RemoteFailures, &v.MonitorAlerts, &v.RetentionDays, &v.Revision, &v.UpdatedAt)
	return v, e
}

func (s *Store) SaveNotificationSettings(v NotificationSettings, expectedRevision int64) (NotificationSettings, error) {
	if v.RetentionDays < 7 || v.RetentionDays > 365 || expectedRevision < 1 {
		return NotificationSettings{}, sql.ErrNoRows
	}
	// Flush events allowed by the old policy before switching it. Events that
	// happened while a source was disabled must not replay on re-enablement.
	if e := s.syncNotifications(); e != nil {
		return NotificationSettings{}, e
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return NotificationSettings{}, e
	}
	defer tx.Rollback()
	var old NotificationSettings
	if e = tx.QueryRow(`SELECT schedule_failures,remote_failures,monitor_alerts,retention_days,revision,updated_at FROM notification_settings WHERE id=1`).Scan(&old.ScheduleFailures, &old.RemoteFailures, &old.MonitorAlerts, &old.RetentionDays, &old.Revision, &old.UpdatedAt); e != nil {
		return NotificationSettings{}, e
	}
	if old.Revision != expectedRevision {
		return NotificationSettings{}, sql.ErrNoRows
	}
	if !old.ScheduleFailures && v.ScheduleFailures {
		if _, e = tx.Exec(`INSERT OR IGNORE INTO notification_exclusions SELECT 'schedule_run',id FROM schedule_runs WHERE state='failed'`); e != nil {
			return NotificationSettings{}, e
		}
	}
	if !old.RemoteFailures && v.RemoteFailures {
		if _, e = tx.Exec(`INSERT OR IGNORE INTO notification_exclusions SELECT 'remote_copy',id FROM backup_remote_copies WHERE state='failed'; INSERT OR IGNORE INTO notification_exclusions SELECT 'mariadb_remote_copy',id FROM mariadb_remote_copies WHERE state='failed'`); e != nil {
			return NotificationSettings{}, e
		}
	}
	if !old.MonitorAlerts && v.MonitorAlerts {
		if _, e = tx.Exec(`INSERT OR IGNORE INTO notification_exclusions SELECT 'monitor_alert',id FROM monitor_alerts`); e != nil {
			return NotificationSettings{}, e
		}
	}
	result, e := tx.Exec(`UPDATE notification_settings SET schedule_failures=?,remote_failures=?,monitor_alerts=?,retention_days=?,revision=revision+1,updated_at=? WHERE id=1 AND revision=?`, v.ScheduleFailures, v.RemoteFailures, v.MonitorAlerts, v.RetentionDays, Now(), expectedRevision)
	if e != nil {
		return NotificationSettings{}, e
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return NotificationSettings{}, sql.ErrNoRows
	}
	if e = tx.Commit(); e != nil {
		return NotificationSettings{}, e
	}
	return s.NotificationSettings()
}

func (s *Store) Notifications(limit int) ([]Notification, int, error) {
	if limit < 1 || limit > 100 {
		limit = 30
	}
	if e := s.syncNotifications(); e != nil {
		return nil, 0, e
	}
	rows, e := s.DB.Query(`SELECT id,kind,title,message,severity,source,source_id,created_at,read_at FROM notifications ORDER BY created_at DESC,rowid DESC LIMIT ?`, limit)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	out := []Notification{}
	for rows.Next() {
		var v Notification
		if e = rows.Scan(&v.ID, &v.Kind, &v.Title, &v.Message, &v.Severity, &v.Source, &v.SourceID, &v.CreatedAt, &v.ReadAt); e != nil {
			return nil, 0, e
		}
		out = append(out, v)
	}
	var unread int
	if e = rows.Err(); e == nil {
		e = s.DB.QueryRow(`SELECT count(*) FROM notifications WHERE read_at=0`).Scan(&unread)
	}
	return out, unread, e
}

func (s *Store) ReadNotification(id string) error {
	if !ValidID(id) {
		return sql.ErrNoRows
	}
	result, e := s.DB.Exec(`UPDATE notifications SET read_at=? WHERE id=? AND read_at=0`, time.Now().Unix(), id)
	if e != nil {
		return e
	}
	if n, _ := result.RowsAffected(); n == 0 {
		var exists int
		if e = s.DB.QueryRow(`SELECT count(*) FROM notifications WHERE id=?`, id).Scan(&exists); e != nil || exists == 0 {
			return sql.ErrNoRows
		}
	}
	return nil
}

func (s *Store) ReadAllNotifications() error {
	if e := s.syncNotifications(); e != nil {
		return e
	}
	_, e := s.DB.Exec(`UPDATE notifications SET read_at=? WHERE read_at=0`, time.Now().Unix())
	return e
}
