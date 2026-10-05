package core

import (
	"database/sql"
	"errors"
	"net/http"
	"time"
)

const defaultSessionIdleMinutes = 30

type SessionPolicy struct {
	IdleMinutes int    `json:"idle_minutes"`
	Revision    int64  `json:"revision"`
	UpdatedAt   string `json:"updated_at"`
}

func (s *Store) migrateSessionPolicy() error {
	var applied int
	if err := s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=37`).Scan(&applied); err != nil {
		return err
	}
	if applied != 0 {
		return nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`ALTER TABLE sessions ADD COLUMN last_activity_at INTEGER NOT NULL DEFAULT 0;
UPDATE sessions SET last_activity_at=CAST(strftime('%s','now') AS INTEGER) WHERE expires_at>CAST(strftime('%s','now') AS INTEGER);
CREATE TABLE session_policy(id INTEGER PRIMARY KEY CHECK(id=1),idle_minutes INTEGER NOT NULL,revision INTEGER NOT NULL,updated_at TEXT NOT NULL);
INSERT INTO session_policy VALUES(1,30,1,strftime('%Y-%m-%dT%H:%M:%SZ','now'));
INSERT INTO schema_migrations VALUES(37,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetSessionPolicy() (SessionPolicy, error) {
	var policy SessionPolicy
	err := s.DB.QueryRow(`SELECT idle_minutes,revision,updated_at FROM session_policy WHERE id=1`).Scan(&policy.IdleMinutes, &policy.Revision, &policy.UpdatedAt)
	return policy, err
}

func (s *Store) UpdateSessionPolicy(minutes int, revision int64, actor string) (SessionPolicy, error) {
	if minutes < 5 || minutes > 240 {
		return SessionPolicy{}, errors.New("会话空闲超时需为 5–240 分钟")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return SessionPolicy{}, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE session_policy SET idle_minutes=?,revision=revision+1,updated_at=? WHERE id=1 AND revision=?`, minutes, Now(), revision)
	if err != nil {
		return SessionPolicy{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return SessionPolicy{}, err
	}
	if changed != 1 {
		return SessionPolicy{}, errors.New("会话策略已被其他操作修改，请刷新后重试")
	}
	var policy SessionPolicy
	if err = tx.QueryRow(`SELECT idle_minutes,revision,updated_at FROM session_policy WHERE id=1`).Scan(&policy.IdleMinutes, &policy.Revision, &policy.UpdatedAt); err != nil {
		return SessionPolicy{}, err
	}
	if _, err = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'session.policy.update','session','success',?)`, actor, Now()); err != nil {
		return SessionPolicy{}, err
	}
	return policy, tx.Commit()
}

func (a *Server) sessionPolicyRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/session-policy", a.authorize(func(w http.ResponseWriter, r *http.Request, _ identity) {
		policy, err := a.Store.GetSessionPolicy()
		if err != nil {
			fail(w, 500, "会话策略暂不可用")
			return
		}
		send(w, 200, policy)
	}))
	m.HandleFunc("PUT /api/session-policy", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var input struct {
			IdleMinutes int   `json:"idle_minutes"`
			Revision    int64 `json:"revision"`
		}
		if !decode(w, r, &input) {
			return
		}
		policy, err := a.Store.UpdateSessionPolicy(input.IdleMinutes, input.Revision, u.Username)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, policy)
	}))
	m.HandleFunc("POST /api/session/activity", a.authorize(func(w http.ResponseWriter, r *http.Request, _ identity) {
		send(w, 200, map[string]bool{"ok": true})
	}))
}

func (s *Store) sessionIdentity(tokenHash string, now time.Time) (identity, error) {
	var user identity
	err := s.DB.QueryRow(`SELECT u.id,u.username,s.csrf FROM sessions s JOIN users u ON s.user_id=u.id CROSS JOIN session_policy p WHERE s.token_hash=? AND s.expires_at>? AND s.last_activity_at+p.idle_minutes*60>?`, tokenHash, now.Unix(), now.Unix()).Scan(&user.ID, &user.Username, &user.CSRF)
	return user, err
}

func (s *Store) touchSession(tokenHash string, now time.Time) error {
	result, err := s.DB.Exec(`UPDATE sessions SET last_activity_at=? WHERE token_hash=? AND expires_at>?`, now.Unix(), tokenHash, now.Unix())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	return nil
}
