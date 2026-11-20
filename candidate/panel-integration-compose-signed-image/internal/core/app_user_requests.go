package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
)

const appUserRequestLimit = 100000

var appUserRequestKey = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)

func (s *Store) migrateAppUserRequests() error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS app_user_request_receipts (
		request_key TEXT PRIMARY KEY NOT NULL CHECK(length(request_key) BETWEEN 1 AND 128),
		actor_id TEXT NOT NULL CHECK(length(actor_id)=32),
		payload_mac TEXT NOT NULL CHECK(length(payload_mac)=64),
		created_at TEXT NOT NULL
	);
	INSERT OR IGNORE INTO schema_migrations VALUES(104,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

type appUserRequest struct {
	key, actor, mac string
}

func (a *Server) appUserMutationRequest(actor, key, action string, in AppModuleInput) (*appUserRequest, error) {
	if key == "" {
		// Older API clients can omit the header and retain their former behavior.
		return nil, nil
	}
	if !appUserRequestKey.MatchString(key) || !ValidID(actor) || len(a.accountSecretKey) != 32 {
		return nil, errors.New("账户变更请求标识无法核对")
	}
	// Bind fields consumed by this operation so unrelated module inputs added
	// in later releases cannot invalidate existing account receipts.
	raw, err := json.Marshal(struct {
		Username, Role, Password string
		SiteIDs, MenuIDs         []string
		ExpectedRevision         int64
	}{in.Username, in.Role, in.Password, in.SiteIDs, in.MenuIDs, in.ExpectedRevision})
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, a.accountSecretKey)
	// The private MAC binds the account, key and exact decoded input. The
	// database does not contain the input or an unkeyed password fingerprint.
	mac.Write([]byte("panel:app-user-request:v1\x00" + actor + "\x00" + key + "\x00" + action + "\x00"))
	mac.Write(raw)
	return &appUserRequest{key: key, actor: actor, mac: hex.EncodeToString(mac.Sum(nil))}, nil
}

func (r *appUserRequest) preflight(ctx context.Context, tx *sql.Tx) (bool, error) {
	var actor, mac string
	err := tx.QueryRowContext(ctx, `SELECT actor_id,payload_mac FROM app_user_request_receipts WHERE request_key=?`, r.key).Scan(&actor, &mac)
	if err == nil {
		if actor != r.actor || !hmac.Equal([]byte(mac), []byte(r.mac)) {
			return false, errors.New("原账户请求标识已绑定其他账户、动作或内容")
		}
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM app_user_request_receipts`).Scan(&count); err != nil {
		return false, err
	}
	if count >= appUserRequestLimit {
		return false, errors.New("账户请求回执已达容量，原回执仍可核对")
	}
	return false, nil
}

func (r *appUserRequest) commit(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO app_user_request_receipts(request_key,actor_id,payload_mac,created_at) VALUES(?,?,?,?)`, r.key, r.actor, r.mac, Now())
	return err
}

func appUserMutationResult(action, username string) map[string]any {
	return map[string]any{"username": username, "action": action, "ok": true}
}
