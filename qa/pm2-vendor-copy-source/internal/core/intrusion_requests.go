package core

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const intrusionRequestMax = 100000

func (s *Store) migrateIntrusionRequests() error {
	_, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS intrusion_requests(job_id TEXT PRIMARY KEY REFERENCES runtime_jobs(id),actor_id TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('software_configure','software_uninstall','software_recover')),idempotency_key TEXT NOT NULL UNIQUE,payload_sha256 TEXT NOT NULL,created_at TEXT NOT NULL,CHECK(length(job_id)=32 AND length(actor_id)=32 AND length(idempotency_key)=32 AND length(payload_sha256)=64));
CREATE INDEX IF NOT EXISTS intrusion_requests_actor_job ON intrusion_requests(actor_id,job_id);
INSERT OR IGNORE INTO schema_migrations VALUES(102,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return err
}

func intrusionOriginalPayload(kind, payload string) error {
	bad := errors.New("防入侵原请求内容无法核对；未采用或重发")
	if len(payload) > 4096 || !wafInventoryJSONShape([]byte(payload), []string{"settings", "version"}) {
		return bad
	}
	var in struct {
		Settings map[string]any `json:"settings"`
		Version  string         `json:"version"`
	}
	if json.Unmarshal([]byte(payload), &in) != nil || in.Version != "" || in.Settings == nil {
		return bad
	}
	var normalized map[string]any
	var err error
	switch kind {
	case "software_configure":
		if len(in.Settings) != 3 {
			return bad
		}
		normalized, err = normalizeSoftwareSettings("intrusion-prevention", in.Settings)
	case "software_uninstall":
		if len(in.Settings) != 0 {
			return bad
		}
		normalized = map[string]any{}
	case "software_recover":
		normalized, err = NormalizeIntrusionRecovery(in.Settings)
	default:
		return bad
	}
	canonical, marshalErr := json.Marshal(map[string]any{"settings": normalized, "version": ""})
	if err != nil || marshalErr != nil || !bytes.Equal(canonical, []byte(payload)) {
		return bad
	}
	return nil
}

func intrusionRequestAccess(tx *sql.Tx, actor string) error {
	access, err := readUserAccess(tx, actor)
	if !ValidID(actor) || err != nil || access.Role != "admin" || !menuSubset([]string{"runtimes", "security"}, access.MenuIDs) {
		return errors.New("当前账户未获防入侵原请求管理权限")
	}
	return nil
}

func (s *Store) queueIntrusionRequest(action string, settings map[string]any, key string, u identity) (string, error) {
	if action != "configure" && action != "uninstall" && action != "recover" || !ValidID(key) {
		return "", errors.New("防入侵原请求类型或32位幂等标识无效")
	}
	if action == "configure" && len(settings) != 3 || action == "uninstall" && len(settings) != 0 {
		return "", errors.New("防入侵请求缺少完整设置或卸载附带未知参数，未丢弃请求字段")
	}
	bind := func(tx *sql.Tx, job string, existing bool) error {
		bad := errors.New("防入侵原请求账户、任务或完整内容不符；未采用、替换或重新提交")
		if err := intrusionRequestAccess(tx, u.ID); err != nil {
			return err
		}
		var target, kind, payload, jobKey, created string
		if err := tx.QueryRow(`SELECT target_id,kind,payload,idempotency_key,created_at FROM runtime_jobs WHERE id=?`, job).Scan(&target, &kind, &payload, &jobKey, &created); err != nil || !ValidID(job) || target != "intrusion-prevention" || kind != "software_"+action || jobKey != key || intrusionOriginalPayload(kind, payload) != nil {
			return bad
		}
		stamp, err := time.Parse(time.RFC3339, created)
		if err != nil || stamp.UTC().Format(time.RFC3339) != created {
			return bad
		}
		digest := registryInstallDigest([]byte(payload))
		var actor, storedKind, storedKey, storedHash, storedCreated string
		err = tx.QueryRow(`SELECT actor_id,kind,idempotency_key,payload_sha256,created_at FROM intrusion_requests WHERE job_id=?`, job).Scan(&actor, &storedKind, &storedKey, &storedHash, &storedCreated)
		if err == nil {
			if actor != u.ID || storedKind != kind || storedKey != key || storedHash != digest || storedCreated != created {
				return bad
			}
			return nil
		}
		// A guessed key must never adopt an old, unbound queue job.
		if !errors.Is(err, sql.ErrNoRows) || existing {
			return bad
		}
		var count int
		if err = tx.QueryRow(`SELECT count(*) FROM intrusion_requests`).Scan(&count); err != nil || count >= intrusionRequestMax {
			return errors.New("防入侵原请求目录不可读或已达逻辑容量，保留旧证据，未提交")
		}
		_, err = tx.Exec(`INSERT INTO intrusion_requests(job_id,actor_id,kind,idempotency_key,payload_sha256,created_at) VALUES(?,?,?,?,?,?)`, job, u.ID, kind, key, digest, created)
		return err
	}
	return s.queueSoftwareActionBound("intrusion-prevention", action, settings, "", key, u.Username, bind)
}

// Bind the browser's displayed account to the authenticated principal BEFORE
// queueing. A same-name recreated account or a late UI response cannot submit
// an old account's draft under the new account. Inner recovery stays exactly
// transaction_id + plan_sha256; the envelope grants no executor authority.
func decodeIntrusionActorBody(raw []byte, actor, action string) (map[string]any, error) {
	bad := errors.New("防入侵请求账户或完整字段无法核对；未提交")
	if len(raw) > 4096 || !ValidID(actor) || !wafInventoryJSONShape(raw, []string{"actor_id", "settings"}) {
		return nil, bad
	}
	var in struct {
		Actor    string          `json:"actor_id"`
		Settings json.RawMessage `json:"settings"`
	}
	if json.Unmarshal(raw, &in) != nil || in.Actor != actor {
		return nil, bad
	}
	if action == "recover" {
		wrapped, err := json.Marshal(map[string]json.RawMessage{"settings": in.Settings})
		if err != nil {
			return nil, bad
		}
		return decodeIntrusionRecoveryBody(wrapped)
	}
	fields := []string{"max_retry", "find_time_minutes", "ban_time_minutes"}
	if action == "uninstall" {
		fields = []string{}
	} else if action != "configure" {
		return nil, bad
	}
	if !wafInventoryJSONShape(in.Settings, fields) {
		return nil, bad
	}
	var settings map[string]any
	if json.Unmarshal(in.Settings, &settings) != nil || settings == nil {
		return nil, bad
	}
	return settings, nil
}

type intrusionRequestSummary struct {
	ID            string `json:"id"`
	Action        string `json:"action"`
	State         string `json:"state"`
	CreatedAt     string `json:"created_at"`
	RequestSHA256 string `json:"request_sha256"`
}
type intrusionRequestPage struct {
	ActorID    string                    `json:"actor_id"`
	Entries    []intrusionRequestSummary `json:"entries"`
	NextCursor string                    `json:"next_cursor"`
	ReadOnly   bool                      `json:"read_only"`
}

func (s *Store) readIntrusionRequests(actor, cursor string) (intrusionRequestPage, error) {
	out := intrusionRequestPage{ActorID: actor, Entries: []intrusionRequestSummary{}, ReadOnly: true}
	bad := errors.New("当前账户原请求目录无法完整核对；未返回部分目录或推断未提交")
	if cursor != "" && !ValidID(cursor) {
		return out, bad
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err = intrusionRequestAccess(tx, actor); err != nil {
		return out, err
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM intrusion_requests`).Scan(&count); err != nil || count > intrusionRequestMax {
		return out, bad
	}
	rows, err := tx.Query(`SELECT b.job_id,b.kind,b.idempotency_key,b.payload_sha256,b.created_at,j.target_id,j.kind,j.idempotency_key,j.payload,j.created_at,j.state FROM intrusion_requests b LEFT JOIN runtime_jobs j ON j.id=b.job_id WHERE b.actor_id=? AND b.job_id>? ORDER BY b.job_id LIMIT 21`, actor, cursor)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	previous := cursor
	for rows.Next() {
		var id, kind, key, digest, created, target, jobKind, jobKey, payload, jobCreated, state string
		if err = rows.Scan(&id, &kind, &key, &digest, &created, &target, &jobKind, &jobKey, &payload, &jobCreated, &state); err != nil || !ValidID(id) || id <= previous || !ValidID(key) || target != "intrusion-prevention" || jobKind != kind || jobKey != key || jobCreated != created || registryInstallDigest([]byte(payload)) != digest || intrusionOriginalPayload(kind, payload) != nil {
			return out, bad
		}
		stamp, stampErr := time.Parse(time.RFC3339, created)
		if stampErr != nil || stamp.UTC().Format(time.RFC3339) != created {
			return out, bad
		}
		switch state {
		case "queued", "running", "succeeded", "failed", "needs_attention", "cancelled":
		default:
			return out, bad
		}
		previous = id
		if len(out.Entries) == 20 {
			out.NextCursor = out.Entries[19].ID
			continue
		}
		out.Entries = append(out.Entries, intrusionRequestSummary{ID: id, Action: kind[len("software_"):], State: state, CreatedAt: created, RequestSHA256: digest})
	}
	if rows.Err() != nil {
		return out, bad
	}
	if err = rows.Close(); err != nil {
		return out, err
	}
	return out, tx.Commit()
}
