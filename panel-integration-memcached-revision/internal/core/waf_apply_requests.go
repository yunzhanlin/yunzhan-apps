package core

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const wafApplyRequestMax = 100000            // Immutable metadata bound, not physical disk quota.
const wafApplyPayloadMax = (128 << 10) + 128 // Existing normalized configuration plus the fixed job envelope.

func wafApplyApp(app string) bool { return app == "nginx-waf" || app == "apache-waf" }

// Validate only retained JSON. Do not preview/reload a website, consult an
// executor, renormalize against current sites, or turn this into an install
// receipt. The original payload hash remains part of the request identity.
func wafApplyOriginalSettings(app, payload string) (map[string]any, error) {
	bad := errors.New("原防火墙任务配置不可核对；不修复、替换或重发原请求")
	if !wafApplyApp(app) || len(payload) > wafApplyPayloadMax || !wafInventoryJSONShape([]byte(payload), []string{"settings", "version"}) {
		return nil, bad
	}
	var in struct {
		Settings map[string]any `json:"settings"`
		Version  string         `json:"version"`
	}
	d := json.NewDecoder(bytes.NewReader([]byte(payload)))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || in.Settings == nil || in.Version != "" {
		return nil, bad
	}
	canonical, marshalErr := json.Marshal(map[string]any{"settings": in.Settings, "version": in.Version})
	if marshalErr != nil || !bytes.Equal(canonical, []byte(payload)) {
		return nil, bad
	}
	var err error
	if app == "nginx-waf" {
		_, err = DecodeWAFConfig(in.Settings)
	} else {
		_, err = DecodeApacheWAFConfig(in.Settings)
	}
	if err != nil {
		return nil, bad
	}
	return in.Settings, nil
}

// This binding is in the SAME queue transaction as the immutable original job
// and its requested audit. It is neither a succeeded outcome nor an automatic
// retry, and a new/recreated same-name account cannot inherit it.
func (s *Store) bindWAFApplyRequest(app, key string, u identity) func(*sql.Tx, string, bool) error {
	return func(tx *sql.Tx, job string, existing bool) error {
		bad := errors.New("原防火墙请求账户、任务或内容不可核对；未采用或重新提交")
		if !wafApplyApp(app) || !ValidID(u.ID) || !ValidID(job) || key == "" || len(key) > 128 {
			return bad
		}
		access, err := readUserAccess(tx, u.ID)
		if err != nil || access.Role != "admin" || !menuSubset([]string{"runtimes", "security"}, access.MenuIDs) {
			return bad
		}
		var target, kind, payload, jobKey, created string
		if err = tx.QueryRow(`SELECT target_id,kind,payload,idempotency_key,created_at FROM runtime_jobs WHERE id=?`, job).Scan(&target, &kind, &payload, &jobKey, &created); err != nil || target != app || (kind != "software_install" && kind != "software_configure") || jobKey != key {
			return bad
		}
		stamp, err := time.Parse(time.RFC3339, created)
		if err != nil || stamp.UTC().Format(time.RFC3339) != created {
			return bad
		}
		if _, err = wafApplyOriginalSettings(app, payload); err != nil {
			return bad
		}
		digest := registryInstallDigest([]byte(payload))
		var actor, storedApp, storedKind, storedKey, storedHash, storedCreated string
		err = tx.QueryRow(`SELECT actor_id,app_id,kind,idempotency_key,payload_sha256,created_at FROM waf_apply_requests WHERE job_id=?`, job).Scan(&actor, &storedApp, &storedKind, &storedKey, &storedHash, &storedCreated)
		if err == nil {
			if actor != u.ID || storedApp != app || storedKind != kind || storedKey != key || storedHash != digest || storedCreated != created {
				return bad
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) || existing {
			return bad
		} // Never adopt an unbound legacy job by guessing a key.
		var count int
		if err = tx.QueryRow(`SELECT count(*) FROM waf_apply_requests`).Scan(&count); err != nil || count >= wafApplyRequestMax {
			return errors.New("原防火墙请求记录不可读取或已达逻辑上限；保留旧记录，未提交")
		}
		_, err = tx.Exec(`INSERT INTO waf_apply_requests(job_id,actor_id,app_id,kind,idempotency_key,payload_sha256,created_at) VALUES(?,?,?,?,?,?,?)`, job, u.ID, app, kind, key, digest, created)
		return err
	}
}

func (s *Store) queueWAFApplyRequest(app, action string, settings map[string]any, key string, u identity) (string, error) {
	if !wafApplyApp(app) || (action != "configure" && action != "install") {
		return "", errors.New("原防火墙请求类型无效")
	}
	return s.queueSoftwareActionBound(app, action, settings, "", key, u.Username, s.bindWAFApplyRequest(app, key, u))
}
