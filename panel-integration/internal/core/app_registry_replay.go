package core

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"local/panel/internal/appcatalog"
	"strings"
)

type registryUpdateInput struct {
	ExpectedVersion string `json:"expected_version"`
	ExpectedSHA256  string `json:"expected_sha256"`
}
type registryUpdateReplay struct{ JobID, Provider string }

func validateRegistryUpdateRequest(appID, actorID, key string, in registryUpdateInput) error {
	digest, err := hex.DecodeString(in.ExpectedSHA256)
	if !ValidID(actorID) || len(appID) < 2 || len(appID) > 64 || strings.TrimSpace(appID) != appID ||
		key == "" || len(key) > 128 || strings.TrimSpace(key) != key ||
		!appcatalog.ValidVersion(in.ExpectedVersion) || err != nil || len(digest) != 32 || hex.EncodeToString(digest) != in.ExpectedSHA256 {
		return errors.New("应用更新请求标识、版本或摘要无效")
	}
	for _, r := range appID {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return errors.New("应用更新标识无效")
		}
	}
	return nil
}

// Durable bindings survive job completion, receipt reconciliation, a later
// catalog version and process restart. Replaying never requeues or retries.
func (s *Store) registryUpdateReplay(appID, actorID, key string, in registryUpdateInput) (registryUpdateReplay, bool, error) {
	var out registryUpdateReplay
	if err := validateRegistryUpdateRequest(appID, actorID, key, in); err != nil {
		return out, false, err
	}
	var oldActor, oldApp, version, digest, scope, target, kind, payload, jobKey string
	err := s.DB.QueryRow(`SELECT q.actor_id,q.app_id,q.version,q.sha256,q.provider,q.scope,q.job_id,j.target_id,j.kind,j.payload,j.idempotency_key
 FROM app_registry_update_requests q JOIN runtime_jobs j ON j.id=q.job_id WHERE q.idempotency_key=?`, key).
		Scan(&oldActor, &oldApp, &version, &digest, &out.Provider, &scope, &out.JobID, &target, &kind, &payload, &jobKey)
	if errors.Is(err, sql.ErrNoRows) {
		// A missing referenced job must not turn a retained key into a fresh request.
		var n int
		if e := s.DB.QueryRow(`SELECT count(*) FROM app_registry_update_requests WHERE idempotency_key=?`, key).Scan(&n); e != nil {
			return out, false, e
		}
		if n != 0 {
			return out, false, errors.New("原应用更新任务缺失，保留请求记录，未重发")
		}
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if oldActor != actorID || oldApp != appID || version != in.ExpectedVersion || digest != in.ExpectedSHA256 || scope != target || jobKey != key || !ValidID(out.JobID) {
		return out, false, errors.New("幂等键已绑定不同用户、应用或更新版本")
	}
	if out.Provider == "panel-module" {
		expected := `{"settings":null,"version":"` + version + `"}`
		if kind != "software_update" || payload != expected {
			return out, false, errors.New("原应用更新任务内容不一致，未重发")
		}
	} else if out.Provider != "runtime" || kind != "install_runtime" {
		return out, false, errors.New("原应用更新任务类型不一致，未重发")
	}
	return out, true, nil
}

func (s *Store) bindRegistryUpdate(item appcatalog.CatalogItem, scope, key, actorID string) func(*sql.Tx, string, bool) error {
	return func(tx *sql.Tx, job string, existing bool) error {
		var oldActor, oldApp, version, digest, provider, oldScope, oldJob string
		err := tx.QueryRow(`SELECT actor_id,app_id,version,sha256,provider,scope,job_id FROM app_registry_update_requests WHERE idempotency_key=?`, key).
			Scan(&oldActor, &oldApp, &version, &digest, &provider, &oldScope, &oldJob)
		if err == nil {
			if oldActor != actorID || oldApp != item.ID || version != item.Version || digest != item.SHA256 || provider != item.Provider || oldScope != scope || oldJob != job {
				return errors.New("幂等键已绑定不同应用更新请求")
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if existing {
			return errors.New("幂等键已被其他未绑定仓库请求使用，未重新提交")
		}
		var count int
		if err = tx.QueryRow(`SELECT count(*) FROM app_registry_update_requests`).Scan(&count); err != nil {
			return err
		}
		if count >= 100000 {
			return errors.New("应用更新请求记录达到容量上限，保留原幂等身份，未提交")
		}
		_, err = tx.Exec(`INSERT INTO app_registry_update_requests(idempotency_key,actor_id,app_id,version,sha256,provider,scope,job_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			key, actorID, item.ID, item.Version, item.SHA256, item.Provider, scope, job, Now())
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO app_registry_pending(job_id,app_id,scope,version,sha256,target,provider,created_at) VALUES(?,?,?,?,?,?,?,?)`,
			job, item.ID, scope, item.Version, item.SHA256, item.Target, item.Provider, Now())
		return err
	}
}
