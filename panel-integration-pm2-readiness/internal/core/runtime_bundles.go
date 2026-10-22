package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"local/panel/internal/runtimecatalog"
	"strings"
)

type RuntimeBundleResult struct {
	JobIDs    []string `json:"job_ids"`
	Installed []string `json:"installed"`
}

func (s *Store) migrateRuntimeBundles() error {
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS runtime_install_bundles(
idempotency_key TEXT PRIMARY KEY,request_hash TEXT NOT NULL,result_json TEXT NOT NULL,created_at TEXT NOT NULL);
INSERT OR IGNORE INTO schema_migrations VALUES(27,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	return e
}

// QueueInstallBundle commits every install job or none. The caller may safely
// retry an uncertain HTTP response using the same idempotency key.
func (s *Store) QueueInstallBundle(releases []string, key, actor string) (RuntimeBundleResult, error) {
	out := RuntimeBundleResult{JobIDs: []string{}, Installed: []string{}}
	if key == "" || len(key) > 128 || len(releases) < 1 || len(releases) > 5 {
		return out, errors.New("组合安装需要 1–5 个版本和有效幂等键")
	}
	seenID, seenFamily := map[string]bool{}, map[string]bool{}
	for _, id := range releases {
		release, ok := runtimecatalog.Find(id)
		if !ok || seenID[id] || seenFamily[release.Family] {
			return out, errors.New("组合安装包含无效版本或同一家族的重复版本")
		}
		if release.Family == "docker" {
			spec, available := runtimecatalog.DockerSpecOn(runtimecatalog.HostPlatform())
			if !available || !runtimecatalog.DockerAvailableOn(runtimecatalog.HostPlatform()) || spec.ReleaseID != release.ID {
				return out, errors.New("当前 Debian 版本尚未适配此 Docker 固定包")
			}
		}
		seenID[id], seenFamily[release.Family] = true, true
	}
	digest := Hash(strings.Join(releases, "\x00"))
	tx, e := s.DB.Begin()
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	var priorHash, priorJSON string
	e = tx.QueryRow(`SELECT request_hash,result_json FROM runtime_install_bundles WHERE idempotency_key=?`, key).Scan(&priorHash, &priorJSON)
	if e == nil {
		if priorHash != digest {
			return out, errors.New("幂等键已被不同组合使用")
		}
		if e = json.Unmarshal([]byte(priorJSON), &out); e != nil {
			return RuntimeBundleResult{}, e
		}
		return out, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return out, e
	}
	for _, id := range releases {
		var installed, active int
		if e = tx.QueryRow(`SELECT count(*) FROM runtime_installations WHERE id=? AND status='installed'`, id).Scan(&installed); e != nil {
			return RuntimeBundleResult{}, e
		}
		if installed > 0 {
			out.Installed = append(out.Installed, id)
			continue
		}
		if e = tx.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE target_id=? AND state IN ('queued','running')`, id).Scan(&active); e != nil {
			return RuntimeBundleResult{}, e
		}
		if active > 0 {
			return RuntimeBundleResult{}, errors.New("组合中的版本已有活动任务，请先核对任务中心")
		}
		jobID := ID()
		jobKey := "bundle:" + Hash(key+":"+id)
		if _, e = tx.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,created_at,updated_at) VALUES(?,?,'install_runtime','queued',?,?,?)`, jobID, id, jobKey, Now(), Now()); e != nil {
			return RuntimeBundleResult{}, e
		}
		if _, e = tx.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'runtime.install',?,'queued',?)`, actor, id, Now()); e != nil {
			return RuntimeBundleResult{}, e
		}
		out.JobIDs = append(out.JobIDs, jobID)
	}
	encoded, e := json.Marshal(out)
	if e != nil {
		return RuntimeBundleResult{}, e
	}
	if _, e = tx.Exec(`INSERT INTO runtime_install_bundles(idempotency_key,request_hash,result_json,created_at) VALUES(?,?,?,?)`, key, digest, string(encoded), Now()); e != nil {
		return RuntimeBundleResult{}, e
	}
	if e = tx.Commit(); e != nil {
		return RuntimeBundleResult{}, e
	}
	return out, nil
}
