package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const wafCountryRequestMax = 100000

func (s *Store) migrateWAFCountryRequests() error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS waf_country_requests(job_id TEXT PRIMARY KEY REFERENCES runtime_jobs(id),actor_id TEXT NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,payload_sha256 TEXT NOT NULL,created_at TEXT NOT NULL,CHECK(length(job_id)=32 AND length(actor_id)=32 AND length(idempotency_key)=32 AND length(payload_sha256)=64));
CREATE INDEX IF NOT EXISTS waf_country_requests_actor_job ON waf_country_requests(actor_id,job_id);
CREATE TABLE IF NOT EXISTS waf_country_results(job_id TEXT PRIMARY KEY REFERENCES waf_country_requests(job_id),request_sha256 TEXT NOT NULL,result_sha256 TEXT NOT NULL,body BLOB NOT NULL,state TEXT NOT NULL,created_at TEXT NOT NULL,CHECK(length(request_sha256)=64 AND length(result_sha256)=64 AND length(body)>0 AND length(body)<=32768 AND state IN ('succeeded','failed','needs_attention')));
INSERT OR IGNORE INTO schema_migrations VALUES(103,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func wafCountryCurrentAccess(ctx context.Context, tx accessReader, actor string) error {
	access, err := readUserAccessContext(ctx, tx, actor)
	if !ValidID(actor) || err != nil || access.Role != "admin" || !menuSubset([]string{"runtimes", "security"}, access.MenuIDs) {
		return errors.New("国家数据任务需要当前管理员的软件商店和安全管理权限")
	}
	return nil
}

type wafCountryOriginal struct {
	Job                             Job
	Actor, Key, PayloadSHA, Created string
	Selection                       WAFCountryDataSelection
}

func readWAFCountryOriginal(ctx context.Context, db accessReader, id string) (wafCountryOriginal, error) {
	var out wafCountryOriginal
	bad := errors.New("国家数据原始任务、账户、完整内容或唯一审计无法核对；未采用或重发")
	if !ValidID(id) {
		return out, bad
	}
	var key, created string
	// Bound materialization INSIDE SQL, before a Root read can allocate a
	// corrupt oversized Core string. A malformed row becomes refusal, never
	// a partial/default request or authority to repair the original record.
	err := db.QueryRowContext(ctx, `SELECT r.actor_id,r.idempotency_key,r.payload_sha256,r.created_at,j.id,j.target_id,j.kind,j.payload,j.idempotency_key,j.created_at,j.state FROM waf_country_requests r JOIN runtime_jobs j ON j.id=r.job_id WHERE r.job_id=? AND j.kind='waf_country_data' AND j.target_id='nginx-waf' AND typeof(j.payload)='text' AND length(CAST(j.payload AS BLOB)) BETWEEN 1 AND 2048 AND length(CAST(r.actor_id AS BLOB))=32 AND length(CAST(r.idempotency_key AS BLOB))=32 AND length(CAST(r.payload_sha256 AS BLOB))=64 AND length(CAST(r.created_at AS BLOB))=20 AND length(CAST(j.id AS BLOB))=32 AND length(CAST(j.idempotency_key AS BLOB))=32 AND length(CAST(j.created_at AS BLOB))=20 AND length(CAST(j.state AS BLOB)) BETWEEN 1 AND 32`, id).Scan(&out.Actor, &out.Key, &out.PayloadSHA, &out.Created, &out.Job.ID, &out.Job.TargetID, &out.Job.Kind, &out.Job.Payload, &key, &created, &out.Job.State)
	if err != nil || !ValidID(out.Actor) || !ValidID(out.Key) || !validLowerSHA256(out.PayloadSHA) || out.Job.ID != id || out.Job.TargetID != "nginx-waf" || out.Job.Kind != "waf_country_data" || out.Key != key || out.Created != created || out.PayloadSHA != Hash(out.Job.Payload) {
		return wafCountryOriginal{}, bad
	}
	if out.Job.State != "queued" && out.Job.State != "running" && out.Job.State != "succeeded" && out.Job.State != "failed" && out.Job.State != "needs_attention" && out.Job.State != "cancelled" {
		return wafCountryOriginal{}, bad
	}
	stamp, err := time.Parse(time.RFC3339, created)
	if err != nil || stamp.UTC().Format(time.RFC3339) != created {
		return wafCountryOriginal{}, bad
	}
	out.Selection, err = DecodeWAFCountryDataSelection([]byte(out.Job.Payload))
	if err != nil {
		return wafCountryOriginal{}, bad
	}
	canonical, err := json.Marshal(out.Selection)
	if err != nil || string(canonical) != out.Job.Payload {
		return wafCountryOriginal{}, bad
	}
	var count int
	var actor, result string
	if db.QueryRowContext(ctx, `SELECT count(*),coalesce(min(CASE WHEN length(CAST(actor AS BLOB))=32 THEN actor ELSE '' END),''),coalesce(min(CASE WHEN length(CAST(result AS BLOB))<=16 THEN result ELSE '' END),'') FROM audit_logs WHERE action='waf.country.queue' AND target=?`, id).Scan(&count, &actor, &result) != nil || count != 1 || actor != out.Actor || result != "queued" {
		return wafCountryOriginal{}, bad
	}
	if out.Job.State == "cancelled" {
		if _, err := countryCancellationProof(ctx, db, out); err != nil {
			return wafCountryOriginal{}, err
		}
	}
	return out, nil
}

func (s *Store) queueWAFCountryData(ctx context.Context, in WAFCountryDataSelection, key, actor string) (string, bool, error) {
	if ctx == nil || ctx.Err() != nil || ValidateWAFCountryDataSelection(in) != nil || !ValidID(key) || !ValidID(actor) {
		return "", false, errors.New("国家数据请求或32位原始幂等标识无效")
	}
	in.Countries = append([]string(nil), in.Countries...)
	raw, err := json.Marshal(in)
	if err != nil {
		return "", false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	if err := wafCountryCurrentAccess(ctx, tx, actor); err != nil {
		return "", false, err
	}
	var id string
	err = tx.QueryRowContext(ctx, `SELECT id FROM runtime_jobs WHERE idempotency_key=?`, key).Scan(&id)
	if err == nil {
		original, err := readWAFCountryOriginal(ctx, tx, id)
		if err != nil || original.Actor != actor || original.Key != key || original.Job.Payload != string(raw) || !SameWAFCountryDataSelection(original.Selection, in) {
			return "", false, errors.New("国家数据幂等标识已经绑定其他账户、任务或内容，未补建或替换")
		}
		return id, true, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM runtime_jobs WHERE target_id='nginx-waf' AND kind='waf_country_data' AND state IN ('queued','running','needs_attention')`).Scan(&count) != nil || count != 0 {
		return "", false, errors.New("原国家数据任务仍未结束或待核对，未创建替代下载")
	}
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM waf_country_requests`).Scan(&count) != nil || count >= wafCountryRequestMax {
		return "", false, errors.New("国家数据原始任务目录不可读或已达逻辑容量，旧证据保留")
	}
	id, created := ID(), Now()
	if _, err = tx.ExecContext(ctx, `INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at) VALUES(?,'nginx-waf','waf_country_data','queued',?,?,?,?)`, id, string(raw), key, created, created); err != nil {
		return "", false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO waf_country_requests(job_id,actor_id,idempotency_key,payload_sha256,created_at) VALUES(?,?,?,?,?)`, id, actor, key, Hash(string(raw)), created); err != nil {
		return "", false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'waf.country.queue',?,'queued',?)`, actor, id, created); err != nil {
		return "", false, err
	}
	return id, false, tx.Commit()
}

// The unique dispatch intent is durable BEFORE the one Root POST. Once that
// boundary exists, restarts and lost acknowledgements may only read that same
// original Root task. Late revocation still permits read-only reconciliation.
func (s *Store) wafCountryDispatchBoundary(ctx context.Context, j Job, commitIntent bool) (bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return false, errors.New("国家数据提交上下文失效")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	bad := errors.New("国家数据原任务或完整提交意图不同，未提交或重发")
	original, err := readWAFCountryOriginal(ctx, tx, j.ID)
	if err != nil || j.TargetID != "nginx-waf" || j.Kind != "waf_country_data" || original.Job.State != "running" || original.Job.Payload != j.Payload {
		return false, bad
	}
	var count int
	var actor, digest string
	if tx.QueryRowContext(ctx, `SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action='waf.country.dispatch' AND target=?`, j.ID).Scan(&count, &actor, &digest) != nil || count > 1 {
		return false, bad
	}
	if count == 1 {
		if actor != original.Actor || digest != original.PayloadSHA {
			return false, bad
		}
		return true, tx.Commit()
	}
	if err := wafCountryCurrentAccess(ctx, tx, original.Actor); err != nil {
		return false, err
	}
	if commitIntent {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'waf.country.dispatch',?,?,?)`, original.Actor, j.ID, original.PayloadSHA, Now()); err != nil {
			return false, err
		}
	}
	return false, tx.Commit()
}
