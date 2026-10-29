package core

import (
	"context"
	"database/sql"
	"errors"
)

// Read-only Core evidence, NOT a data signature or installed capability.
// Root must additionally verify the original app/data envelope, its own WAF
// instance, programme guard and fixed worker identity. A receipt alone grants
// no filesystem, network-source, configuration or activation authority.
func (s *Store) ValidateWAFCountryDataNative(ctx context.Context, id, actor, payloadSHA string) error {
	bad := errors.New("国家数据原任务、当前账户、应用回执或唯一提交意图不能核对")
	if ctx == nil || ctx.Err() != nil || !ValidID(id) || !ValidID(actor) || !validLowerSHA256(payloadSHA) {
		return bad
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	original, err := readWAFCountryOriginal(ctx, tx, id)
	if err != nil || original.Actor != actor || original.PayloadSHA != payloadSHA || original.Job.State != "running" {
		return bad
	}
	if err := wafCountryCurrentAccess(ctx, tx, actor); err != nil {
		return err
	}
	var count int
	var dispatcher, digest string
	if tx.QueryRowContext(ctx, `SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action='waf.country.dispatch' AND target=?`, id).Scan(&count, &dispatcher, &digest) != nil || count != 1 || dispatcher != actor || digest != payloadSHA {
		return bad
	}
	var version, sha, target string
	if tx.QueryRowContext(ctx, `SELECT version,sha256,target FROM app_registry_receipts WHERE app_id='nginx-waf' AND scope='nginx-waf'`).Scan(&version, &sha, &target) != nil || version != original.Selection.AppVersion || sha != original.Selection.AppManifestSHA || target != "nginx-waf" {
		return bad
	}
	return tx.Commit()
}

// Read-only programme admission: a lost POST can leave no Root journal at all.
// Core's original unknown/needs-attention state must still block replacement.
// The older102 schema has NEITHER country table; a partial migration, orphan
// job or mismatched terminal is not treated as an empty queue.
func (s *Store) CheckWAFCountryUpgrade(ctx context.Context) error {
	bad := errors.New("country original Core task is pending, unknown or inconsistent; upgrade refused")
	if ctx == nil || ctx.Err() != nil || s == nil || s.DB == nil {
		return bad
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var tables, pending int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('waf_country_requests','waf_country_results')`).Scan(&tables) != nil {
		return bad
	}
	if tables == 0 {
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM runtime_jobs WHERE kind='waf_country_data'`).Scan(&pending) != nil || pending != 0 {
			return bad
		}
		return tx.Commit()
	}
	if tables != 2 {
		return bad
	}
	checks := []string{
		`SELECT count(*) FROM runtime_jobs WHERE kind='waf_country_data' AND (state IS NULL OR state NOT IN ('succeeded','failed'))`,
		`SELECT count(*) FROM runtime_jobs j LEFT JOIN waf_country_requests r ON r.job_id=j.id WHERE j.kind='waf_country_data' AND (r.job_id IS NULL OR j.target_id!='nginx-waf' OR r.idempotency_key!=j.idempotency_key OR r.created_at!=j.created_at)`,
		`SELECT count(*) FROM waf_country_requests r LEFT JOIN runtime_jobs j ON j.id=r.job_id WHERE j.id IS NULL OR j.kind!='waf_country_data' OR j.target_id!='nginx-waf' OR j.state IS NULL OR j.state NOT IN ('succeeded','failed')`,
		`SELECT count(*) FROM waf_country_results r LEFT JOIN runtime_jobs j ON j.id=r.job_id LEFT JOIN waf_country_requests q ON q.job_id=r.job_id WHERE j.id IS NULL OR q.job_id IS NULL OR j.kind!='waf_country_data' OR r.state IS NULL OR r.state!=j.state OR r.state NOT IN ('succeeded','failed')`,
	}
	for _, query := range checks {
		if tx.QueryRowContext(ctx, query).Scan(&pending) != nil || pending != 0 {
			return bad
		}
	}
	// A terminal label is not completion. Reuse the original complete reader,
	// including actor/key/payload/audit binding and the WHOLE Root result hash.
	// The outer native five-second context is unchanged; timeout or capacity
	// exhaustion never returns partial drain evidence.
	rows, err := tx.QueryContext(ctx, `SELECT CASE WHEN typeof(job_id)='text' AND length(CAST(job_id AS BLOB))=32 THEN job_id ELSE '' END FROM waf_country_requests ORDER BY job_id LIMIT 100001`)
	if err != nil {
		return bad
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || !ValidID(id) || len(ids) >= wafCountryRequestMax || len(ids) > 0 && id <= ids[len(ids)-1] {
			rows.Close()
			return bad
		}
		ids = append(ids, id)
	}
	rowErr, closeErr := rows.Err(), rows.Close()
	if rowErr != nil || closeErr != nil {
		return bad
	}
	for _, id := range ids {
		original, err := readWAFCountryOriginal(ctx, tx, id)
		if err != nil {
			return bad
		}
		detail, err := countryRequestDetail(ctx, tx, original)
		if err != nil || detail.Request.State != "succeeded" && detail.Request.State != "failed" || detail.Request.State == "failed" && detail.Error == "" {
			return bad
		}
	}
	return tx.Commit()
}
