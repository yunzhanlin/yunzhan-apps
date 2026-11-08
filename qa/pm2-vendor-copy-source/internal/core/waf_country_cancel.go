package core

import (
	"context"
	"errors"
	"time"
)

const wafCountryCancelledMessage = "已在提交执行服务前取消原国家数据任务"

// This is Core's before-dispatch evidence only, never a Root cancellation,
// stopped-worker claim, data receipt or policy-activation authority.
type wafCountryCancellation struct {
	Format                 int    `json:"format"`
	JobID                  string `json:"job_id"`
	ActorID                string `json:"actor_id"`
	PayloadSHA             string `json:"payload_sha256"`
	CancelledAt            string `json:"cancelled_at"`
	BeforeDispatch         bool   `json:"before_dispatch"`
	AutomaticReplayAllowed bool   `json:"automatic_replay_allowed"`
}

func countryCancellationProof(ctx context.Context, db accessReader, original wafCountryOriginal) (wafCountryCancellation, error) {
	var empty wafCountryCancellation
	bad := errors.New("国家数据原取消证据不完整；没有认定已取消、重发或修复记录")
	if ctx == nil || ctx.Err() != nil || original.Job.State != "cancelled" {
		return empty, bad
	}
	var stamp string
	if db.QueryRowContext(ctx, `SELECT updated_at FROM runtime_jobs WHERE id=? AND state='cancelled' AND error=? AND steps='[]' AND typeof(updated_at)='text' AND length(CAST(updated_at AS BLOB))=20`, original.Job.ID, wafCountryCancelledMessage).Scan(&stamp) != nil {
		return empty, bad
	}
	t, err := time.Parse(time.RFC3339, stamp)
	if err != nil || t.UTC().Format(time.RFC3339) != stamp || stamp < original.Created {
		return empty, bad
	}
	checks := []struct {
		query string
		args  []any
		count int
	}{
		{`SELECT count(*) FROM waf_country_results WHERE job_id=?`, []any{original.Job.ID}, 0},
		// Exactly the original queue and this cancellation. In particular a
		// dispatch intent, result or an unknown country action must be absent.
		{`SELECT count(*) FROM audit_logs WHERE action LIKE 'waf.country.%' AND target=?`, []any{original.Job.ID}, 2},
		{`SELECT count(*) FROM audit_logs WHERE action='waf.country.queue' AND target=? AND actor=? AND result='queued' AND created_at=?`, []any{original.Job.ID, original.Actor, original.Created}, 1},
		{`SELECT count(*) FROM audit_logs WHERE action='waf.country.cancel-before-dispatch' AND target=? AND actor=? AND result=? AND created_at=?`, []any{original.Job.ID, original.Actor, original.PayloadSHA, stamp}, 1},
	}
	for _, c := range checks {
		var count int
		if db.QueryRowContext(ctx, c.query, c.args...).Scan(&count) != nil || count != c.count {
			return empty, bad
		}
	}
	return wafCountryCancellation{Format: 1, JobID: original.Job.ID, ActorID: original.Actor, PayloadSHA: original.PayloadSHA, CancelledAt: stamp, BeforeDispatch: true}, nil
}

// The UI is only told what the current read snapshot permits. The mutating
// method repeats all checks and races atomically with the durable dispatch.
func countryCanCancelBeforeDispatch(ctx context.Context, db accessReader, original wafCountryOriginal) (bool, error) {
	if original.Job.State != "queued" && original.Job.State != "running" {
		return false, nil
	}
	var count int
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM runtime_jobs j WHERE j.id=? AND j.state IN ('queued','running') AND j.error='' AND j.steps='[]' AND NOT EXISTS(SELECT 1 FROM waf_country_results r WHERE r.job_id=j.id) AND (SELECT count(*) FROM audit_logs a WHERE a.target=j.id AND a.action LIKE 'waf.country.%')=1`, original.Job.ID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 1, nil
}

// No Root endpoint, repository, network or worker is called here. A dispatch
// intent makes cancellation impossible, including a lost Root acknowledgement.
// Conversely, committing cancellation makes every later Root authorization
// fail because the original Core job is no longer running. Neither side can
// overwrite the other's durable evidence.
func (s *Store) cancelWAFCountryBeforeDispatch(ctx context.Context, actor, id, payloadSHA string, selection WAFCountryDataSelection) (wafCountryCancellation, error) {
	var empty wafCountryCancellation
	bad := errors.New("仅当前账户尚未提交执行服务的同一国家数据任务可以取消；已提交或待核对任务保留原状态")
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || !ValidID(actor) || !ValidID(id) || !validLowerSHA256(payloadSHA) || ValidateWAFCountryDataSelection(selection) != nil {
		return empty, bad
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := wafCountryCurrentAccess(ctx, tx, actor); err != nil {
		return empty, err
	}
	original, err := readWAFCountryOriginal(ctx, tx, id)
	if err != nil || original.Actor != actor || original.PayloadSHA != payloadSHA || !SameWAFCountryDataSelection(original.Selection, selection) {
		return empty, bad
	}
	if original.Job.State == "cancelled" {
		proof, err := countryCancellationProof(ctx, tx, original)
		if err != nil {
			return empty, err
		}
		return proof, tx.Commit()
	}
	allowed, err := countryCanCancelBeforeDispatch(ctx, tx, original)
	if err != nil || !allowed {
		return empty, bad
	}
	stamp := Now()
	changed, err := tx.ExecContext(ctx, `UPDATE runtime_jobs SET state='cancelled',error=?,updated_at=? WHERE id=? AND state IN ('queued','running') AND payload=? AND error='' AND steps='[]' AND NOT EXISTS(SELECT 1 FROM waf_country_results r WHERE r.job_id=runtime_jobs.id) AND (SELECT count(*) FROM audit_logs a WHERE a.target=runtime_jobs.id AND a.action LIKE 'waf.country.%')=1`, wafCountryCancelledMessage, stamp, id, original.Job.Payload)
	if err != nil {
		return empty, err
	}
	if n, err := changed.RowsAffected(); err != nil || n != 1 {
		return empty, bad
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'waf.country.cancel-before-dispatch',?,?,?)`, actor, id, original.PayloadSHA, stamp); err != nil {
		return empty, err
	}
	original.Job.State = "cancelled"
	proof, err := countryCancellationProof(ctx, tx, original)
	if err != nil {
		return empty, err
	}
	return proof, tx.Commit()
}
