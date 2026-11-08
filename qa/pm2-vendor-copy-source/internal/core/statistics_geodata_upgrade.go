package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// ValidateStatisticsGeoFailedInstall is a SELECT-only cross-authority check,
// not recovery or permission to dispatch. Revocation of the old actor cannot
// erase a completed failure, but the original unique queue and dispatch audit
// must still bind that actor, payload, key and exact Root result. Callers must
// independently authenticate the original private Root files and stopped unit.
func (s *Store) ValidateStatisticsGeoFailedInstall(ctx context.Context, result StatisticsGeoOperation) error {
	bad := errors.New("原地域失败安装与面板任务、账户或提交审计不能核对；阻止程序升级")
	if !ValidID(result.JobID) || ValidateStatisticsGeoSelection(result.Selection) != nil || result.Selection.Action != "install" || result.State != "failed" || result.Error == "" || len(result.Error) > 1024 || len(result.Steps) > 16 {
		return bad
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return bad
	}
	defer tx.Rollback()
	var payload, state, detail, key string
	if tx.QueryRowContext(ctx, `SELECT payload,state,error,idempotency_key FROM runtime_jobs WHERE id=? AND kind='statistics_geodata' AND target_id='website-statistics-v2'`, result.JobID).Scan(&payload, &state, &detail, &key) != nil || state != result.State || detail != result.Error {
		return bad
	}
	raw, _ := json.Marshal(result.Selection)
	if payload != string(raw) {
		return bad
	}
	var count int
	var actor string
	if tx.QueryRowContext(ctx, `SELECT count(*),coalesce(min(actor),'') FROM audit_logs WHERE action='statistics.geodata.queue' AND target=?`, result.JobID).Scan(&count, &actor) != nil || count != 1 || !ValidID(actor) {
		return bad
	}
	id, found, err := statisticsGeoReplay(tx, result.Selection, key, actor)
	if err != nil || !found || id != result.JobID {
		return bad
	}
	var dispatchedActor, digest string
	if tx.QueryRowContext(ctx, `SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action='statistics.geodata.dispatch' AND target=?`, result.JobID).Scan(&count, &dispatchedActor, &digest) != nil || count != 1 || dispatchedActor != actor || digest != Hash(payload) {
		return bad
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return tx.Commit()
}
