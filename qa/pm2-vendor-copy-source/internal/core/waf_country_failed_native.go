package core

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
)

// Read-only historical evidence for ONE failed original worker. Current
// permission to download is not inferred from a past result. This does not
// reclassify, recover or replay the original task or replace its error.
func (s *Store) ValidateWAFCountryFailedNative(ctx context.Context, result WAFCountryDataOperation) error {
	bad := errors.New("国家数据失败单元缺少完整匹配的原 Core 终态")
	if ctx == nil || ctx.Err() != nil || s == nil || s.DB == nil || result.State != "failed" || result.Cache != nil || result.Error == "" || !ValidID(result.JobID) {
		return bad
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	original, err := readWAFCountryOriginal(ctx, tx, result.JobID)
	if err != nil || original.Job.State != "failed" || original.Actor != result.ActorID || original.PayloadSHA != result.PayloadSHA || !SameWAFCountryDataSelection(original.Selection, result.Selection) {
		return bad
	}
	detail, err := countryRequestDetail(ctx, tx, original)
	if err != nil || detail.Result == nil || !reflect.DeepEqual(*detail.Result, result) || !validLowerSHA256(detail.ResultSHA) || detail.Error != result.Error {
		return bad
	}
	for _, row := range []struct{ action, actor, value string }{
		{"waf.country.dispatch", original.Actor, original.PayloadSHA},
		{"waf.country.result", "executor", "failed:" + detail.ResultSHA},
	} {
		var count int
		var actor, value string
		if tx.QueryRowContext(ctx, `SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action=? AND target=?`, row.action, result.JobID).Scan(&count, &actor, &value) != nil || count != 1 || actor != row.actor || value != row.value {
			return bad
		}
	}
	return tx.Commit()
}
