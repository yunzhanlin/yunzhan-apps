package core

import (
	"context"
	"errors"
)

func statisticsGeoCurrentAuthority(ctx context.Context, db accessReader, actor string) error {
	access, err := readUserAccessContext(ctx, db, actor)
	if !ValidID(actor) || err != nil || access.Role != "admin" || !menuSubset([]string{"runtimes", "sites"}, access.MenuIDs) {
		return errors.New("原地域任务账户已删除、降权或收回网站/软件商店权限；未提交执行")
	}
	return nil
}

// Re-read the claimed immutable job and its unique original actor. Commit the
// dispatch intent before the one POST: a crash or lost response may only observe
// that same Root ID, never submit it again. Intent is not proof of Root execution.
// Current authorization is checked before network work and again at this durable
// dispatch boundary. A later revocation cannot undo an already submitted native
// operation; it must not prevent read-only reconciliation of its original result.
func (s *Store) statisticsGeoDispatchBoundary(ctx context.Context, j Job, commitIntent bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	bad := errors.New("原地域任务、账户审计或执行意图不能核对；未提交或重发")
	if !ValidID(j.ID) || j.TargetID != "website-statistics-v2" || j.Kind != "statistics_geodata" {
		return false, bad
	}
	if _, err := DecodeStatisticsGeoSelection([]byte(j.Payload)); err != nil {
		return false, bad
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var payload, state string
	if err = tx.QueryRowContext(ctx, "SELECT payload,state FROM runtime_jobs WHERE id=? AND target_id=? AND kind=?", j.ID, j.TargetID, j.Kind).Scan(&payload, &state); err != nil || state != "running" || payload != j.Payload {
		return false, bad
	}
	var count int
	var actor, result string
	if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action='statistics.geodata.queue' AND target=?", j.ID).Scan(&count, &actor, &result); err != nil || count != 1 || !ValidID(actor) || result != "queued" {
		return false, bad
	}
	var dispatchedActor, digest string
	if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action='statistics.geodata.dispatch' AND target=?", j.ID).Scan(&count, &dispatchedActor, &digest); err != nil || count > 1 {
		return false, bad
	}
	if count == 1 {
		if dispatchedActor != actor || digest != Hash(j.Payload) {
			return false, bad
		}
		return true, tx.Commit()
	}
	if err = statisticsGeoCurrentAuthority(ctx, tx, actor); err != nil {
		return false, err
	}
	if commitIntent {
		if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'statistics.geodata.dispatch',?,?,?)", actor, j.ID, Hash(j.Payload), Now()); err != nil {
			return false, errors.New("地域任务提交意图不能保存；未提交执行")
		}
	}
	return false, tx.Commit()
}
