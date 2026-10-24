package core

import (
	"context"
	"database/sql"
	"errors"
)

// Read-only preflight, including queued Core intents not yet published to Root.
// Deleted/revoked owners do not erase evidence or block valid terminal history.
// A genuinely older schema may lack BOTH dedicated tables; partial/new schemas
// and unknown states are not silently interpreted as an empty queue.
func (s *Store) CheckHostDiskUpgrade(ctx context.Context) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return errHostDiskRecord
	}
	defer tx.Rollback()
	if err := checkHostDiskUpgrade(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func checkHostDiskUpgrade(ctx context.Context, tx *sql.Tx) error {
	var jobs, results, closures int
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='disk_host_jobs'").Scan(&jobs) != nil ||
		tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='disk_host_job_results'").Scan(&results) != nil || tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='disk_host_job_closures'").Scan(&closures) != nil {
		return errHostDiskRecord
	}
	if jobs == 0 && results == 0 && closures == 0 {
		return nil
	}
	if jobs != 1 || results != 1 || closures != 1 {
		return errHostDiskRecord
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+hostDiskColumns+" FROM disk_host_jobs LIMIT 129")
	if err != nil {
		return errHostDiskRecord
	}
	retained := []HostDiskJob{}
	for rows.Next() {
		j, err := scanHostDiskJob(rows)
		if err != nil {
			rows.Close()
			return errHostDiskRecord
		}
		retained = append(retained, j)
		if len(retained) > 128 {
			rows.Close()
			return errHostDiskRecord
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return errHostDiskRecord
	}
	for _, j := range retained {
		if hostDiskAudit(ctx, tx, j) != nil {
			return errHostDiskRecord
		}
		switch j.State {
		case "complete", "partial", "canceled", "failed":
		default:
			return errors.New("原全盘任务尚未核对退出，程序升级被阻止；未取消、重放或删除任务")
		}
	}
	var orphan int
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM disk_host_job_results r WHERE NOT EXISTS(SELECT 1 FROM disk_host_jobs j WHERE j.id=r.job_id)").Scan(&orphan) != nil || orphan != 0 {
		return errHostDiskRecord
	}
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM disk_host_job_closures c WHERE NOT EXISTS(SELECT 1 FROM disk_host_jobs j WHERE j.id=c.job_id)").Scan(&orphan) != nil || orphan != 0 {
		return errHostDiskRecord
	}
	return nil
}
