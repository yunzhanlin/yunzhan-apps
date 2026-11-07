package core

import (
	"database/sql"
	"errors"
)

// Consume before the RPC. If the panel is interrupted after dispatch, recovery
// may observe the original native job but cannot automatically dispatch a second
// compilation using the earlier human retry authorization. Job payload/registry
// receipt bindings remain byte-for-byte unchanged.
func (s *Store) takeRuntimeNativeRetry(j Job) (bool, error) {
	if j.Kind != "install_runtime" && j.Kind != "install_php_extension" {
		return false, errors.New("该任务不接受原生运行时重试授权")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var state, payload string
	if err := tx.QueryRow(`SELECT state,payload FROM runtime_jobs WHERE id=? AND target_id=? AND kind=?`, j.ID, j.TargetID, j.Kind).Scan(&state, &payload); err != nil || state != "running" || payload != j.Payload {
		return false, errors.New("安装任务当前执行身份不可核实，未领取重试授权")
	}
	var consumed sql.NullString
	err = tx.QueryRow(`SELECT consumed_at FROM runtime_native_retry_grants WHERE job_id=?`, j.ID).Scan(&consumed)
	if errors.Is(err, sql.ErrNoRows) || err == nil && consumed.Valid {
		return false, tx.Commit()
	}
	if err != nil {
		return false, err
	}
	result, err := tx.Exec(`UPDATE runtime_native_retry_grants SET consumed_at=? WHERE job_id=? AND consumed_at IS NULL`, Now(), j.ID)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return false, errors.New("原生重试授权已被领取，未重复尝试")
	}
	return true, tx.Commit()
}
