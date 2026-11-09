package core

import (
	"context"
	"database/sql"
	"errors"

	"local/panel/internal/appcatalog"
)

// A reservation awaiting its original Root delivery/result is still work,
// including after actor revocation. This SELECT-only fence neither polls a
// mutating legacy job observer nor reconciles/deletes the pending row. Root's
// complete separate journal fence remains independently mandatory.
func (s *Store) CheckMemcachedUnixInstallUpgrade(ctx context.Context) error {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil {
		return errMemcachedUnixAuthority
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return errMemcachedUnixAuthority
	}
	defer tx.Rollback()
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM app_registry_pending WHERE app_id='memcached' AND version=?`, appcatalog.MemcachedUnixVersion).Scan(&count) != nil {
		return errMemcachedUnixAuthority
	}
	if count != 0 {
		return errors.New("Memcached Socket 原安装请求尚未与 Root 完整结算；阻止程序或其他 Docker 变更，不重发、不删除")
	}
	if ctx.Err() != nil || tx.Commit() != nil {
		return errMemcachedUnixAuthority
	}
	return nil
}

// Only a native caller with the independently verified ORIGINAL submission
// may use this narrower census under its real run/engine leases. Recheck the
// exact live binding first; never accept a bare caller-selected skip-job ID.
func (s *Store) CheckMemcachedUnixOtherInstalls(ctx context.Context, original DockerProjectRequest, expected MemcachedUnixBinding) error {
	bound, err := s.MemcachedUnixInstallBinding(ctx, original)
	if err != nil || bound != expected {
		return errMemcachedUnixAuthority
	}
	var count int
	if s.DB.QueryRowContext(ctx, `SELECT count(*) FROM app_registry_pending WHERE app_id='memcached' AND version=? AND job_id<>?`, appcatalog.MemcachedUnixVersion, original.JobID).Scan(&count) != nil || count != 0 || ctx.Err() != nil {
		return errMemcachedUnixAuthority
	}
	return nil
}
