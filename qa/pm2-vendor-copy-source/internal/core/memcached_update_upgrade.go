package core

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"local/panel/internal/appcatalog"
)

// SELECT-only program-upgrade guard. A reservation not yet delivered to Root
// remains work. Revoking/deleting its actor cannot turn it into an empty queue.
// Older databases may lack BOTH objects; a partial schema is never repaired.
func (s *Store) CheckMemcachedUpdateUpgrade(ctx context.Context) error {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return errMemcachedUpdateStore
	}
	defer tx.Rollback()
	var tables, indexes int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='memcached_update_requests'`).Scan(&tables) != nil ||
		tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='index' AND name='one_active_memcached_update_project'`).Scan(&indexes) != nil {
		return errMemcachedUpdateStore
	}
	if tables == 0 && indexes == 0 {
		return tx.Commit()
	}
	if tables != 1 || indexes != 1 {
		return errMemcachedUpdateStore
	}
	for _, definition := range []struct{ kind, name, text string }{{"table", "memcached_update_requests", memcachedUpdateTable}, {"index", "one_active_memcached_update_project", memcachedUpdateProjectIndex}} {
		var actual string
		if tx.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type=? AND name=?`, definition.kind, definition.name).Scan(&actual) != nil || actual != strings.Replace(definition.text, " IF NOT EXISTS", "", 1) {
			return errMemcachedUpdateStore
		}
	}
	inventory, err := memcachedUpdateInventory(ctx, tx)
	if err != nil {
		return err
	}
	for _, row := range inventory {
		switch row.State {
		case "failed_safe", "rolled_back":
		case "committed":
			// Receipt and committed Core chain are one transaction. Merely
			// writing a terminal state cannot bypass the pending-work guard.
			var version, sha, target string
			if tx.QueryRowContext(ctx, `SELECT version,sha256,target FROM app_registry_receipts WHERE app_id='memcached' AND scope=?`, row.Seed.Dispatch.ProjectID).Scan(&version, &sha, &target) != nil {
				return errMemcachedUpdateStore
			}
			comparison, valid := appcatalog.CompareVersions(version, row.Seed.Dispatch.Input.ExpectedVersion)
			if !valid || comparison < 0 || target != "memcached-cache" || !registryDigestValid(sha) || comparison == 0 && sha != row.Seed.Dispatch.Input.ExpectedSHA256 {
				return errMemcachedUpdateStore
			}
		default:
			return errors.New("Memcached 原更新尚未核对结束，阻止程序升级；未重放、取消或删除原事务")
		}
	}
	return tx.Commit()
}
