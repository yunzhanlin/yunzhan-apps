package core

import (
	"context"
	"database/sql"
	"strings"

	"local/panel/internal/loadbalancestream"
)

const streamInstallRequestTable = "CREATE TABLE IF NOT EXISTS load_balance_stream_install_requests(job_id TEXT PRIMARY KEY NOT NULL,actor_id TEXT NOT NULL,access_revision INTEGER NOT NULL CHECK(access_revision>0),actor_observation_sha256 TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('software_install','software_update')),payload_sha256 TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,request_sha256 TEXT NOT NULL,key_sha256 TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,CHECK(length(job_id)=32 AND length(actor_id)=32 AND length(actor_observation_sha256)=64 AND length(payload_sha256)=64 AND length(manifest_sha256)=64 AND length(request_sha256)=64 AND length(key_sha256)=64))"
const streamInstallRequestLimit = 4096

func streamInstallAuthoritySchema(ctx context.Context, q accessReader) error {
	var count int
	if q.QueryRowContext(ctx, "SELECT count(*)FROM sqlite_master WHERE tbl_name='load_balance_stream_install_requests'").Scan(&count) != nil || count != 3 {
		return errLoadBalanceStreamInstallAuthority
	}
	for _, o := range []struct{ kind, name, definition string }{
		{"table", "load_balance_stream_install_requests", strings.Replace(streamInstallRequestTable, " IF NOT EXISTS", "", 1)},
		{"index", "sqlite_autoindex_load_balance_stream_install_requests_1", ""},
		{"index", "sqlite_autoindex_load_balance_stream_install_requests_2", ""},
	} {
		var kind, table, definition string
		if q.QueryRowContext(ctx, "SELECT count(*),coalesce(min(type),''),coalesce(min(tbl_name),''),coalesce(min(sql),'')FROM sqlite_master WHERE name=?", o.name).Scan(&count, &kind, &table, &definition) != nil || count != 1 || kind != o.kind || table != "load_balance_stream_install_requests" || definition != o.definition {
			return errLoadBalanceStreamInstallAuthority
		}
	}
	return nil
}

// Store.Open initializes only the independent empty schema. It does not enable
// a feature, dispatch native work or adopt missing original history after a
// selected native job/receipt/audit.
func (s *Store) migrateLoadBalanceStreamInstallRequests() error {
	if s == nil || s.DB == nil {
		return errLoadBalanceStreamInstallAuthority
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if tx.QueryRow("SELECT count(*)FROM sqlite_master WHERE tbl_name='load_balance_stream_install_requests'").Scan(&n) != nil {
		return errLoadBalanceStreamInstallAuthority
	}
	if n == 0 {
		if tx.QueryRow("SELECT(SELECT count(*)FROM app_registry_install_requests WHERE app_id='load-balance'AND version=?)+(SELECT count(*)FROM app_registry_update_requests WHERE app_id='load-balance'AND version=?)+(SELECT count(*)FROM app_registry_receipts WHERE app_id='load-balance'AND version=?)+(SELECT count(*)FROM audit_logs WHERE action='app.load-balance.stream.install-request')", loadbalancestream.AppVersion, loadbalancestream.AppVersion, loadbalancestream.AppVersion).Scan(&n) != nil || n != 0 {
			return errLoadBalanceStreamInstallAuthority
		}
		if _, err = tx.Exec(streamInstallRequestTable); err != nil {
			return err
		}
	}
	if streamInstallAuthoritySchema(context.Background(), tx) != nil {
		return errLoadBalanceStreamInstallAuthority
	}
	return tx.Commit()
}

// Compose the normal signed-registry binder with the exact original full-admin
// grant in ONE queue transaction. No legacy HTTP package gains L4 authority.
func (s *Store) bindLoadBalanceStreamRegistryRequest(actor, key, target, version string, registry func(*sql.Tx, string, bool) error) func(*sql.Tx, string, bool) error {
	if target != "load-balance" || version != loadbalancestream.AppVersion {
		return registry
	}
	return func(tx *sql.Tx, job string, existing bool) error {
		if registry == nil {
			return errLoadBalanceStreamInstallAuthority
		}
		if err := registry(tx, job, existing); err != nil {
			return err
		}
		return s.bindLoadBalanceStreamInstallRequest(actor, key)(tx, job, existing)
	}
}

func streamInstallGrantMatches(ctx context.Context, q accessReader, v LoadBalanceStreamInstallAuthority) bool {
	var count int
	return q.QueryRowContext(ctx, `SELECT count(*)FROM load_balance_stream_install_requests WHERE job_id=? AND actor_id=? AND access_revision=? AND actor_observation_sha256=? AND kind=? AND payload_sha256=? AND manifest_sha256=? AND request_sha256=? AND key_sha256=? AND created_at=?`, v.JobID, v.ActorID, v.AccessRevision, v.ActorObservationSHA256, "software_"+v.Action, v.PayloadSHA256, v.ManifestSHA256, v.OriginalRequestSHA256, v.KeySHA256, v.JobCreatedAt).Scan(&count) == nil && count == 1
}

// Compose AFTER the normal signed-registry binder in the same queue SQL
// transaction. There is no effect dispatch here and no backfill for old jobs.
func (s *Store) bindLoadBalanceStreamInstallRequest(actor, key string) func(*sql.Tx, string, bool) error {
	return func(tx *sql.Tx, job string, existing bool) error {
		ctx := context.Background()
		if !ValidID(actor) || key == "" || streamInstallAuthoritySchema(ctx, tx) != nil {
			return errLoadBalanceStreamInstallAuthority
		}
		v, err := readLoadBalanceStreamInstallAuthority(ctx, tx, job, "queued")
		if err != nil || v.ActorID != actor || v.KeySHA256 != Hash(key) {
			return errLoadBalanceStreamInstallAuthority
		}
		var count int
		if tx.QueryRow("SELECT count(*)FROM load_balance_stream_install_requests WHERE job_id=? OR key_sha256=?", job, Hash(key)).Scan(&count) != nil {
			return errLoadBalanceStreamInstallAuthority
		}
		if count != 0 {
			if count != 1 || !streamInstallGrantMatches(ctx, tx, v) {
				return errLoadBalanceStreamInstallAuthority
			}
			return nil
		}
		if existing || tx.QueryRow("SELECT count(*)FROM load_balance_stream_install_requests").Scan(&count) != nil || count >= streamInstallRequestLimit {
			return errLoadBalanceStreamInstallAuthority
		}
		if _, err = tx.Exec(`INSERT INTO load_balance_stream_install_requests(job_id,actor_id,access_revision,actor_observation_sha256,kind,payload_sha256,manifest_sha256,request_sha256,key_sha256,created_at)VALUES(?,?,?,?,?,?,?,?,?,?)`, v.JobID, v.ActorID, v.AccessRevision, v.ActorObservationSHA256, "software_"+v.Action, v.PayloadSHA256, v.ManifestSHA256, v.OriginalRequestSHA256, v.KeySHA256, v.JobCreatedAt); err != nil {
			return err
		}
		_, err = tx.Exec("INSERT INTO audit_logs(actor,action,target,result,created_at)VALUES(?,'app.load-balance.stream.install-request',?,?,?)", actor, job, v.PayloadSHA256, v.JobCreatedAt)
		return err
	}
}
