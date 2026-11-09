package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"local/panel/internal/loadbalancestream"
)

// SELECT-only history, not a skip list or effect capability. Root must also
// verify every original private record, native unit, lease and exit witness.
type LoadBalanceStreamUpgradeJob struct {
	Authority LoadBalanceStreamInstallAuthority
	State     string
}

// A revoked administrator, lost grant table, deleted pending row or terminal
// label cannot make original work disappear. The sole optional live job is
// admitted only by re-reading its COMPLETE current original authority in this
// transaction; passing a bare job ID is deliberately impossible.
func (s *Store) LoadBalanceStreamInstallUpgradeJobs(ctx context.Context, original *LoadBalanceStreamInstallAuthority) ([]LoadBalanceStreamUpgradeJob, error) {
	bad := errLoadBalanceStreamInstallAuthority
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil {
		return nil, bad
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, bad
	}
	defer tx.Rollback()
	var tables, activated, nativeJobs int
	if tx.QueryRowContext(ctx, "SELECT count(*)FROM sqlite_master WHERE tbl_name='load_balance_stream_install_requests'").Scan(&tables) != nil ||
		tx.QueryRowContext(ctx, `SELECT(SELECT count(*)FROM app_registry_install_requests WHERE app_id='load-balance'AND version=?)+(SELECT count(*)FROM app_registry_update_requests WHERE app_id='load-balance'AND version=?)+(SELECT count(*)FROM app_registry_receipts WHERE app_id='load-balance'AND version=?)+(SELECT count(*)FROM app_registry_pending WHERE app_id='load-balance'AND version=?)+(SELECT count(*)FROM audit_logs WHERE action='app.load-balance.stream.install-request')`, loadbalancestream.AppVersion, loadbalancestream.AppVersion, loadbalancestream.AppVersion, loadbalancestream.AppVersion).Scan(&activated) != nil ||
		tx.QueryRowContext(ctx, `SELECT count(*)FROM runtime_jobs WHERE target_id='load-balance'AND kind IN('software_install','software_update')AND CASE WHEN length(CAST(payload AS BLOB)) BETWEEN 1 AND 1024 THEN CASE WHEN json_valid(payload)THEN json_extract(payload,'$.version')ELSE '' END ELSE '' END=?`, loadbalancestream.AppVersion).Scan(&nativeJobs) != nil {
		return nil, bad
	}
	if tables == 0 {
		var pending int
		// An older Core has no native grant schema. Even an unsupported future
		// version, malformed pending payload or old HTTP job must drain before
		// programme replacement; absence of today's 1.9 table is not emptiness.
		if tx.QueryRowContext(ctx, `SELECT(SELECT count(*)FROM app_registry_pending WHERE app_id='load-balance')+(SELECT count(*)FROM runtime_jobs WHERE target_id='load-balance'AND state NOT IN('succeeded','failed','cancelled'))`).Scan(&pending) != nil || pending != 0 || activated != 0 || nativeJobs != 0 || original != nil {
			return nil, bad
		}
		if tx.Commit() != nil {
			return nil, bad
		}
		return []LoadBalanceStreamUpgradeJob{}, nil
	}
	if streamInstallAuthoritySchema(ctx, tx) != nil {
		return nil, bad
	}
	var count int
	if tx.QueryRowContext(ctx, "SELECT count(*)FROM load_balance_stream_install_requests").Scan(&count) != nil || count > streamInstallRequestLimit {
		return nil, bad
	}
	rows, err := tx.QueryContext(ctx, `SELECT job_id,actor_id,access_revision,actor_observation_sha256,kind,payload_sha256,manifest_sha256,request_sha256,key_sha256,created_at FROM load_balance_stream_install_requests WHERE typeof(created_at)='text'AND length(CAST(created_at AS BLOB)) BETWEEN 1 AND 32 ORDER BY job_id LIMIT ?`, streamInstallRequestLimit+1)
	if err != nil {
		return nil, bad
	}
	var jobs []LoadBalanceStreamUpgradeJob
	for rows.Next() {
		v := LoadBalanceStreamInstallAuthority{Format: 1, AppVersion: loadbalancestream.AppVersion}
		var kind string
		if len(jobs) >= streamInstallRequestLimit || rows.Scan(&v.JobID, &v.ActorID, &v.AccessRevision, &v.ActorObservationSHA256, &kind, &v.PayloadSHA256, &v.ManifestSHA256, &v.OriginalRequestSHA256, &v.KeySHA256, &v.JobCreatedAt) != nil {
			rows.Close()
			return nil, bad
		}
		v.Action = strings.TrimPrefix(kind, "software_")
		jobs = append(jobs, LoadBalanceStreamUpgradeJob{Authority: v})
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil || len(jobs) != count || nativeJobs != count {
		return nil, bad
	}
	allowed, succeeded := 0, 0
	for i := range jobs {
		v := jobs[i].Authority
		if !ValidID(v.JobID) || !ValidID(v.ActorID) || v.AccessRevision < 1 || v.Action != "install" && v.Action != "update" || !streamControlDigest(v.ActorObservationSHA256) || !streamControlDigest(v.PayloadSHA256) || !streamControlDigest(v.ManifestSHA256) || !streamControlDigest(v.OriginalRequestSHA256) || !streamControlDigest(v.KeySHA256) {
			return nil, bad
		}
		var kind, payload, key, created, updated, state string
		if tx.QueryRowContext(ctx, `SELECT kind,payload,idempotency_key,created_at,updated_at,state FROM runtime_jobs WHERE id=? AND target_id='load-balance'AND length(CAST(payload AS BLOB)) BETWEEN 1 AND 1024 AND length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 128 AND length(CAST(created_at AS BLOB)) BETWEEN 1 AND 32 AND length(CAST(updated_at AS BLOB)) BETWEEN 1 AND 32 AND length(CAST(state AS BLOB)) BETWEEN 1 AND 32`, v.JobID).Scan(&kind, &payload, &key, &created, &updated, &state) != nil || kind != "software_"+v.Action || Hash(payload) != v.PayloadSHA256 || Hash(key) != v.KeySHA256 || created != v.JobCreatedAt {
			return nil, bad
		}
		first, a := streamInstallClock(created)
		last, b := streamInstallClock(updated)
		expected := `{"settings":{},"version":"` + loadbalancestream.AppVersion + `"}`
		if v.Action == "update" {
			expected = `{"settings":null,"version":"` + loadbalancestream.AppVersion + `"}`
		}
		if !a || !b || last.Before(first) || payload != expected || streamInstallOriginalRegistryHistory(ctx, tx, v, payload, key) != nil {
			return nil, bad
		}
		if original != nil && v.JobID == original.JobID {
			live, err := readLoadBalanceStreamInstallAuthority(ctx, tx, v.JobID, "running")
			if err != nil || v != *original || live != v || state != "running" || !streamInstallGrantMatches(ctx, tx, live) {
				return nil, bad
			}
			allowed++
		} else if state != "succeeded" && state != "failed" && state != "cancelled" {
			return nil, bad
		}
		if state == "succeeded" {
			succeeded++
			if tx.QueryRowContext(ctx, `SELECT count(*)FROM app_registry_receipts WHERE app_id='load-balance'AND scope='load-balance'AND target='load-balance'AND version=? AND sha256=?`, v.AppVersion, v.ManifestSHA256).Scan(&count) != nil || count != 1 {
				return nil, bad
			}
		}
		jobs[i].State = state
	}
	// Complete census: orphan registry requests/audits/receipts and ANY other
	// nonterminal load-balance job are uncertainty, even after revocation.
	if original != nil && allowed != 1 || original == nil && allowed != 0 ||
		tx.QueryRowContext(ctx, `SELECT(SELECT count(*)FROM app_registry_install_requests WHERE app_id='load-balance'AND version=?)+(SELECT count(*)FROM app_registry_update_requests WHERE app_id='load-balance'AND version=?)+(SELECT count(*)FROM audit_logs WHERE action='app.load-balance.stream.install-request')`, loadbalancestream.AppVersion, loadbalancestream.AppVersion).Scan(&count) != nil || count != 2*len(jobs) ||
		tx.QueryRowContext(ctx, `SELECT count(*)FROM app_registry_receipts WHERE app_id='load-balance'AND version=?`, loadbalancestream.AppVersion).Scan(&count) != nil || count != succeeded ||
		tx.QueryRowContext(ctx, `SELECT count(*)FROM runtime_jobs WHERE target_id='load-balance'AND state NOT IN('succeeded','failed','cancelled')`).Scan(&count) != nil || count != allowed ||
		tx.QueryRowContext(ctx, `SELECT count(*)FROM app_registry_pending WHERE app_id='load-balance'`).Scan(&count) != nil || count != allowed || ctx.Err() != nil || tx.Commit() != nil {
		return nil, bad
	}
	return jobs, nil
}

// Terminal history is checked independently of today's actor permissions.
// Live effect admission continues to use readLoadBalanceStreamInstallAuthority
// with the original current full-administrator revision and pending pin.
func streamInstallOriginalRegistryHistory(ctx context.Context, q softwareInstallRowQueryer, v LoadBalanceStreamInstallAuthority, payload, key string) error {
	var actor, digest, stamp, request string
	if v.Action == "install" {
		if q.QueryRowContext(ctx, `SELECT actor_id,sha256,created_at,request_sha256 FROM app_registry_install_requests WHERE job_id=? AND runtime_job_id=? AND idempotency_key=? AND app_id='load-balance'AND provider='panel-module'AND scope='load-balance'AND target='load-balance'AND version=? AND job_payload_sha256=? AND length(CAST(created_at AS BLOB)) BETWEEN 1 AND 32`, v.JobID, v.JobID, key, v.AppVersion, registryInstallDigest([]byte(payload))).Scan(&actor, &digest, &stamp, &request) != nil {
			return errLoadBalanceStreamInstallAuthority
		}
		wanted, err := registryInstallRequestHash("load-balance", actor, key, registryInstallInput{Settings: map[string]any{}, ExpectedVersion: v.AppVersion, ExpectedSHA256: digest})
		if err != nil || request != wanted {
			return errLoadBalanceStreamInstallAuthority
		}
	} else {
		if q.QueryRowContext(ctx, `SELECT actor_id,sha256,created_at FROM app_registry_update_requests WHERE job_id=? AND idempotency_key=? AND app_id='load-balance'AND provider='panel-module'AND scope='load-balance'AND version=? AND length(CAST(created_at AS BLOB)) BETWEEN 1 AND 32`, v.JobID, key, v.AppVersion).Scan(&actor, &digest, &stamp) != nil {
			return errLoadBalanceStreamInstallAuthority
		}
		raw, err := json.Marshal([]string{actor, "load-balance", key, v.JobID, v.AppVersion, digest, "panel-module", "load-balance", payload, stamp})
		if err != nil {
			return errLoadBalanceStreamInstallAuthority
		}
		request = Hash(string(raw))
	}
	when, ok := streamInstallClock(stamp)
	first, firstOK := streamInstallClock(v.JobCreatedAt)
	var audits int
	if !ok || !firstOK || when.Before(first) || actor != v.ActorID || digest != v.ManifestSHA256 || request != v.OriginalRequestSHA256 ||
		q.QueryRowContext(ctx, `SELECT count(*)FROM audit_logs WHERE action='app.load-balance.stream.install-request'AND actor=? AND target=? AND result=? AND created_at=?`, v.ActorID, v.JobID, v.PayloadSHA256, v.JobCreatedAt).Scan(&audits) != nil || audits != 1 {
		return errLoadBalanceStreamInstallAuthority
	}
	return nil
}
