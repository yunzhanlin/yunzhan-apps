package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"local/panel/internal/loadbalancestream"
)

var errLoadBalanceStreamInstallAuthority = errors.New("TCP/UDP 独立安装的原签名任务、完整管理员权限或待处理版本无法核对；未授权账号、依赖或服务变更")

// A read-only prerequisite for the fixed original Root installer. These fields
// neither verify a downloaded signature nor authorize a native effect. The
// original job, private once-only journal, selected signed package and native
// leases must all be independently verified by that installer too.
type LoadBalanceStreamInstallAuthority struct {
	Format                 int    `json:"format"`
	JobID                  string `json:"job_id"`
	ActorID                string `json:"actor_id"`
	Action                 string `json:"action"`
	AppVersion             string `json:"app_version"`
	ManifestSHA256         string `json:"manifest_sha256"`
	PayloadSHA256          string `json:"payload_sha256"`
	OriginalRequestSHA256  string `json:"original_request_sha256"`
	KeySHA256              string `json:"key_sha256"`
	AccessRevision         int64  `json:"access_revision"`
	ActorObservationSHA256 string `json:"actor_observation_sha256"`
	JobCreatedAt           string `json:"job_created_at"`
}

func streamInstallClock(value string) (time.Time, bool) {
	v, err := time.Parse(time.RFC3339, value)
	return v, err == nil && v.Year() >= 2026 && v.UTC().Format(time.RFC3339) == value && !v.After(time.Now().Add(time.Second))
}

// This authority is not exposed as an HTTP capability or called by the old
// id-only dependency service. The dedicated dispatcher and fixed Root reader
// can inspect ONLY a currently running original signed install/update for the
// independently selected native stream version.
func (s *Store) LoadBalanceStreamInstallAuthority(ctx context.Context, job string) (LoadBalanceStreamInstallAuthority, error) {
	var empty LoadBalanceStreamInstallAuthority
	bad := errLoadBalanceStreamInstallAuthority
	if ctx == nil || ctx.Err() != nil || s == nil || s.DB == nil || !ValidID(job) {
		return empty, bad
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, bad
	}
	defer tx.Rollback()
	if streamInstallAuthoritySchema(ctx, tx) != nil {
		return empty, bad
	}
	out, err := readLoadBalanceStreamInstallAuthority(ctx, tx, job, "running")
	if err != nil || !streamInstallGrantMatches(ctx, tx, out) || tx.Commit() != nil || ctx.Err() != nil {
		return empty, bad
	}
	return out, nil
}

// Same transaction reader for atomic queue issuance and live Root admission.
// A later grant elevation or restored role may not manufacture an original
// full-administrator revision that was never reserved with the signed job.
func readLoadBalanceStreamInstallAuthority(ctx context.Context, tx *sql.Tx, job, state string) (LoadBalanceStreamInstallAuthority, error) {
	var empty LoadBalanceStreamInstallAuthority
	bad := errLoadBalanceStreamInstallAuthority
	if ctx == nil || ctx.Err() != nil || !ValidID(job) || state != "queued" && state != "running" {
		return empty, bad
	}
	var kind, payload, key, created, updated string
	if tx.QueryRowContext(ctx, `SELECT kind,payload,idempotency_key,created_at,updated_at FROM runtime_jobs WHERE id=? AND state=? AND target_id='load-balance' AND kind IN ('software_install','software_update') AND typeof(payload)='text' AND length(CAST(payload AS BLOB)) BETWEEN 1 AND 1024 AND typeof(idempotency_key)='text' AND length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 128 AND length(CAST(created_at AS BLOB)) BETWEEN 1 AND 32 AND length(CAST(updated_at AS BLOB)) BETWEEN 1 AND 32`, job, state).Scan(&kind, &payload, &key, &created, &updated) != nil {
		return empty, bad
	}
	action := strings.TrimPrefix(kind, "software_")
	expected := `{"settings":{},"version":"` + loadbalancestream.AppVersion + `"}`
	if action == "update" {
		expected = `{"settings":null,"version":"` + loadbalancestream.AppVersion + `"}`
	}
	first, firstOK := streamInstallClock(created)
	last, lastOK := streamInstallClock(updated)
	if payload != expected || !firstOK || !lastOK || last.Before(first) || ensureRegistryRequestOpen(tx, key) != nil {
		return empty, bad
	}
	var installs, updates int
	if tx.QueryRowContext(ctx, `SELECT (SELECT count(*)FROM app_registry_install_requests WHERE job_id=? OR runtime_job_id=? OR idempotency_key=?),(SELECT count(*)FROM app_registry_update_requests WHERE job_id=? OR idempotency_key=?)`, job, job, key, job, key).Scan(&installs, &updates) != nil ||
		action == "install" && (installs != 1 || updates != 0) || action == "update" && (updates != 1 || installs != 0) ||
		checkCompetingLoadBalanceStreamInstalls(ctx, tx, job) != nil {
		return empty, bad
	}
	var actor, manifest, stamp, requestHash string
	if action == "install" {
		if tx.QueryRowContext(ctx, `SELECT actor_id,sha256,created_at,request_sha256 FROM app_registry_install_requests WHERE job_id=? AND runtime_job_id=? AND idempotency_key=? AND app_id='load-balance' AND provider='panel-module' AND scope='load-balance' AND target='load-balance' AND version=? AND job_payload_sha256=? AND length(CAST(actor_id AS BLOB))=32 AND length(CAST(sha256 AS BLOB))=64 AND length(CAST(request_sha256 AS BLOB))=64 AND length(CAST(created_at AS BLOB)) BETWEEN 1 AND 32`, job, job, key, loadbalancestream.AppVersion, registryInstallDigest([]byte(payload))).Scan(&actor, &manifest, &stamp, &requestHash) != nil {
			return empty, bad
		}
		// New native installation deliberately requires explicit signed pins
		// and empty settings; legacy omitted pins cannot expand host authority.
		wanted, e := registryInstallRequestHash("load-balance", actor, key, registryInstallInput{Settings: map[string]any{}, ExpectedVersion: loadbalancestream.AppVersion, ExpectedSHA256: manifest})
		if e != nil || requestHash != wanted {
			return empty, bad
		}
	} else {
		if tx.QueryRowContext(ctx, `SELECT actor_id,sha256,created_at FROM app_registry_update_requests WHERE job_id=? AND idempotency_key=? AND app_id='load-balance' AND provider='panel-module' AND scope='load-balance' AND version=? AND length(CAST(actor_id AS BLOB))=32 AND length(CAST(sha256 AS BLOB))=64 AND length(CAST(created_at AS BLOB)) BETWEEN 1 AND 32`, job, key, loadbalancestream.AppVersion).Scan(&actor, &manifest, &stamp) != nil {
			return empty, bad
		}
		// The update table has no stored request digest. Derive a closed hash
		// of ALL independently checked original fields, not a claimed receipt.
		raw, e := json.Marshal([]string{actor, "load-balance", key, job, loadbalancestream.AppVersion, manifest, "panel-module", "load-balance", payload, stamp})
		if e != nil {
			return empty, bad
		}
		requestHash = Hash(string(raw))
	}
	when, clockOK := streamInstallClock(stamp)
	if !ValidID(actor) || !streamControlDigest(manifest) || !streamControlDigest(requestHash) || !clockOK || when.Before(first) || state == "running" && when.After(last) || validateRegistryUpdateRequest("load-balance", actor, key, registryUpdateInput{loadbalancestream.AppVersion, manifest}) != nil {
		return empty, bad
	}
	var pending, matching int
	if tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(CASE WHEN job_id=? AND app_id='load-balance' AND scope='load-balance' AND target='load-balance' AND provider='panel-module' AND version=? AND sha256=? THEN 1 ELSE 0 END),0)FROM app_registry_pending WHERE app_id='load-balance' OR job_id=?`, job, loadbalancestream.AppVersion, manifest, job).Scan(&pending, &matching) != nil || pending != 1 || matching != 1 {
		return empty, bad
	}
	access, err := readUserAccessContext(ctx, tx, actor)
	if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 || access.Revision < 1 || ctx.Err() != nil {
		return empty, bad
	}
	raw, err := json.Marshal(access)
	if err != nil {
		return empty, bad
	}
	out := LoadBalanceStreamInstallAuthority{1, job, actor, action, loadbalancestream.AppVersion, manifest, Hash(payload), requestHash, Hash(key), access.Revision, Hash(string(raw)), created}
	return out, nil
}

// Core may admit a distinct request after a recorded pre-handoff refusal.
// Root still checks every original native record and both fixed units before
// the new request may change host state. No retained job becomes dispatchable.
func checkCompetingLoadBalanceStreamInstalls(ctx context.Context, tx *sql.Tx, job string) error {
	type history struct {
		authority                                           LoadBalanceStreamInstallAuthority
		kind, payload, key, created, updated, detail, steps string
	}
	rows, err := tx.QueryContext(ctx, `SELECT j.id,j.state,j.kind,substr(j.payload,1,1025),substr(j.idempotency_key,1,129),substr(j.created_at,1,33),substr(j.updated_at,1,33),
		substr(j.error,1,1025),substr(j.steps,1,5),r.kind,r.actor_id,r.access_revision,r.actor_observation_sha256,
		r.manifest_sha256,r.payload_sha256,r.request_sha256,r.key_sha256,r.created_at
		FROM runtime_jobs j LEFT JOIN load_balance_stream_install_requests r ON r.job_id=j.id
		WHERE j.target_id='load-balance' AND j.id<>? AND j.state NOT IN ('succeeded','failed','cancelled')
		ORDER BY j.id LIMIT 129`, job)
	if err != nil {
		return errLoadBalanceStreamInstallAuthority
	}
	defer rows.Close()
	var originals []history
	for rows.Next() {
		var h history
		v := &h.authority
		var state, originalKind string
		if len(originals) == 128 ||
			rows.Scan(&v.JobID, &state, &h.kind, &h.payload, &h.key, &h.created, &h.updated,
				&h.detail, &h.steps, &originalKind, &v.ActorID, &v.AccessRevision, &v.ActorObservationSHA256,
				&v.ManifestSHA256, &v.PayloadSHA256, &v.OriginalRequestSHA256, &v.KeySHA256, &v.JobCreatedAt) != nil ||
			state != "needs_attention" || h.kind != originalKind || len(h.key) > 128 {
			return errLoadBalanceStreamInstallAuthority
		}
		v.Format = 1
		v.AppVersion = loadbalancestream.AppVersion
		v.Action = strings.TrimPrefix(h.kind, "software_")
		if !validLoadBalanceStreamHistory(*v, h.payload, h.key, h.created, h.updated) {
			return errLoadBalanceStreamInstallAuthority
		}
		originals = append(originals, h)
	}
	if rows.Err() != nil {
		return errLoadBalanceStreamInstallAuthority
	}
	rows.Close()
	for _, h := range originals {
		if streamInstallOriginalRegistryHistory(ctx, tx, h.authority, h.payload, h.key) != nil ||
			retainedLoadBalanceStreamPreflight(ctx, tx, h.authority.JobID, h.kind, h.updated, h.detail, h.steps) == "" {
			return errLoadBalanceStreamInstallAuthority
		}
	}
	return ctx.Err()
}
