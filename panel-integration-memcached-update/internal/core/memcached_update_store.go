package core

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"local/panel/internal/appcatalog"
)

const memcachedUpdateRequestLimit = 128
const memcachedUpdateTable = `CREATE TABLE IF NOT EXISTS memcached_update_requests(request_id TEXT PRIMARY KEY NOT NULL,job_id TEXT NOT NULL UNIQUE,actor_id TEXT NOT NULL,project_id TEXT NOT NULL,dispatch_sha256 TEXT NOT NULL,seed_record TEXT NOT NULL,chain TEXT NOT NULL DEFAULT '',state TEXT NOT NULL CHECK(state IN ('reserved','unknown','prepared','pull_started','image_verified','apply_started','applied','committed','rollback_started','rolled_back','failed_safe','needs_attention')),created_at TEXT NOT NULL,updated_at TEXT NOT NULL,CHECK(length(request_id)=32 AND length(job_id)=32 AND length(actor_id)=32 AND length(project_id)=32 AND length(dispatch_sha256)=64 AND length(seed_record) BETWEEN 1 AND 16384 AND length(chain)<=262144))`
const memcachedUpdateProjectIndex = `CREATE UNIQUE INDEX IF NOT EXISTS one_active_memcached_update_project ON memcached_update_requests(project_id) WHERE state NOT IN ('committed','rolled_back','failed_safe')`

var errMemcachedUpdateStore = errors.New("Memcached 原更新请求、审计或事件链不能核对；未重发或覆盖")
var errMemcachedUpdateAuthority = errors.New("Memcached 主机容器更新需要原账户当前完整管理员权限")

// SELECT-only, including when called by a fresh privileged native reader that
// deliberately does not call OpenStore/migrations. A vanished project fence,
// replaced table/index or added trigger is not restored or accepted as absence.
func memcachedUpdateSchema(ctx context.Context, db accessReader) error {
	var count int
	if db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE tbl_name='memcached_update_requests'`).Scan(&count) != nil || count != 4 {
		return errMemcachedUpdateStore
	}
	for _, object := range []struct{ kind, name, text string }{
		{"table", "memcached_update_requests", strings.Replace(memcachedUpdateTable, " IF NOT EXISTS", "", 1)},
		{"index", "one_active_memcached_update_project", strings.Replace(memcachedUpdateProjectIndex, " IF NOT EXISTS", "", 1)},
		{"index", "sqlite_autoindex_memcached_update_requests_1", ""},
		{"index", "sqlite_autoindex_memcached_update_requests_2", ""},
	} {
		var kind, table, definition string
		if db.QueryRowContext(ctx, `SELECT count(*),coalesce(min(type),''),coalesce(min(tbl_name),''),coalesce(min(sql),'') FROM sqlite_master WHERE name=?`, object.name).Scan(&count, &kind, &table, &definition) != nil || count != 1 || kind != object.kind || table != "memcached_update_requests" || definition != object.text {
			return errMemcachedUpdateStore
		}
	}
	return nil
}

// The initial table/index pair is one atomic migration. Partial or changed
// pre-existing schemas fail closed, not repaired with missing indexes or rows.
func (s *Store) migrateMemcachedUpdates() error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var tables, indexes int
	if tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='memcached_update_requests'`).Scan(&tables) != nil || tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name='one_active_memcached_update_project'`).Scan(&indexes) != nil {
		return errMemcachedUpdateStore
	}
	if tables == 0 && indexes == 0 {
		if _, err := tx.Exec(memcachedUpdateTable); err != nil {
			return err
		}
		if _, err := tx.Exec(memcachedUpdateProjectIndex); err != nil {
			return err
		}
	} else if tables != 1 || indexes != 1 {
		return errMemcachedUpdateStore
	}
	if err := memcachedUpdateSchema(context.Background(), tx); err != nil {
		return err
	}
	return tx.Commit()
}

func memcachedUpdateAuthority(ctx context.Context, db accessReader, actor, expectedRevision string) error {
	if !ValidID(actor) {
		return errMemcachedUpdateAuthority
	}
	access, err := readUserAccessContext(ctx, db, actor)
	if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 || access.Revision < 1 || expectedRevision != "" && strconv.FormatInt(access.Revision, 10) != expectedRevision {
		return errMemcachedUpdateAuthority
	}
	return nil
}

type memcachedUpdateReservation struct {
	Seed                 MemcachedUpdateRecord
	Chain                []MemcachedUpdateRecord
	State                string
	CreatedAt, UpdatedAt string
}

// Bounds are applied inside SQL before large/corrupted text reaches the reader.
// SQLite substr(empty BLOB) is NULL. Preserve a legitimate empty chain as an
// empty BLOB, while the independent byte-length scan still rejects an actually
// NULL/corrupted source column. Nonempty records remain strictly canonical.
const memcachedUpdateColumns = `request_id,job_id,actor_id,project_id,dispatch_sha256,substr(CAST(seed_record AS BLOB),1,16385),length(CAST(seed_record AS BLOB)),coalesce(substr(CAST(chain AS BLOB),1,262145),X''),length(CAST(chain AS BLOB)),state,created_at,updated_at`

func scanMemcachedUpdateReservation(row interface{ Scan(...any) error }) (memcachedUpdateReservation, error) {
	var out memcachedUpdateReservation
	var request, job, actor, project, dispatchSHA, seedRaw, chainRaw string
	var seedBytes, chainBytes int
	if err := row.Scan(&request, &job, &actor, &project, &dispatchSHA, &seedRaw, &seedBytes, &chainRaw, &chainBytes, &out.State, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return out, err
	}
	seed, err := DecodeMemcachedUpdateRecord([]byte(seedRaw))
	if err != nil || seedBytes != len(seedRaw) || seedBytes > MaxMemcachedUpdateRecordBytes || chainBytes != len(chainRaw) || chainBytes > MaxMemcachedUpdateChainBytes ||
		seed.Phase != "prepared" || seed.Dispatch.RequestID != request || seed.Dispatch.JobID != job || seed.Dispatch.ActorID != actor || seed.Dispatch.ProjectID != project || seed.DispatchSHA256 != dispatchSHA {
		return out, errMemcachedUpdateStore
	}
	out.Seed = seed
	created, e1 := time.Parse(time.RFC3339, out.CreatedAt)
	updated, e2 := time.Parse(time.RFC3339, out.UpdatedAt)
	if e1 != nil || e2 != nil || created.UTC().Format(time.RFC3339) != out.CreatedAt || updated.UTC().Format(time.RFC3339) != out.UpdatedAt || created.Year() < 2026 || updated.Before(created) {
		return out, errMemcachedUpdateStore
	}
	if chainRaw == "" {
		if out.State != "reserved" && out.State != "unknown" {
			return out, errMemcachedUpdateStore
		}
		return out, nil
	}
	if json.Unmarshal([]byte(chainRaw), &out.Chain) != nil {
		return out, errMemcachedUpdateStore
	}
	canonical, err := json.Marshal(out.Chain)
	if err != nil || !bytes.Equal(canonical, []byte(chainRaw)) {
		return out, errMemcachedUpdateStore
	}
	head, err := MemcachedUpdateChainHead(seed, out.Chain)
	if err != nil || out.State != head.Phase {
		return out, errMemcachedUpdateStore
	}
	return out, nil
}

func memcachedUpdateAudit(ctx context.Context, db accessReader, row memcachedUpdateReservation) error {
	check := func(action, target, result string) error {
		var count int
		var actor, stored string
		if db.QueryRowContext(ctx, `SELECT count(*),coalesce(min(actor),''),coalesce(min(result),'') FROM audit_logs WHERE action=? AND target=?`, action, target).Scan(&count, &actor, &stored) != nil || count != 1 || actor != row.Seed.Dispatch.ActorID || stored != result {
			return errMemcachedUpdateStore
		}
		return nil
	}
	if err := check("app.memcached.update.reserve", row.Seed.Dispatch.JobID, row.Seed.RecordSHA256); err != nil {
		return err
	}
	for _, record := range row.Chain {
		if err := check("app.memcached.update.observe", row.Seed.Dispatch.JobID+":"+strconv.Itoa(record.Sequence), record.RecordSHA256); err != nil {
			return err
		}
	}
	var count int
	if db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE action='app.memcached.update.observe' AND target LIKE ?`, row.Seed.Dispatch.JobID+":%").Scan(&count) != nil || count != len(row.Chain) {
		return errMemcachedUpdateStore
	}
	return nil
}

func memcachedUpdateInventory(ctx context.Context, tx *sql.Tx) ([]memcachedUpdateReservation, error) {
	if err := memcachedUpdateSchema(ctx, tx); err != nil {
		return nil, err
	}
	// An audit without its original reservation is retained uncertainty, not
	// absence. Do not admit a replacement after a partial/corrupted deletion.
	// Per-row checks below also require exactly one audit for every real event
	// and reject extra/aliased sequence targets within a known job prefix.
	var orphan int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs a WHERE a.action LIKE 'app.memcached.update.%' AND (
	 a.action NOT IN ('app.memcached.update.reserve','app.memcached.update.observe') OR
	 (a.action='app.memcached.update.reserve' AND NOT EXISTS(SELECT 1 FROM memcached_update_requests r WHERE r.job_id=a.target)) OR
	 (a.action='app.memcached.update.observe' AND NOT EXISTS(SELECT 1 FROM memcached_update_requests r WHERE r.job_id=substr(a.target,1,32) AND substr(a.target,33,1)=':'))
	)`).Scan(&orphan) != nil || orphan != 0 {
		return nil, errMemcachedUpdateStore
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+memcachedUpdateColumns+" FROM memcached_update_requests LIMIT 129")
	if err != nil {
		return nil, errMemcachedUpdateStore
	}
	defer rows.Close()
	result := []memcachedUpdateReservation{}
	for rows.Next() {
		row, err := scanMemcachedUpdateReservation(rows)
		if err != nil {
			return nil, errMemcachedUpdateStore
		}
		result = append(result, row)
		if len(result) > memcachedUpdateRequestLimit {
			return nil, errMemcachedUpdateStore
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errMemcachedUpdateStore
	}
	rows.Close()
	projects := map[string]bool{}
	for _, row := range result {
		if memcachedUpdateAudit(ctx, tx, row) != nil {
			return nil, errMemcachedUpdateStore
		}
		if row.State != "committed" && row.State != "rolled_back" && row.State != "failed_safe" {
			if projects[row.Seed.Dispatch.ProjectID] {
				return nil, errMemcachedUpdateStore
			}
			projects[row.Seed.Dispatch.ProjectID] = true
		}
	}
	return result, nil
}

func readMemcachedUpdateReservation(ctx context.Context, db accessReader, requestID string) (memcachedUpdateReservation, bool, error) {
	var empty memcachedUpdateReservation
	if !ValidID(requestID) {
		return empty, false, errMemcachedUpdateStore
	}
	out, err := scanMemcachedUpdateReservation(db.QueryRowContext(ctx, "SELECT "+memcachedUpdateColumns+" FROM memcached_update_requests WHERE request_id=?", requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return empty, false, nil
	}
	if err != nil || memcachedUpdateAudit(ctx, db, out) != nil {
		return empty, false, errMemcachedUpdateStore
	}
	return out, true, nil
}

// Reserve identity and audit atomically BEFORE the first executor POST. A
// repeated request only returns the retained binding; it never grants dispatch
// again. This is not a queue/installation receipt and never advances a version.
func (s *Store) reserveMemcachedUpdate(ctx context.Context, actor string, seed MemcachedUpdateRecord) (memcachedUpdateReservation, bool, error) {
	var empty memcachedUpdateReservation
	if ValidateMemcachedUpdateRecord(seed) != nil || seed.Phase != "prepared" || seed.Dispatch.ActorID != actor {
		return empty, false, errMemcachedUpdateStore
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, false, err
	}
	defer tx.Rollback()
	if err := memcachedUpdateAuthority(ctx, tx, actor, seed.Dispatch.AccessRevision); err != nil {
		return empty, false, err
	}
	prior, found, err := readMemcachedUpdateReservation(ctx, tx, seed.Dispatch.RequestID)
	if err != nil {
		return empty, false, err
	}
	if found {
		if prior.Seed != seed {
			return empty, false, errMemcachedUpdateStore
		}
		return prior, false, tx.Commit()
	}
	inventory, err := memcachedUpdateInventory(ctx, tx)
	if err != nil {
		return empty, false, err
	}
	if len(inventory) >= memcachedUpdateRequestLimit {
		return empty, false, errors.New("Memcached 更新请求达到128份保留上限；不自动清理或重发原任务")
	}
	for _, original := range inventory {
		if original.Seed.Dispatch.JobID == seed.Dispatch.JobID || original.Seed.Dispatch.ProjectID == seed.Dispatch.ProjectID && original.State != "committed" && original.State != "rolled_back" && original.State != "failed_safe" {
			return empty, false, errors.New("Memcached 原项目存在未核对更新；不换任务ID重试")
		}
	}
	raw, _ := json.Marshal(seed)
	now := Now()
	_, err = tx.ExecContext(ctx, `INSERT INTO memcached_update_requests(request_id,job_id,actor_id,project_id,dispatch_sha256,seed_record,chain,state,created_at,updated_at) VALUES(?,?,?,?,?,?,'','reserved',?,?)`, seed.Dispatch.RequestID, seed.Dispatch.JobID, actor, seed.Dispatch.ProjectID, seed.DispatchSHA256, string(raw), now, now)
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'app.memcached.update.reserve',?,?,?)`, actor, seed.Dispatch.JobID, seed.RecordSHA256, now)
	}
	if err != nil {
		return empty, false, errMemcachedUpdateStore
	}
	out, found, err := readMemcachedUpdateReservation(ctx, tx, seed.Dispatch.RequestID)
	if err != nil || !found {
		return empty, false, errMemcachedUpdateStore
	}
	return out, true, tx.Commit()
}

// A transport timeout is not failure or non-submission. Do not clear a previous
// observed phase, release the project slot, advance a version or allow resend.
func (s *Store) markMemcachedUpdateUnknown(ctx context.Context, actor, requestID string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row, found, err := readMemcachedUpdateReservation(ctx, tx, requestID)
	if err != nil || !found || row.Seed.Dispatch.ActorID != actor {
		return errMemcachedUpdateStore
	}
	if row.State != "reserved" {
		return tx.Commit()
	}
	now := Now()
	if now < row.UpdatedAt {
		now = row.UpdatedAt
	}
	if _, err := tx.ExecContext(ctx, `UPDATE memcached_update_requests SET state='unknown',updated_at=? WHERE request_id=? AND state='reserved'`, now, requestID); err != nil {
		return errMemcachedUpdateStore
	}
	return tx.Commit()
}

// Read-only status permission and original actor isolation are checked now, not
// inherited from a stale session, cached role or the actor string in a body.
func (s *Store) memcachedUpdateForActor(ctx context.Context, actor, requestID string) (memcachedUpdateReservation, bool, error) {
	var empty memcachedUpdateReservation
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, false, err
	}
	defer tx.Rollback()
	if err := memcachedUpdateAuthority(ctx, tx, actor, ""); err != nil {
		return empty, false, err
	}
	row, found, err := readMemcachedUpdateReservation(ctx, tx, requestID)
	if err != nil || found && row.Seed.Dispatch.ActorID != actor {
		return empty, false, errMemcachedUpdateStore
	}
	return row, found, tx.Commit()
}

// The native worker calls this against the protected Core database before any
// NEW pull/apply effect, including after a slow pull. It is SELECT-only, binds
// original reservation+audit+seed, and rechecks current full administrator access.
// Known-outcome restoration/recovery requires a separate original-transaction
// policy; this function is never a grant to blindly replay a queued command.
func (s *Store) CheckMemcachedUpdateMutation(ctx context.Context, expected MemcachedUpdateRecord) error {
	return s.checkMemcachedUpdateOriginal(ctx, expected, true)
}

// Only a native worker already holding the ORIGINAL run/engine leases and a
// verified rollback_started chain may use this original reservation condition
// for bounded restoration. It is deliberately not a current grant to pull,
// update, retry an interrupted job or run any other Docker action. Revocation
// during a failed update must not force the already-authorized service to stay
// broken. Root independently binds the retained image and fixed rollback YAML.
func (s *Store) CheckMemcachedUpdateRestoration(ctx context.Context, expected MemcachedUpdateRecord) error {
	return s.checkMemcachedUpdateOriginal(ctx, expected, false)
}

func (s *Store) checkMemcachedUpdateOriginal(ctx context.Context, expected MemcachedUpdateRecord, currentGrant bool) error {
	if ctx == nil || s == nil || s.DB == nil || ValidateMemcachedUpdateRecord(expected) != nil || expected.Phase != "prepared" {
		return errMemcachedUpdateStore
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return errMemcachedUpdateStore
	}
	defer tx.Rollback()
	inventory, err := memcachedUpdateInventory(ctx, tx)
	if err != nil {
		return errMemcachedUpdateStore
	}
	var original *memcachedUpdateReservation
	for i := range inventory {
		if inventory[i].Seed.Dispatch.RequestID == expected.Dispatch.RequestID {
			original = &inventory[i]
		}
	}
	if original == nil || original.Seed != expected || original.State == "committed" || original.State == "rolled_back" || original.State == "failed_safe" || original.State == "needs_attention" {
		return errMemcachedUpdateStore
	}
	if currentGrant {
		if err := memcachedUpdateAuthority(ctx, tx, expected.Dispatch.ActorID, expected.Dispatch.AccessRevision); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Only an independently bound complete original Root chain can reconcile a
// receipt. This internal method is NOT an HTTP endpoint accepting user records.
// A missed poll can catch up, but a fork, shorter reply, fabricated phase or
// same-version package conflict cannot rewrite the retained evidence/version.
func (s *Store) reconcileMemcachedUpdate(ctx context.Context, requestID string, chain []MemcachedUpdateRecord) (memcachedUpdateReservation, error) {
	var empty memcachedUpdateReservation
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	row, found, err := readMemcachedUpdateReservation(ctx, tx, requestID)
	if err != nil || !found {
		return empty, errMemcachedUpdateStore
	}
	head, err := MemcachedUpdateChainHead(row.Seed, chain)
	if err != nil {
		return empty, err
	}
	if len(row.Chain) > 0 {
		for i := 0; i < len(row.Chain) && i < len(chain); i++ {
			if row.Chain[i] != chain[i] {
				return empty, errMemcachedUpdateStore
			}
		}
		if len(chain) <= len(row.Chain) {
			return row, tx.Commit() // Valid stale read, never regress or re-audit.
		}
	}
	raw, err := json.Marshal(chain)
	if err != nil || len(raw) > MaxMemcachedUpdateChainBytes {
		return empty, errMemcachedUpdateStore
	}
	now := Now()
	if now < row.UpdatedAt {
		now = row.UpdatedAt // Metadata monotonicity, not a freshness assertion.
	}
	for _, record := range chain[len(row.Chain):] {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'app.memcached.update.observe',?,?,?)`, row.Seed.Dispatch.ActorID, row.Seed.Dispatch.JobID+":"+strconv.Itoa(record.Sequence), record.RecordSHA256, now); err != nil {
			return empty, errMemcachedUpdateStore
		}
	}
	if head.Phase == "committed" {
		var oldVersion, oldSHA, target string
		err := tx.QueryRowContext(ctx, `SELECT version,sha256,target FROM app_registry_receipts WHERE app_id='memcached' AND scope=?`, row.Seed.Dispatch.ProjectID).Scan(&oldVersion, &oldSHA, &target)
		if err == nil {
			comparison, valid := appcatalog.CompareVersions(row.Seed.Dispatch.Input.ExpectedVersion, oldVersion)
			if !valid || comparison < 0 || target != "memcached-cache" || !registryDigestValid(oldSHA) || comparison == 0 && oldSHA != row.Seed.Dispatch.Input.ExpectedSHA256 {
				return empty, errors.New("Memcached 原版本回执存在冲突；保留原记录，未覆盖版本")
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return empty, errMemcachedUpdateStore
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO app_registry_receipts(app_id,scope,version,sha256,target,updated_at) VALUES('memcached',?,?,?,'memcached-cache',?) ON CONFLICT(app_id,scope) DO UPDATE SET version=excluded.version,sha256=excluded.sha256,target=excluded.target,updated_at=excluded.updated_at`, row.Seed.Dispatch.ProjectID, row.Seed.Dispatch.Input.ExpectedVersion, row.Seed.Dispatch.Input.ExpectedSHA256, now); err != nil {
			return empty, errMemcachedUpdateStore
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE memcached_update_requests SET chain=?,state=?,updated_at=? WHERE request_id=?`, string(raw), head.Phase, now, requestID); err != nil {
		return empty, errMemcachedUpdateStore
	}
	out, found, err := readMemcachedUpdateReservation(ctx, tx, requestID)
	if err != nil || !found {
		return empty, errMemcachedUpdateStore
	}
	return out, tx.Commit()
}
