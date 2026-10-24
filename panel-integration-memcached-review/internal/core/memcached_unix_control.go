package core

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"local/panel/internal/appcatalog"
)

const MaxMemcachedUnixControlBytes = 2048
const memcachedUnixControlLimit = 4096
const memcachedUnixControlTable = "CREATE TABLE IF NOT EXISTS memcached_unix_controls(request_id TEXT PRIMARY KEY NOT NULL,project_id TEXT NOT NULL,actor_id TEXT NOT NULL,operation TEXT NOT NULL,operation_sha256 TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('reserved','unknown','completed')),result TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,CHECK(length(request_id)=32 AND length(project_id)=32 AND length(actor_id)=32 AND length(operation) BETWEEN 1 AND 2048 AND length(operation_sha256)=64 AND length(result)<=4096))"
const memcachedUnixControlIndex = "CREATE UNIQUE INDEX IF NOT EXISTS one_active_memcached_unix_control ON memcached_unix_controls(project_id) WHERE state<>'completed'"

var ErrMemcachedUnixControl = errors.New("Memcached 原启停请求、当前权限或结果不能核对；保留原编号，不自动重发")

type MemcachedUnixControlInput struct {
	Action                string `json:"action"`
	ExpectedRuntimeSHA256 string `json:"expected_runtime_sha256"`
	AcknowledgeCacheLoss  bool   `json:"acknowledge_cache_loss"`
}
type MemcachedUnixControlOperation struct {
	Format    int                       `json:"format"`
	RequestID string                    `json:"request_id"`
	ProjectID string                    `json:"project_id"`
	ActorID   string                    `json:"actor_id"`
	Input     MemcachedUnixControlInput `json:"input"`
}
type MemcachedUnixControlResult struct {
	Format          int    `json:"format"`
	RequestID       string `json:"request_id"`
	ProjectID       string `json:"project_id"`
	OperationSHA256 string `json:"operation_sha256"`
	State           string `json:"state"`
	FinalState      string `json:"final_state,omitempty"`
	RuntimeSHA256   string `json:"runtime_sha256,omitempty"`
	ReviewerID      string `json:"reviewer_id,omitempty"`
	ObservedAt      string `json:"observed_at,omitempty"`
}

func ValidateMemcachedUnixControlOperation(op MemcachedUnixControlOperation) error {
	if op.Format != 1 || !ValidID(op.RequestID) || !ValidID(op.ProjectID) || !ValidID(op.ActorID) || !registryDigestValid(op.Input.ExpectedRuntimeSHA256) {
		return ErrMemcachedUnixControl
	}
	switch op.Input.Action {
	case "start":
		if op.Input.AcknowledgeCacheLoss {
			return ErrMemcachedUnixControl
		}
	case "stop", "restart":
		if !op.Input.AcknowledgeCacheLoss {
			return ErrMemcachedUnixControl
		}
	default:
		return ErrMemcachedUnixControl
	}
	return nil
}
func DecodeMemcachedUnixControlOperation(raw []byte) (MemcachedUnixControlOperation, error) {
	var op MemcachedUnixControlOperation
	if len(raw) == 0 || len(raw) > MaxMemcachedUnixControlBytes || json.Unmarshal(raw, &op) != nil {
		return op, ErrMemcachedUnixControl
	}
	canonical, _ := json.Marshal(op)
	if !bytes.Equal(raw, canonical) || ValidateMemcachedUnixControlOperation(op) != nil {
		return MemcachedUnixControlOperation{}, ErrMemcachedUnixControl
	}
	return op, nil
}
func MemcachedUnixControlSHA(op MemcachedUnixControlOperation) string {
	raw, _ := json.Marshal(op)
	return Hash(string(raw))
}
func ValidateMemcachedUnixControlResult(op MemcachedUnixControlOperation, result MemcachedUnixControlResult) error {
	if ValidateMemcachedUnixControlOperation(op) != nil || result.Format != 1 || result.RequestID != op.RequestID || result.ProjectID != op.ProjectID || result.OperationSHA256 != MemcachedUnixControlSHA(op) {
		return ErrMemcachedUnixControl
	}
	if result.State != "observed" && (result.ReviewerID != "" || result.ObservedAt != "") {
		return ErrMemcachedUnixControl
	}
	switch result.State {
	case "completed":
		want := "running"
		if op.Input.Action == "stop" {
			want = "stopped"
		}
		if result.FinalState != want || !registryDigestValid(result.RuntimeSHA256) {
			return ErrMemcachedUnixControl
		}
	case "refused":
		if result.FinalState != "" || result.RuntimeSHA256 != "" {
			return ErrMemcachedUnixControl
		}
	case "unknown":
		if result.FinalState != "" || result.RuntimeSHA256 != "" {
			return ErrMemcachedUnixControl
		}
	case "observed":
		// A separate administrator observation, NEVER an assertion that the
		// original command succeeded. Its actual current state may differ
		// from the command's target; the unknown original remains immutable.
		stamp, err := time.Parse(time.RFC3339Nano, result.ObservedAt)
		if !ValidID(result.ReviewerID) || err != nil || stamp.Year() < 2026 || stamp.UTC().Format(time.RFC3339Nano) != result.ObservedAt || (result.FinalState != "running" && result.FinalState != "stopped") || !registryDigestValid(result.RuntimeSHA256) {
			return ErrMemcachedUnixControl
		}
	default:
		return ErrMemcachedUnixControl
	}
	return nil
}
func memcachedUnixControlSchema(ctx context.Context, db accessReader) error {
	var count int
	if db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE tbl_name='memcached_unix_controls'").Scan(&count) != nil || count != 3 {
		return ErrMemcachedUnixControl
	}
	for _, object := range []struct{ kind, name, text string }{
		{"table", "memcached_unix_controls", strings.Replace(memcachedUnixControlTable, " IF NOT EXISTS", "", 1)},
		{"index", "sqlite_autoindex_memcached_unix_controls_1", ""},
		{"index", "one_active_memcached_unix_control", strings.Replace(memcachedUnixControlIndex, " IF NOT EXISTS", "", 1)},
	} {
		var kind, table, definition string
		if db.QueryRowContext(ctx, "SELECT count(*),coalesce(min(type),''),coalesce(min(tbl_name),''),coalesce(min(sql),'') FROM sqlite_master WHERE name=?", object.name).Scan(&count, &kind, &table, &definition) != nil || count != 1 || kind != object.kind || table != "memcached_unix_controls" || definition != object.text {
			return ErrMemcachedUnixControl
		}
	}
	return nil
}
func (s *Store) migrateMemcachedUnixControls() error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE tbl_name='memcached_unix_controls'").Scan(&count) != nil {
		return ErrMemcachedUnixControl
	}
	if count == 0 {
		var audits int
		if tx.QueryRow("SELECT count(*) FROM audit_logs WHERE action='app.memcached.unix.control'").Scan(&audits) != nil || audits != 0 {
			return ErrMemcachedUnixControl
		}
		if _, err = tx.Exec(memcachedUnixControlTable); err != nil {
			return err
		}
		if _, err = tx.Exec(memcachedUnixControlIndex); err != nil {
			return err
		}
	}
	if memcachedUnixControlSchema(context.Background(), tx) != nil {
		return ErrMemcachedUnixControl
	}
	return tx.Commit()
}

type memcachedUnixControlRow struct {
	Operation MemcachedUnixControlOperation `json:"operation"`
	State     string                        `json:"state"`
	Result    *MemcachedUnixControlResult   `json:"result,omitempty"`
}

func readMemcachedUnixControl(ctx context.Context, db accessReader, key string) (memcachedUnixControlRow, bool, error) {
	var out memcachedUnixControlRow
	if !ValidID(key) || memcachedUnixControlSchema(ctx, db) != nil {
		return out, false, ErrMemcachedUnixControl
	}
	var id, project, actor, raw, digest, result, created, updated string
	var size, resultSize int
	err := db.QueryRowContext(ctx, "SELECT request_id,project_id,actor_id,substr(CAST(operation AS BLOB),1,2049),length(CAST(operation AS BLOB)),operation_sha256,state,coalesce(substr(CAST(result AS BLOB),1,4097),''),length(CAST(result AS BLOB)),created_at,updated_at FROM memcached_unix_controls WHERE request_id=?", key).Scan(&id, &project, &actor, &raw, &size, &digest, &out.State, &result, &resultSize, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil || size != len(raw) || size > MaxMemcachedUnixControlBytes || resultSize != len(result) || resultSize > 4096 || id != key {
		return out, false, ErrMemcachedUnixControl
	}
	op, err := DecodeMemcachedUnixControlOperation([]byte(raw))
	if err != nil || op.RequestID != id || op.ProjectID != project || op.ActorID != actor || digest != MemcachedUnixControlSHA(op) {
		return out, false, ErrMemcachedUnixControl
	}
	out.Operation = op
	for _, stamp := range []string{created, updated} {
		v, e := time.Parse(time.RFC3339, stamp)
		if e != nil || v.Year() < 2026 || v.UTC().Format(time.RFC3339) != stamp {
			return out, false, ErrMemcachedUnixControl
		}
	}
	if result != "" {
		var value MemcachedUnixControlResult
		if json.Unmarshal([]byte(result), &value) != nil || ValidateMemcachedUnixControlResult(op, value) != nil {
			return out, false, ErrMemcachedUnixControl
		}
		canonical, _ := json.Marshal(value)
		if string(canonical) != result || value.State == "unknown" {
			return out, false, ErrMemcachedUnixControl
		}
		out.Result = &value
	}
	if (out.State == "completed") != (out.Result != nil) || (out.State != "completed" && out.State != "reserved" && out.State != "unknown") {
		return out, false, ErrMemcachedUnixControl
	}
	return out, true, nil
}
func (s *Store) memcachedUnixControlForActor(ctx context.Context, actor, key string) (memcachedUnixControlRow, bool, error) {
	var empty memcachedUnixControlRow
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, false, err
	}
	defer tx.Rollback()
	if memcachedUpdateAuthority(ctx, tx, actor, "") != nil {
		return empty, false, ErrMemcachedUnixControl
	}
	row, found, err := readMemcachedUnixControl(ctx, tx, key)
	if err != nil || found && row.Operation.ActorID != actor {
		return empty, false, ErrMemcachedUnixControl
	}
	return row, found, tx.Commit()
}
func (s *Store) reserveMemcachedUnixControl(ctx context.Context, op MemcachedUnixControlOperation) (memcachedUnixControlRow, bool, error) {
	var empty memcachedUnixControlRow
	if ValidateMemcachedUnixControlOperation(op) != nil {
		return empty, false, ErrMemcachedUnixControl
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, false, err
	}
	defer tx.Rollback()
	if memcachedUpdateAuthority(ctx, tx, op.ActorID, "") != nil {
		return empty, false, ErrMemcachedUnixControl
	}
	prior, found, err := readMemcachedUnixControl(ctx, tx, op.RequestID)
	if err != nil {
		return empty, false, err
	}
	if found {
		if prior.Operation != op {
			return empty, false, ErrMemcachedUnixControl
		}
		return prior, false, tx.Commit()
	}
	var count int
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM memcached_unix_controls").Scan(&count) != nil || count >= memcachedUnixControlLimit {
		return empty, false, ErrMemcachedUnixControl
	}
	// Serialise all host mutations, not only a project's buttons. Original
	// unknown submissions remain fences after role revocation or session loss.
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM memcached_unix_controls WHERE state<>'completed'").Scan(&count) != nil || count != 0 {
		return empty, false, ErrMemcachedUnixControl
	}
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM app_registry_pending WHERE app_id='memcached'").Scan(&count) != nil || count != 0 {
		return empty, false, ErrMemcachedUnixControl
	}
	var version string
	if tx.QueryRowContext(ctx, "SELECT version FROM app_registry_receipts WHERE app_id='memcached' AND scope=? AND target='memcached-cache'", op.ProjectID).Scan(&version) != nil || version != appcatalog.MemcachedUnixVersion {
		return empty, false, ErrMemcachedUnixControl
	}
	raw, _ := json.Marshal(op)
	stamp := Now()
	if _, err = tx.ExecContext(ctx, "INSERT INTO memcached_unix_controls(request_id,project_id,actor_id,operation,operation_sha256,state,created_at,updated_at) VALUES(?,?,?,?,?,'reserved',?,?)", op.RequestID, op.ProjectID, op.ActorID, string(raw), MemcachedUnixControlSHA(op), stamp, stamp); err != nil {
		return empty, false, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'app.memcached.unix.control',?,?,?)", op.ActorID, op.RequestID, MemcachedUnixControlSHA(op), stamp); err != nil {
		return empty, false, err
	}
	return memcachedUnixControlRow{Operation: op, State: "reserved"}, true, tx.Commit()
}

// Read-only original reservation check for the real Root caller. This does
// not authenticate an image/install/signature; Root must do that independently.
func (s *Store) CheckMemcachedUnixControl(ctx context.Context, op MemcachedUnixControlOperation) error {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || ValidateMemcachedUnixControlOperation(op) != nil {
		return ErrMemcachedUnixControl
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if memcachedUpdateAuthority(ctx, tx, op.ActorID, "") != nil {
		return ErrMemcachedUnixControl
	}
	row, found, err := readMemcachedUnixControl(ctx, tx, op.RequestID)
	if err != nil || !found || row.Operation != op || row.State != "reserved" {
		return ErrMemcachedUnixControl
	}
	return tx.Commit()
}
func (s *Store) finishMemcachedUnixControl(ctx context.Context, op MemcachedUnixControlOperation, result *MemcachedUnixControlResult) error {
	if result != nil && result.State == "observed" {
		return ErrMemcachedUnixControl
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row, found, err := readMemcachedUnixControl(ctx, tx, op.RequestID)
	if err != nil || !found || row.Operation != op {
		return ErrMemcachedUnixControl
	}
	if row.State == "completed" {
		if result == nil || row.Result == nil || *row.Result != *result {
			return ErrMemcachedUnixControl
		}
		return tx.Commit()
	}
	state, raw := "unknown", ""
	if result != nil {
		if ValidateMemcachedUnixControlResult(op, *result) != nil || result.State == "unknown" {
			return ErrMemcachedUnixControl
		}
		encoded, _ := json.Marshal(result)
		state, raw = "completed", string(encoded)
	}
	changed, err := tx.ExecContext(ctx, "UPDATE memcached_unix_controls SET state=?,result=?,updated_at=? WHERE request_id=? AND state IN('reserved','unknown')", state, raw, Now(), op.RequestID)
	if err != nil {
		return err
	}
	if n, e := changed.RowsAffected(); e != nil || n != 1 {
		return ErrMemcachedUnixControl
	}
	return tx.Commit()
}
func (s *Store) CheckMemcachedUnixControlUpgrade(ctx context.Context) error {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil {
		return ErrMemcachedUnixControl
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A completely older schema can coexist only before any socket receipt
	// exists. Partial schemas or a missing store after activation are uncertainty.
	var count int
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE tbl_name='memcached_unix_controls'").Scan(&count) != nil {
		return ErrMemcachedUnixControl
	}
	if count == 0 {
		var audits int
		if tx.QueryRowContext(ctx, "SELECT count(*) FROM audit_logs WHERE action='app.memcached.unix.control'").Scan(&audits) != nil || audits != 0 {
			return ErrMemcachedUnixControl
		}
		if tx.QueryRowContext(ctx, "SELECT count(*) FROM app_registry_receipts WHERE app_id='memcached' AND version='1.6.45-compat4'").Scan(&count) != nil || count != 0 {
			return ErrMemcachedUnixControl
		}
		return tx.Commit()
	}
	if memcachedUnixControlSchema(ctx, tx) != nil {
		return ErrMemcachedUnixControl
	}
	rows, err := tx.QueryContext(ctx, "SELECT request_id FROM memcached_unix_controls LIMIT ?", memcachedUnixControlLimit+1)
	if err != nil {
		return ErrMemcachedUnixControl
	}
	var keys []string
	for rows.Next() {
		var key string
		if rows.Scan(&key) != nil {
			rows.Close()
			return ErrMemcachedUnixControl
		}
		keys = append(keys, key)
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil || len(keys) > memcachedUnixControlLimit {
		return ErrMemcachedUnixControl
	}
	for _, key := range keys {
		row, found, err := readMemcachedUnixControl(ctx, tx, key)
		if err != nil || !found || row.State != "completed" || row.Result == nil {
			return ErrMemcachedUnixControl
		}
	}
	if ctx.Err() != nil {
		return ErrMemcachedUnixControl
	}
	return tx.Commit()
}

// A narrower Core census is identity data only. The production Root caller
// must additionally hold the original private run inode and real engine lease.
func (s *Store) CheckMemcachedUnixOtherControls(ctx context.Context, op MemcachedUnixControlOperation) error {
	if s.CheckMemcachedUnixControl(ctx, op) != nil {
		return ErrMemcachedUnixControl
	}
	var count int
	if s.DB.QueryRowContext(ctx, "SELECT count(*) FROM memcached_unix_controls WHERE state<>'completed' AND request_id<>?", op.RequestID).Scan(&count) != nil || count != 0 {
		return ErrMemcachedUnixControl
	}
	if s.CheckMemcachedUnixInstallUpgrade(ctx) != nil || s.CheckMemcachedUpdateUpgrade(ctx) != nil {
		return ErrMemcachedUnixControl
	}
	return s.CheckMemcachedUnixControl(ctx, op)
}
