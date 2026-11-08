package core

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"local/panel/internal/loadbalancestream"
)

// This separate controller schema is initialized by Store.Open, but no HTTP
// mutation or native effect follows from schema creation. Native availability
// remains false until the complete controller and its live lifecycle pass.
// No older HTTP load-balancer request gains L4 powers.
const loadBalanceStreamControlVersion = loadbalancestream.AppVersion
const loadBalanceStreamControlLimit = 4096
const loadBalanceStreamControlTable = "CREATE TABLE IF NOT EXISTS load_balance_stream_controls(request_id TEXT PRIMARY KEY NOT NULL,actor_id TEXT NOT NULL,access_revision INTEGER NOT NULL CHECK(access_revision>0),operation TEXT NOT NULL,operation_sha256 TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,scope TEXT NOT NULL DEFAULT 'host' CHECK(scope='host'),state TEXT NOT NULL CHECK(state IN ('reserved','issued','unknown','completed')),result TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,CHECK(length(request_id)=32 AND length(actor_id)=32 AND length(operation) BETWEEN 1 AND 17408 AND length(operation_sha256)=64 AND length(manifest_sha256)=64 AND length(result)<=2048))"
const loadBalanceStreamControlIndex = "CREATE UNIQUE INDEX IF NOT EXISTS one_active_load_balance_stream_control ON load_balance_stream_controls(scope) WHERE state<>'completed'"
const loadBalanceStreamControlColumns = "request_id,actor_id,access_revision,substr(CAST(operation AS BLOB),1,17409),length(CAST(operation AS BLOB)),operation_sha256,manifest_sha256,scope,state,coalesce(substr(CAST(result AS BLOB),1,2049),''),length(CAST(result AS BLOB)),created_at,updated_at"

var errLoadBalanceStreamControl = errors.New("TCP/UDP 原始控制请求、独立安装版本、当前权限或持久结果无法核对；保留原编号，不重新派发不确定操作")

type loadBalanceStreamControlResult struct {
	Format                int    `json:"format"`
	RequestID             string `json:"request_id"`
	OperationSHA256       string `json:"operation_sha256"`
	State                 string `json:"state"`
	SeedSHA256            string `json:"seed_sha256,omitempty"`
	FinalEventSHA256      string `json:"final_event_sha256,omitempty"`
	ConfigurationSHA256   string `json:"configuration_sha256,omitempty"`
	ServiceObservationSHA string `json:"service_observation_sha256,omitempty"`
	PreflightRefusal      string `json:"preflight_refusal,omitempty"`
}

type loadBalanceStreamControlRow struct {
	CreatedAt      string                          `json:"created_at"`
	Operation      loadbalancestream.Operation     `json:"operation"`
	AccessRevision int64                           `json:"access_revision"`
	ManifestSHA256 string                          `json:"manifest_sha256"`
	State          string                          `json:"state"`
	Result         *loadBalanceStreamControlResult `json:"result,omitempty"`
}

// Read-only identity data for the fixed Root controller. This is not a native
// capability, signature verification, caller grant or a configurable DB path.
type LoadBalanceStreamAuthority struct {
	OriginalRequestSHA256  string `json:"original_request_sha256"`
	Format                 int    `json:"format"`
	RequestID              string `json:"request_id"`
	ActorID                string `json:"actor_id"`
	OperationSHA256        string `json:"operation_sha256"`
	AppID                  string `json:"app_id"`
	AppVersion             string `json:"app_version"`
	ManifestSHA256         string `json:"manifest_sha256"`
	AccessRevision         int64  `json:"access_revision"`
	ActorObservationSHA256 string `json:"actor_observation_sha256"`
}

func streamControlDigest(v string) bool {
	return registryDigestValid(v) && v != strings.Repeat("0", 64)
}

func streamControlSchema(ctx context.Context, db accessReader) error {
	var count int
	if db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE tbl_name='load_balance_stream_controls'").Scan(&count) != nil || count != 3 {
		return errLoadBalanceStreamControl
	}
	for _, object := range []struct{ kind, name, text string }{
		{"table", "load_balance_stream_controls", strings.Replace(loadBalanceStreamControlTable, " IF NOT EXISTS", "", 1)},
		{"index", "sqlite_autoindex_load_balance_stream_controls_1", ""},
		{"index", "one_active_load_balance_stream_control", strings.Replace(loadBalanceStreamControlIndex, " IF NOT EXISTS", "", 1)},
	} {
		var kind, table, definition string
		if db.QueryRowContext(ctx, "SELECT count(*),coalesce(min(type),''),coalesce(min(tbl_name),''),coalesce(min(sql),'') FROM sqlite_master WHERE name=?", object.name).Scan(&count, &kind, &table, &definition) != nil || count != 1 || kind != object.kind || table != "load_balance_stream_controls" || definition != object.text {
			return errLoadBalanceStreamControl
		}
	}
	return nil
}

func (s *Store) migrateLoadBalanceStreamControls() error {
	if s == nil || s.DB == nil {
		return errLoadBalanceStreamControl
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE tbl_name='load_balance_stream_controls'").Scan(&count) != nil {
		return errLoadBalanceStreamControl
	}
	if count == 0 {
		var prior int
		if tx.QueryRow("SELECT (SELECT count(*) FROM audit_logs WHERE action LIKE 'app.load-balance.stream.%')+(SELECT count(*) FROM app_registry_receipts WHERE app_id='load-balance' AND version=?)", loadBalanceStreamControlVersion).Scan(&prior) != nil || prior != 0 {
			return errLoadBalanceStreamControl
		}
		if _, err = tx.Exec(loadBalanceStreamControlTable); err != nil {
			return err
		}
		if _, err = tx.Exec(loadBalanceStreamControlIndex); err != nil {
			return err
		}
	}
	if streamControlSchema(context.Background(), tx) != nil {
		return errLoadBalanceStreamControl
	}
	return tx.Commit()
}

func streamControlAuthority(ctx context.Context, db accessReader, actor string, revision int64, manifest string) (int64, string, error) {
	if ctx == nil || ctx.Err() != nil || !ValidID(actor) {
		return 0, "", errLoadBalanceStreamControl
	}
	access, err := readUserAccessContext(ctx, db, actor)
	if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 || access.Revision < 1 || revision != 0 && access.Revision != revision {
		return 0, "", errLoadBalanceStreamControl
	}
	var version, digest, target string
	if db.QueryRowContext(ctx, "SELECT version,sha256,target FROM app_registry_receipts WHERE app_id='load-balance' AND scope='load-balance'").Scan(&version, &digest, &target) != nil || version != loadBalanceStreamControlVersion || target != "load-balance" || !streamControlDigest(digest) || manifest != "" && manifest != digest {
		return 0, "", errLoadBalanceStreamControl
	}
	var pending int
	if db.QueryRowContext(ctx, "SELECT count(*) FROM app_registry_pending WHERE app_id='load-balance'").Scan(&pending) != nil || pending != 0 {
		return 0, "", errLoadBalanceStreamControl
	}
	return access.Revision, digest, nil
}

func validateStreamControlResult(op loadbalancestream.Operation, result loadBalanceStreamControlResult) error {
	if result.Format != 1 || result.RequestID != op.RequestID || result.OperationSHA256 != loadbalancestream.OperationSHA256(op) {
		return errLoadBalanceStreamControl
	}
	hashes := []string{result.SeedSHA256, result.FinalEventSHA256, result.ConfigurationSHA256, result.ServiceObservationSHA}
	switch result.State {
	case "committed":
		if result.PreflightRefusal != "" {
			return errLoadBalanceStreamControl
		}
		for _, h := range hashes {
			if !streamControlDigest(h) {
				return errLoadBalanceStreamControl
			}
		}
	case "refused-before-issue", "refused-before-effects":
		for _, h := range hashes {
			if h != "" {
				return errLoadBalanceStreamControl
			}
		}
		if result.State == "refused-before-effects" {
			if _, err := decodeStreamPreflightRefusal(result.PreflightRefusal, op); err != nil {
				return errLoadBalanceStreamControl
			}
		} else if result.PreflightRefusal != "" {
			return errLoadBalanceStreamControl
		}
	default:
		return errLoadBalanceStreamControl
	}
	return nil
}

func readStreamControl(ctx context.Context, db accessReader, key string) (loadBalanceStreamControlRow, bool, error) {
	var out loadBalanceStreamControlRow
	if !ValidID(key) || streamControlSchema(ctx, db) != nil {
		return out, false, errLoadBalanceStreamControl
	}
	return scanStreamControl(db.QueryRowContext(ctx, "SELECT "+loadBalanceStreamControlColumns+" FROM load_balance_stream_controls WHERE request_id=?", key), key)
}

// Shared complete canonical decoder for point reads and a single bounded
// streaming upgrade census. SQL byte limits apply before text enters Go.
func scanStreamControl(source interface{ Scan(...any) error }, key string) (loadBalanceStreamControlRow, bool, error) {
	var out loadBalanceStreamControlRow
	var id, actor, raw, digest, scope, result, created, updated string
	var size, resultSize int
	err := source.Scan(&id, &actor, &out.AccessRevision, &raw, &size, &digest, &out.ManifestSHA256, &scope, &out.State, &result, &resultSize, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil || size != len(raw) || size > loadbalancestream.MaxEntryBytes+1024 || resultSize != len(result) || resultSize > 2048 || !ValidID(id) || key != "" && id != key || scope != "host" || out.AccessRevision < 1 || !streamControlDigest(out.ManifestSHA256) {
		return out, false, errLoadBalanceStreamControl
	}
	op, err := loadbalancestream.DecodeOperation([]byte(raw))
	if err != nil || op.RequestID != id || op.ActorID != actor || digest != loadbalancestream.OperationSHA256(op) {
		return out, false, errLoadBalanceStreamControl
	}
	out.Operation = op
	out.CreatedAt = created
	first, e1 := time.Parse(time.RFC3339, created)
	last, e2 := time.Parse(time.RFC3339, updated)
	if e1 != nil || e2 != nil || first.Year() < 2026 || first.UTC().Format(time.RFC3339) != created || last.UTC().Format(time.RFC3339) != updated || last.Before(first) || last.After(time.Now().Add(time.Second)) {
		return out, false, errLoadBalanceStreamControl
	}
	if result != "" {
		var decoded loadBalanceStreamControlResult
		if json.Unmarshal([]byte(result), &decoded) != nil || validateStreamControlResult(op, decoded) != nil {
			return out, false, errLoadBalanceStreamControl
		}
		canonical, _ := json.Marshal(decoded)
		if !bytes.Equal([]byte(result), canonical) {
			return out, false, errLoadBalanceStreamControl
		}
		out.Result = &decoded
		if decoded.State == "refused-before-effects" {
			preflight, err := decodeStreamPreflightRefusal(decoded.PreflightRefusal, op)
			if err != nil || preflight.ManifestSHA256 != out.ManifestSHA256 {
				return out, false, errLoadBalanceStreamControl
			}
		}
	}
	if (out.State == "completed") != (out.Result != nil) || out.State != "reserved" && out.State != "issued" && out.State != "unknown" && out.State != "completed" {
		return out, false, errLoadBalanceStreamControl
	}
	return out, true, nil
}

func (s *Store) reserveLoadBalanceStreamControl(ctx context.Context, op loadbalancestream.Operation) (loadBalanceStreamControlRow, bool, error) {
	var empty loadBalanceStreamControlRow
	raw, err := loadbalancestream.OperationBytes(op)
	if s == nil || s.DB == nil || err != nil || ctx == nil || ctx.Err() != nil {
		return empty, false, errLoadBalanceStreamControl
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return empty, false, err
	}
	defer tx.Rollback()
	revision, manifest, err := streamControlAuthority(ctx, tx, op.ActorID, 0, "")
	if err != nil {
		return empty, false, err
	}
	prior, found, err := readStreamControl(ctx, tx, op.RequestID)
	if err != nil {
		return empty, false, err
	}
	if found {
		old, _ := loadbalancestream.OperationBytes(prior.Operation)
		if !bytes.Equal(old, raw) || prior.AccessRevision != revision || prior.ManifestSHA256 != manifest {
			return empty, false, errLoadBalanceStreamControl
		}
		if _, err := streamControlOriginalRequestSHA(ctx, tx, prior); err != nil {
			return empty, false, err
		}
		return prior, false, tx.Commit()
	}
	var count, active int
	if tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(state<>'completed'),0) FROM load_balance_stream_controls").Scan(&count, &active) != nil || count >= loadBalanceStreamControlLimit || active != 0 {
		return empty, false, errLoadBalanceStreamControl
	}
	stamp := Now()
	if _, err = tx.ExecContext(ctx, "INSERT INTO load_balance_stream_controls(request_id,actor_id,access_revision,operation,operation_sha256,manifest_sha256,state,created_at,updated_at) VALUES(?,?,?,?,?,?,'reserved',?,?)", op.RequestID, op.ActorID, revision, string(raw), loadbalancestream.OperationSHA256(op), manifest, stamp, stamp); err != nil {
		return empty, false, err
	}
	audit, err := streamControlReservationAuditBytes(op)
	if err != nil {
		return empty, false, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'app.load-balance.stream.control',?,?,?)", op.ActorID, op.RequestID, string(audit), stamp); err != nil {
		return empty, false, err
	}
	return loadBalanceStreamControlRow{CreatedAt: stamp, Operation: op, AccessRevision: revision, ManifestSHA256: manifest, State: "reserved"}, true, tx.Commit()
}

// History remains readable by the original current full administrator even
// after a legitimate grant revision or module update; it grants no dispatch.
func (s *Store) loadBalanceStreamControlForActor(ctx context.Context, actor, key string) (loadBalanceStreamControlRow, bool, error) {
	var empty loadBalanceStreamControlRow
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || !ValidID(actor) {
		return empty, false, errLoadBalanceStreamControl
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, false, err
	}
	defer tx.Rollback()
	access, err := readUserAccessContext(ctx, tx, actor)
	if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 || access.Revision < 1 {
		return empty, false, errLoadBalanceStreamControl
	}
	row, found, err := readStreamControl(ctx, tx, key)
	if err != nil || found && row.Operation.ActorID != actor {
		return empty, false, errLoadBalanceStreamControl
	}
	return row, found, tx.Commit()
}

// Durable issued-before-send CAS. Only true permits the one original dispatch;
// retries read the original row and must never POST to Root again.
func (s *Store) issueLoadBalanceStreamControl(ctx context.Context, op loadbalancestream.Operation) (bool, error) {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || loadbalancestream.OperationSHA256(op) == "" {
		return false, errLoadBalanceStreamControl
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	row, found, err := readStreamControl(ctx, tx, op.RequestID)
	if err != nil || !found || loadbalancestream.OperationSHA256(row.Operation) != loadbalancestream.OperationSHA256(op) {
		return false, errLoadBalanceStreamControl
	}
	if _, _, err = streamControlAuthority(ctx, tx, op.ActorID, row.AccessRevision, row.ManifestSHA256); err != nil {
		return false, err
	}
	if _, err := streamControlOriginalRequestSHA(ctx, tx, row); err != nil {
		return false, err
	}
	if row.State != "reserved" {
		return false, tx.Commit()
	}
	changed, err := tx.ExecContext(ctx, "UPDATE load_balance_stream_controls SET state='issued',updated_at=? WHERE request_id=? AND state='reserved'", Now(), op.RequestID)
	if err != nil {
		return false, err
	}
	n, err := changed.RowsAffected()
	if err != nil || n != 1 {
		return false, errLoadBalanceStreamControl
	}
	return true, tx.Commit()
}

// Independent Root read-only prerequisite. This proves a Core reservation and
// fresh full administrator revision/receipt only, not a native lease or grant.
func (s *Store) CheckLoadBalanceStreamControl(ctx context.Context, op loadbalancestream.Operation) error {
	_, err := s.LoadBalanceStreamControlAuthority(ctx, op)
	return err
}

func (s *Store) LoadBalanceStreamControlAuthority(ctx context.Context, op loadbalancestream.Operation) (LoadBalanceStreamAuthority, error) {
	var empty LoadBalanceStreamAuthority
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || loadbalancestream.OperationSHA256(op) == "" {
		return empty, errLoadBalanceStreamControl
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	row, found, err := readStreamControl(ctx, tx, op.RequestID)
	if err != nil || !found || row.State != "issued" || loadbalancestream.OperationSHA256(row.Operation) != loadbalancestream.OperationSHA256(op) {
		return empty, errLoadBalanceStreamControl
	}
	value, err := streamControlRowLiveAuthority(ctx, tx, row)
	if err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return value, nil
}

func (s *Store) markLoadBalanceStreamControlUnknown(ctx context.Context, op loadbalancestream.Operation) error {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || loadbalancestream.OperationSHA256(op) == "" {
		return errLoadBalanceStreamControl
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row, found, err := readStreamControl(ctx, tx, op.RequestID)
	if err != nil || !found || loadbalancestream.OperationSHA256(row.Operation) != loadbalancestream.OperationSHA256(op) || row.State != "issued" && row.State != "unknown" {
		return errLoadBalanceStreamControl
	}
	if row.State == "unknown" {
		return tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, "UPDATE load_balance_stream_controls SET state='unknown',updated_at=? WHERE request_id=? AND state='issued'", Now(), op.RequestID); err != nil {
		return err
	}
	return tx.Commit()
}

// An explicit original-owner cancellation may close ONLY reserved-before-send
// work. Issued/unknown work is never canceled, replayed or relabelled. Since
// Root requires the durable issued state, the CAS makes this race fail closed.
func (s *Store) cancelUndispatchedLoadBalanceStreamControl(ctx context.Context, actor, key string) (bool, error) {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || !ValidID(actor) || !ValidID(key) {
		return false, errLoadBalanceStreamControl
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	access, err := readUserAccessContext(ctx, tx, actor)
	if err != nil || !fullAdministrator(access) || len(access.SiteIDs) != 0 || access.Revision < 1 {
		return false, errLoadBalanceStreamControl
	}
	row, found, err := readStreamControl(ctx, tx, key)
	if err != nil || !found || row.Operation.ActorID != actor {
		return false, errLoadBalanceStreamControl
	}
	if row.State == "completed" && row.Result != nil && row.Result.State == "refused-before-issue" {
		return false, tx.Commit()
	}
	if row.State != "reserved" {
		return false, errLoadBalanceStreamControl
	}
	result := loadBalanceStreamControlResult{Format: 1, RequestID: key, OperationSHA256: loadbalancestream.OperationSHA256(row.Operation), State: "refused-before-issue"}
	if validateStreamControlResult(row.Operation, result) != nil {
		return false, errLoadBalanceStreamControl
	}
	raw, _ := json.Marshal(result)
	stamp := Now()
	changed, err := tx.ExecContext(ctx, "UPDATE load_balance_stream_controls SET state='completed',result=?,updated_at=? WHERE request_id=? AND state='reserved'", string(raw), stamp, key)
	if err != nil {
		return false, err
	}
	count, err := changed.RowsAffected()
	if err != nil || count != 1 {
		return false, errLoadBalanceStreamControl
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at)VALUES(?,'app.load-balance.stream.cancel-before-issue',?,?,?)", actor, key, result.OperationSHA256, stamp); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// The fixed trusted native observer, not HTTP input, must independently verify
// the original Root files/kernel witnesses before supplying this exact chain.
// An unknown dispatch never changes into success through this method.
func (s *Store) finishLoadBalanceStreamControl(ctx context.Context, op loadbalancestream.Operation, seedRaw []byte, records [][]byte) error {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || loadbalancestream.OperationSHA256(op) == "" {
		return errLoadBalanceStreamControl
	}
	seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
	if err != nil || loadbalancestream.OperationSHA256(seed.Operation) != loadbalancestream.OperationSHA256(op) || seed.Binding.AppVersion != loadBalanceStreamControlVersion {
		return errLoadBalanceStreamControl
	}
	chain, err := loadbalancestream.DecodeControlChain(seedRaw, records)
	if err != nil || !chain.Complete || chain.OriginalUnknown {
		return errLoadBalanceStreamControl
	}
	last := chain.Events[len(chain.Events)-1]
	result := loadBalanceStreamControlResult{Format: 1, RequestID: op.RequestID, OperationSHA256: loadbalancestream.OperationSHA256(op), State: "committed",
		SeedSHA256: Hash(string(seedRaw)), FinalEventSHA256: Hash(string(records[len(records)-1])), ConfigurationSHA256: last.ConfigurationSHA256, ServiceObservationSHA: last.ServiceObservationSHA}
	if validateStreamControlResult(op, result) != nil {
		return errLoadBalanceStreamControl
	}
	raw, _ := json.Marshal(result)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row, found, err := readStreamControl(ctx, tx, op.RequestID)
	if err != nil || !found || loadbalancestream.OperationSHA256(row.Operation) != loadbalancestream.OperationSHA256(op) || row.ManifestSHA256 != seed.Binding.ManifestSHA256 {
		return errLoadBalanceStreamControl
	}
	if row.State == "completed" {
		if row.Result == nil || *row.Result != result {
			return errLoadBalanceStreamControl
		}
		return tx.Commit()
	}
	if row.State != "issued" {
		return errLoadBalanceStreamControl
	}
	current, err := streamControlRowLiveAuthority(ctx, tx, row)
	if err != nil || current.ActorObservationSHA256 != seed.Binding.ActorObservationSHA || current.OriginalRequestSHA256 != seed.Binding.OriginalRequestSHA256 {
		return errLoadBalanceStreamControl
	}
	changed, err := tx.ExecContext(ctx, "UPDATE load_balance_stream_controls SET state='completed',result=?,updated_at=? WHERE request_id=? AND state='issued'", string(raw), Now(), op.RequestID)
	if err != nil {
		return err
	}
	n, err := changed.RowsAffected()
	if err != nil || n != 1 {
		return errLoadBalanceStreamControl
	}
	return tx.Commit()
}

// A revoked actor or lost session never removes pending work from upgrade
// admission. Missing/partial stores after activation are uncertainty, not empty.
func (s *Store) CheckLoadBalanceStreamControlUpgrade(ctx context.Context) error {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil {
		return errLoadBalanceStreamControl
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if tx.QueryRowContext(ctx, "SELECT count(*)FROM sqlite_master WHERE tbl_name='load_balance_stream_controls'").Scan(&count) != nil {
		return errLoadBalanceStreamControl
	}
	if count == 0 {
		if tx.QueryRowContext(ctx, "SELECT(SELECT count(*)FROM audit_logs WHERE action LIKE 'app.load-balance.stream.%')+(SELECT count(*)FROM app_registry_receipts WHERE app_id='load-balance'AND version=?)", loadBalanceStreamControlVersion).Scan(&count) != nil || count != 0 {
			return errLoadBalanceStreamControl
		}
		return tx.Commit()
	}
	if streamControlSchema(ctx, tx) != nil {
		return errLoadBalanceStreamControl
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+loadBalanceStreamControlColumns+" FROM load_balance_stream_controls ORDER BY request_id LIMIT ?", loadBalanceStreamControlLimit+1)
	if err != nil {
		return errLoadBalanceStreamControl
	}
	count = 0
	for rows.Next() {
		count++
		if count > loadBalanceStreamControlLimit || ctx.Err() != nil {
			rows.Close()
			return errLoadBalanceStreamControl
		}
		row, found, e := scanStreamControl(rows, "")
		if e != nil || !found || row.State != "completed" || row.Result == nil {
			rows.Close()
			return errLoadBalanceStreamControl
		}
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return errLoadBalanceStreamControl
	}
	if ctx.Err() != nil {
		return errLoadBalanceStreamControl
	}
	return tx.Commit()
}
