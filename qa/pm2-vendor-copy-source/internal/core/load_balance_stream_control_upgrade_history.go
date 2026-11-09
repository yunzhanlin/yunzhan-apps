package core

import (
	"context"
	"database/sql"
	"encoding/json"

	"local/panel/internal/loadbalancestream"
)

// SELECT-only complete history for the separate Root upgrade/control fence.
// This is neither a list of IDs to skip nor permission to replay/recover.
type LoadBalanceStreamControlUpgradeRecord struct {
	Operation      loadbalancestream.Operation
	AccessRevision int64
	ManifestSHA256 string
	State          string
	ResultState    string
	Completion     LoadBalanceStreamControlCompletion
}

func streamControlRowLiveAuthority(ctx context.Context, db accessReader, row loadBalanceStreamControlRow) (LoadBalanceStreamAuthority, error) {
	var empty LoadBalanceStreamAuthority
	op := row.Operation
	if row.State != "issued" || row.Result != nil || loadbalancestream.OperationSHA256(op) == "" {
		return empty, errLoadBalanceStreamControl
	}
	if _, _, err := streamControlAuthority(ctx, db, op.ActorID, row.AccessRevision, row.ManifestSHA256); err != nil {
		return empty, err
	}
	access, err := readUserAccessContext(ctx, db, op.ActorID)
	if err != nil || access.Revision != row.AccessRevision || !fullAdministrator(access) || len(access.SiteIDs) != 0 || ctx.Err() != nil {
		return empty, errLoadBalanceStreamControl
	}
	raw, err := json.Marshal(struct {
		ActorID string     `json:"actor_id"`
		Access  UserAccess `json:"access"`
	}{op.ActorID, access})
	if err != nil {
		return empty, errLoadBalanceStreamControl
	}
	original, err := streamControlOriginalRequestSHA(ctx, db, row)
	if err != nil {
		return empty, err
	}
	return LoadBalanceStreamAuthority{OriginalRequestSHA256: original, Format: 1, RequestID: op.RequestID, ActorID: op.ActorID,
		OperationSHA256: loadbalancestream.OperationSHA256(op), AppID: "load-balance", AppVersion: loadBalanceStreamControlVersion,
		ManifestSHA256: row.ManifestSHA256, AccessRevision: row.AccessRevision, ActorObservationSHA256: Hash(string(raw))}, nil
}

// The optional live original must equal the COMPLETE current full-admin
// authority in this SAME read transaction. Bare IDs, revoked/reissued grants,
// old completed claims and any other pending/unknown operation refuse. Closed
// history remains visible after actor revocation and still requires separate
// original Root journal/exit/configuration/kernel validation by the caller.
func (s *Store) LoadBalanceStreamControlUpgradeHistory(ctx context.Context, original *LoadBalanceStreamAuthority) ([]LoadBalanceStreamControlUpgradeRecord, error) {
	bad := errLoadBalanceStreamControl
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil {
		return nil, bad
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, bad
	}
	defer tx.Rollback()
	var count int
	if tx.QueryRowContext(ctx, "SELECT count(*)FROM sqlite_master WHERE tbl_name='load_balance_stream_controls'").Scan(&count) != nil {
		return nil, bad
	}
	if count == 0 {
		if original != nil || tx.QueryRowContext(ctx, "SELECT(SELECT count(*)FROM audit_logs WHERE action LIKE 'app.load-balance.stream.%')+(SELECT count(*)FROM app_registry_receipts WHERE app_id='load-balance'AND version=?)", loadBalanceStreamControlVersion).Scan(&count) != nil || count != 0 || tx.Commit() != nil {
			return nil, bad
		}
		return []LoadBalanceStreamControlUpgradeRecord{}, nil
	}
	if streamControlSchema(ctx, tx) != nil {
		return nil, bad
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+loadBalanceStreamControlColumns+" FROM load_balance_stream_controls ORDER BY request_id LIMIT ?", loadBalanceStreamControlLimit+1)
	if err != nil {
		return nil, bad
	}
	var decoded []loadBalanceStreamControlRow
	for rows.Next() {
		row, found, err := scanStreamControl(rows, "")
		if err != nil || !found || len(decoded) >= loadBalanceStreamControlLimit || ctx.Err() != nil {
			rows.Close()
			return nil, bad
		}
		decoded = append(decoded, row)
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return nil, bad
	}
	var out []LoadBalanceStreamControlUpgradeRecord
	allowed, safe, refused := 0, 0, 0
	for _, row := range decoded {
		op := row.Operation
		digest := loadbalancestream.OperationSHA256(op)
		// Missing/duplicated/orphan immutable request audits must not make a
		// deleted/altered control row disappear from replacement admission.
		originalRequest, err := streamControlOriginalRequestSHA(ctx, tx, row)
		if err != nil {
			return nil, bad
		}
		item := LoadBalanceStreamControlUpgradeRecord{Operation: op, AccessRevision: row.AccessRevision, ManifestSHA256: row.ManifestSHA256, State: row.State}
		if original != nil && op.RequestID == original.RequestID {
			live, err := streamControlRowLiveAuthority(ctx, tx, row)
			if err != nil || live != *original {
				return nil, bad
			}
			allowed++
		} else if row.State != "completed" || row.Result == nil {
			return nil, bad
		}
		if row.Result != nil {
			result := row.Result
			item.ResultState = result.State
			if result.State == "committed" {
				item.Completion = LoadBalanceStreamControlCompletion{1, op.RequestID, digest, row.ManifestSHA256, result.SeedSHA256, result.FinalEventSHA256, result.ConfigurationSHA256, result.ServiceObservationSHA, originalRequest}
			} else if result.State == "refused-before-issue" {
				safe++
				if tx.QueryRowContext(ctx, `SELECT count(*)FROM audit_logs WHERE action='app.load-balance.stream.cancel-before-issue'AND target=? AND result=?`, op.RequestID, digest).Scan(&count) != nil || count != 1 {
					return nil, bad
				}
			} else if result.State == "refused-before-effects" {
				refused++
				preflight, err := decodeStreamPreflightRefusal(result.PreflightRefusal, op)
				if err != nil || preflight.ManifestSHA256 != row.ManifestSHA256 || preflight.OriginalRequestSHA256 != originalRequest ||
					tx.QueryRowContext(ctx, `SELECT count(*)FROM audit_logs WHERE action='app.load-balance.stream.refused-before-effects'AND actor=? AND target=? AND result=?`, op.ActorID, op.RequestID, Hash(result.PreflightRefusal)).Scan(&count) != nil || count != 1 {
					return nil, bad
				}
			} else {
				return nil, bad
			}
		}
		out = append(out, item)
	}
	if original != nil && allowed != 1 || original == nil && allowed != 0 ||
		tx.QueryRowContext(ctx, "SELECT count(*)FROM audit_logs WHERE action='app.load-balance.stream.control'").Scan(&count) != nil || count != len(decoded) ||
		tx.QueryRowContext(ctx, "SELECT count(*)FROM audit_logs WHERE action='app.load-balance.stream.cancel-before-issue'").Scan(&count) != nil || count != safe ||
		tx.QueryRowContext(ctx, "SELECT count(*)FROM audit_logs WHERE action='app.load-balance.stream.refused-before-effects'").Scan(&count) != nil || count != refused || ctx.Err() != nil || tx.Commit() != nil {
		return nil, bad
	}
	return out, nil
}
