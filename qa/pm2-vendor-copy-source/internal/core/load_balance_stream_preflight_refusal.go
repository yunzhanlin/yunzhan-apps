package core

import (
	"bytes"
	"context"
	"encoding/json"

	"local/panel/internal/loadbalancestream"
)

// An acknowledgement from the ONE original executor POST, before a native
// control journal, configuration, account or service mutation was attempted.
// This is deliberately not an observation/recovery receipt: a lost POST reply
// remains unknown, and GET can never use this value to close an old request.
type LoadBalanceStreamPreflightRefusal struct {
	Format                 int    `json:"format"`
	RequestID              string `json:"request_id"`
	Version                string `json:"version"`
	OperationSHA256        string `json:"operation_sha256"`
	ManifestSHA256         string `json:"manifest_sha256"`
	InstalledSHA256        string `json:"installed_sha256"`
	ProgrammeInputsSHA256  string `json:"programme_inputs_sha256"`
	ActorObservationSHA256 string `json:"actor_observation_sha256"`
	OriginalRequestSHA256  string `json:"original_request_sha256"`
	Stage                  string `json:"stage"`
}

func ValidateLoadBalanceStreamPreflightRefusal(v LoadBalanceStreamPreflightRefusal, op loadbalancestream.Operation) error {
	if v.Format != 1 || v.RequestID != op.RequestID || v.Version != loadbalancestream.AppVersion ||
		v.OperationSHA256 == "" || v.OperationSHA256 != loadbalancestream.OperationSHA256(op) ||
		v.Stage != "kernel-preflight" && v.Stage != "control-preflight" {
		return errLoadBalanceStreamControl
	}
	for _, digest := range []string{v.OperationSHA256, v.ManifestSHA256, v.InstalledSHA256, v.ProgrammeInputsSHA256, v.ActorObservationSHA256, v.OriginalRequestSHA256} {
		if !streamControlDigest(digest) {
			return errLoadBalanceStreamControl
		}
	}
	return nil
}

func decodeStreamPreflightRefusal(raw string, op loadbalancestream.Operation) (LoadBalanceStreamPreflightRefusal, error) {
	var v LoadBalanceStreamPreflightRefusal
	if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal([]byte(raw), &v) != nil || ValidateLoadBalanceStreamPreflightRefusal(v, op) != nil {
		return v, errLoadBalanceStreamControl
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal([]byte(raw), canonical) {
		return LoadBalanceStreamPreflightRefusal{}, errLoadBalanceStreamControl
	}
	return v, nil
}

// Private to the original POST worker. Neither HTTP input, the startup
// observer nor a GET reply can reach this CAS. No native state is deleted,
// adopted, retried or called successful by closing this rejected operation.
func (s *Store) finishLoadBalanceStreamPreflightRefusal(ctx context.Context, op loadbalancestream.Operation, native LoadBalanceStreamNativeResult) error {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || native.State != "refused-before-effects" || ValidateLoadBalanceStreamNativeResult(native, op) != nil {
		return errLoadBalanceStreamControl
	}
	preflight, err := json.Marshal(native.Preflight)
	if err != nil {
		return errLoadBalanceStreamControl
	}
	result := loadBalanceStreamControlResult{Format: 1, RequestID: op.RequestID, OperationSHA256: native.OperationSHA256,
		State: "refused-before-effects", PreflightRefusal: string(preflight)}
	if validateStreamControlResult(op, result) != nil {
		return errLoadBalanceStreamControl
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 2048 {
		return errLoadBalanceStreamControl
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row, found, err := readStreamControl(ctx, tx, op.RequestID)
	if err != nil || !found || row.State != "issued" || row.Result != nil ||
		loadbalancestream.OperationSHA256(row.Operation) != native.OperationSHA256 || row.ManifestSHA256 != native.Preflight.ManifestSHA256 {
		return errLoadBalanceStreamControl
	}
	current, err := streamControlRowLiveAuthority(ctx, tx, row)
	if err != nil || current.ActorObservationSHA256 != native.Preflight.ActorObservationSHA256 || current.OriginalRequestSHA256 != native.Preflight.OriginalRequestSHA256 {
		return errLoadBalanceStreamControl
	}
	stamp := Now()
	changed, err := tx.ExecContext(ctx, "UPDATE load_balance_stream_controls SET state='completed',result=?,updated_at=? WHERE request_id=? AND state='issued'", string(raw), stamp, op.RequestID)
	if err != nil {
		return err
	}
	count, err := changed.RowsAffected()
	if err != nil || count != 1 {
		return errLoadBalanceStreamControl
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(actor,action,target,result,created_at)VALUES(?,'app.load-balance.stream.refused-before-effects',?,?,?)", op.ActorID, op.RequestID, Hash(string(preflight)), stamp); err != nil {
		return err
	}
	return tx.Commit()
}
