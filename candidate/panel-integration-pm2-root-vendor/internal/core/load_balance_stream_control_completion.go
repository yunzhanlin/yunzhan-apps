package core

import (
	"context"
	"database/sql"

	"local/panel/internal/loadbalancestream"
)

// Historical completed metadata only. This cannot issue/revive a request,
// authorize a current actor, prove a Root journal or report service health.
type LoadBalanceStreamControlCompletion struct {
	Format                   int    `json:"format"`
	RequestID                string `json:"request_id"`
	OperationSHA256          string `json:"operation_sha256"`
	ManifestSHA256           string `json:"manifest_sha256"`
	SeedSHA256               string `json:"seed_sha256"`
	FinalEventSHA256         string `json:"final_event_sha256"`
	ConfigurationSHA256      string `json:"configuration_sha256"`
	ServiceObservationSHA256 string `json:"service_observation_sha256"`
	OriginalRequestSHA256    string `json:"original_request_sha256"`
}

func (s *Store) LoadBalanceStreamControlCompletion(ctx context.Context, op loadbalancestream.Operation) (LoadBalanceStreamControlCompletion, error) {
	var empty LoadBalanceStreamControlCompletion
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil {
		return empty, errLoadBalanceStreamControl
	}
	if _, err := loadbalancestream.OperationBytes(op); err != nil {
		return empty, errLoadBalanceStreamControl
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, errLoadBalanceStreamControl
	}
	defer tx.Rollback()
	if streamControlSchema(ctx, tx) != nil {
		return empty, errLoadBalanceStreamControl
	}
	row, found, err := readStreamControl(ctx, tx, op.RequestID)
	if err != nil || !found || row.State != "completed" || row.Result == nil || row.Result.State != "committed" || loadbalancestream.OperationSHA256(row.Operation) != loadbalancestream.OperationSHA256(op) || !streamControlDigest(row.ManifestSHA256) {
		return empty, errLoadBalanceStreamControl
	}
	result := row.Result
	original, err := streamControlOriginalRequestSHA(ctx, tx, row)
	if err != nil {
		return empty, err
	}
	v := LoadBalanceStreamControlCompletion{1, op.RequestID, result.OperationSHA256, row.ManifestSHA256, result.SeedSHA256, result.FinalEventSHA256, result.ConfigurationSHA256, result.ServiceObservationSHA, original}
	if ctx.Err() != nil || tx.Commit() != nil {
		return empty, errLoadBalanceStreamControl
	}
	return v, nil
}
