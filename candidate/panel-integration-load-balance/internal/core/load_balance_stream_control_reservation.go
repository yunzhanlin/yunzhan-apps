package core

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"local/panel/internal/loadbalancestream"
)

type streamControlReservationAudit struct {
	Format          int    `json:"format"`
	OperationSHA256 string `json:"operation_sha256"`
	Nonce           string `json:"nonce"`
}

func streamControlReservationAuditBytes(op loadbalancestream.Operation) ([]byte, error) {
	if loadbalancestream.OperationSHA256(op) == "" {
		return nil, errLoadBalanceStreamControl
	}
	return json.Marshal(streamControlReservationAudit{1, loadbalancestream.OperationSHA256(op), ID()})
}

// The nonce is durable in the existing immutable request audit, not supplied
// by HTTP and not reconstructed from a reused UUID/time. Restoring a DB before
// an old reservation cannot manufacture its original native completion grant.
func streamControlOriginalRequestSHA(ctx context.Context, db accessReader, row loadBalanceStreamControlRow) (string, error) {
	if ctx == nil || ctx.Err() != nil || row.CreatedAt == "" {
		return "", errLoadBalanceStreamControl
	}
	var count, size int
	var actor, raw, created string
	err := db.QueryRowContext(ctx, `SELECT count(*),coalesce(min(actor),''),coalesce(min(substr(CAST(result AS BLOB),1,257)),''),coalesce(min(length(CAST(result AS BLOB))),0),coalesce(min(created_at),'') FROM audit_logs WHERE action='app.load-balance.stream.control' AND target=?`, row.Operation.RequestID).Scan(&count, &actor, &raw, &size, &created)
	if err != nil || count != 1 || actor != row.Operation.ActorID || created != row.CreatedAt || size != len(raw) || size < 1 || size > 256 {
		return "", errLoadBalanceStreamControl
	}
	var v streamControlReservationAudit
	if json.Unmarshal([]byte(raw), &v) != nil || v.Format != 1 || v.OperationSHA256 != loadbalancestream.OperationSHA256(row.Operation) || !ValidID(v.Nonce) || v.Nonce == strings.Repeat("0", 32) {
		return "", errLoadBalanceStreamControl
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(canonical, []byte(raw)) {
		return "", errLoadBalanceStreamControl
	}
	return Hash(raw), nil
}
