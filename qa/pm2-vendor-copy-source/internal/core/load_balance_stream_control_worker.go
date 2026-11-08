package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"local/panel/internal/loadbalancestream"
)

// Only a true issued-before-send CAS can dispatch ONE POST. A retry/restart
// observes the original request with GET; no generic application route, forced
// completion, repeated signal or new request identifier is substituted.
func runLoadBalanceStreamControl(ctx context.Context, s *Store, e *ExecutorClient, op loadbalancestream.Operation, originalDispatch bool) {
	if ctx == nil || ctx.Err() != nil || s == nil || s.DB == nil || e == nil || e.Client == nil {
		return
	}
	if originalDispatch {
		fresh, err := s.issueLoadBalanceStreamControl(ctx, op)
		if err != nil || !fresh {
			return
		}
		var raw json.RawMessage
		err = e.Call(ctx, http.MethodPost, "/v1/load-balance-stream/controls", op, &raw)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			if result, decodeErr := DecodeLoadBalanceStreamNativeResult(raw, op); decodeErr == nil {
				if result.State == "committed" {
					finishLoadBalanceStreamNativeResult(ctx, s, op, result)
					return
				}
				if result.State == "refused-before-effects" {
					if s.finishLoadBalanceStreamPreflightRefusal(ctx, op, result) != nil {
						_ = s.markLoadBalanceStreamControlUnknown(ctx, op)
					}
					return
				}
				if result.State == "unknown" {
					_ = s.markLoadBalanceStreamControlUnknown(ctx, op)
					return
				}
			} else {
				_ = s.markLoadBalanceStreamControlUnknown(ctx, op)
				return
			}
		}
		// A lost original POST reply is GET-only uncertainty, not permission
		// to call POST again. The Root creator may still be running.
	}
	for ctx.Err() == nil {
		row, found, err := readStreamControl(ctx, s.DB, op.RequestID)
		if err != nil || !found || loadbalancestream.OperationSHA256(row.Operation) != loadbalancestream.OperationSHA256(op) || row.State != "issued" {
			return
		}
		if _, err := s.LoadBalanceStreamControlAuthority(ctx, op); err != nil {
			_ = s.markLoadBalanceStreamControlUnknown(ctx, op)
			return
		}
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		var raw json.RawMessage
		err = e.Call(bounded, http.MethodGet, "/v1/load-balance-stream/controls/"+op.RequestID, nil, &raw)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			result, decodeErr := DecodeLoadBalanceStreamNativeResult(raw, op)
			if decodeErr != nil || result.State == "unknown" || result.State == "refused-before-effects" {
				_ = s.markLoadBalanceStreamControlUnknown(ctx, op)
				return
			}
			if result.State == "committed" {
				finishLoadBalanceStreamNativeResult(ctx, s, op, result)
				return
			}
		} else if len(raw) != 0 {
			// A real error response is not an observation timeout or a reason
			// to restart. Preserve the original unknown result immediately.
			_ = s.markLoadBalanceStreamControlUnknown(ctx, op)
			return
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func finishLoadBalanceStreamNativeResult(ctx context.Context, s *Store, op loadbalancestream.Operation, result LoadBalanceStreamNativeResult) error {
	if ctx == nil || ctx.Err() != nil || s == nil || ValidateLoadBalanceStreamNativeResult(result, op) != nil || result.State != "committed" {
		return errLoadBalanceStreamControl
	}
	records := make([][]byte, len(result.Records))
	for i, record := range result.Records {
		records[i] = []byte(record)
	}
	err := s.finishLoadBalanceStreamControl(ctx, op, []byte(result.Seed), records)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		_ = s.markLoadBalanceStreamControlUnknown(ctx, op)
	}
	return err
}

// Snapshot interrupted ISSUED requests before new work starts. Only GET is
// permitted; reserved/unknown/completed rows are never auto-issued or erased.
func startLoadBalanceStreamControlObserver(ctx context.Context, s *Store, e *ExecutorClient) {
	if ctx == nil || ctx.Err() != nil || s == nil || s.DB == nil || e == nil || e.Client == nil {
		return
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT request_id FROM load_balance_stream_controls WHERE state='issued' ORDER BY created_at,request_id LIMIT ?", loadBalanceStreamControlLimit+1)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || !ValidID(id) || len(ids) >= loadBalanceStreamControlLimit {
			rows.Close()
			return
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return
	}
	for _, id := range ids {
		row, found, err := readStreamControl(ctx, s.DB, id)
		if err != nil || !found || row.State != "issued" {
			return
		}
		op := row.Operation
		go runLoadBalanceStreamControl(ctx, s, e, op, false)
	}
}
