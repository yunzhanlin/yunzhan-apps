package core

import (
	"bytes"
	"encoding/json"

	"local/panel/internal/loadbalancestream"
)

// New independent traffic-control wire only. Existing executor response and
// native-read budgets are unchanged. Seed/records retain their exact original
// canonical bytes as JSON strings, never normalized RawMessage documents.
const LoadBalanceStreamNativeResultMaxBytes = 2*loadbalancestream.MaxControlSeedBytes + 12*4096 + 16384

type LoadBalanceStreamNativeResult struct {
	Format               int                                `json:"format"`
	RequestID            string                             `json:"request_id"`
	Version              string                             `json:"version"`
	OperationSHA256      string                             `json:"operation_sha256"`
	State                string                             `json:"state"`
	Seed                 string                             `json:"seed,omitempty"`
	Records              []string                           `json:"records,omitempty"`
	Generation           int64                              `json:"generation,omitempty"`
	GenerationSHA256     string                             `json:"generation_sha256,omitempty"`
	ServiceReceiptSHA256 string                             `json:"service_receipt_sha256,omitempty"`
	Preflight            *LoadBalanceStreamPreflightRefusal `json:"preflight,omitempty"`
}

func ValidateLoadBalanceStreamNativeResult(v LoadBalanceStreamNativeResult, op loadbalancestream.Operation) error {
	if v.Format != 1 || v.RequestID != op.RequestID || v.Version != loadbalancestream.AppVersion ||
		v.OperationSHA256 != loadbalancestream.OperationSHA256(op) || v.OperationSHA256 == "" {
		return errLoadBalanceStreamControl
	}
	if v.State == "running" || v.State == "unknown" || v.State == "refused-before-effects" {
		if v.Seed != "" || len(v.Records) != 0 || v.Generation != 0 || v.GenerationSHA256 != "" || v.ServiceReceiptSHA256 != "" {
			return errLoadBalanceStreamControl
		}
		if v.State == "refused-before-effects" {
			if v.Preflight == nil || ValidateLoadBalanceStreamPreflightRefusal(*v.Preflight, op) != nil {
				return errLoadBalanceStreamControl
			}
		} else if v.Preflight != nil {
			return errLoadBalanceStreamControl
		}
		return nil
	}
	if v.State != "committed" || v.Preflight != nil || v.Generation < 1 || v.Generation > 128 || !streamControlDigest(v.GenerationSHA256) ||
		!streamControlDigest(v.ServiceReceiptSHA256) || len(v.Seed) == 0 || len(v.Seed) > loadbalancestream.MaxControlSeedBytes || len(v.Records) != 12 {
		return errLoadBalanceStreamControl
	}
	seed, err := loadbalancestream.DecodeControlSeed([]byte(v.Seed))
	if err != nil || loadbalancestream.OperationSHA256(seed.Operation) != v.OperationSHA256 {
		return errLoadBalanceStreamControl
	}
	records := make([][]byte, len(v.Records))
	for i, record := range v.Records {
		if len(record) == 0 || len(record) > 2048 {
			return errLoadBalanceStreamControl
		}
		records[i] = []byte(record)
	}
	chain, err := loadbalancestream.DecodeControlChain([]byte(v.Seed), records)
	if err != nil || !chain.Complete || chain.OriginalUnknown || chain.Events[len(chain.Events)-1].ServiceObservationSHA != v.ServiceReceiptSHA256 {
		return errLoadBalanceStreamControl
	}
	return nil
}

func DecodeLoadBalanceStreamNativeResult(raw []byte, op loadbalancestream.Operation) (LoadBalanceStreamNativeResult, error) {
	var v LoadBalanceStreamNativeResult
	if len(raw) == 0 || len(raw) > LoadBalanceStreamNativeResultMaxBytes || json.Unmarshal(raw, &v) != nil ||
		ValidateLoadBalanceStreamNativeResult(v, op) != nil {
		return v, errLoadBalanceStreamControl
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(raw, canonical) {
		return LoadBalanceStreamNativeResult{}, errLoadBalanceStreamControl
	}
	return v, nil
}
