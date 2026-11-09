package core

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"local/panel/internal/loadbalancestream"
)

// Protocol/SQLite models ONLY: these receipts are not native application,
// account, systemd, traffic, signed-catalogue or commercial acceptance.
func streamNativeControlModelResult(t *testing.T, s *Store, op loadbalancestream.Operation) LoadBalanceStreamNativeResult {
	t.Helper()
	seed, records := streamControlModelChain(t, s, op)
	chain, err := loadbalancestream.DecodeControlChain(seed, records)
	if err != nil {
		t.Fatal(err)
	}
	result := LoadBalanceStreamNativeResult{Format: 1, RequestID: op.RequestID, Version: loadbalancestream.AppVersion,
		OperationSHA256: loadbalancestream.OperationSHA256(op), State: "committed", Seed: string(seed),
		Generation: 1, GenerationSHA256: Hash("protocol-model-not-native-generation"),
		ServiceReceiptSHA256: chain.Events[11].ServiceObservationSHA}
	for _, record := range records {
		result.Records = append(result.Records, string(record))
	}
	if err := ValidateLoadBalanceStreamNativeResult(result, op); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestLoadBalanceStreamNativeWireRequiresExactCompleteOriginalChain(t *testing.T) {
	s, _, op := streamControlFixture(t)
	streamControlReserve(t, s, op)
	model := streamNativeControlModelResult(t, s, op)
	raw, _ := json.Marshal(model)
	if _, err := DecodeLoadBalanceStreamNativeResult(raw, op); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*LoadBalanceStreamNativeResult){
		func(r *LoadBalanceStreamNativeResult) { r.RequestID = ID() },
		func(r *LoadBalanceStreamNativeResult) { r.Version = "1.8.5" },
		func(r *LoadBalanceStreamNativeResult) { r.OperationSHA256 = Hash("other") },
		func(r *LoadBalanceStreamNativeResult) { r.Generation = 0 },
		func(r *LoadBalanceStreamNativeResult) { r.Generation = 129 },
		func(r *LoadBalanceStreamNativeResult) { r.GenerationSHA256 = "" },
		func(r *LoadBalanceStreamNativeResult) { r.ServiceReceiptSHA256 = Hash("other") },
		func(r *LoadBalanceStreamNativeResult) { r.Seed = "" },
		func(r *LoadBalanceStreamNativeResult) { r.Records = r.Records[:11] },
		func(r *LoadBalanceStreamNativeResult) { r.State = "running" },
	} {
		bad := model
		change(&bad)
		raw, _ := json.Marshal(bad)
		if _, err := DecodeLoadBalanceStreamNativeResult(raw, op); err == nil {
			t.Fatal("partial, other identity or claimed state accepted")
		}
	}
}

func TestLoadBalanceStreamControlWorkerOnePOSTThenGETOnlyIncludingLostReply(t *testing.T) {
	for _, mode := range []string{"direct-commit", "running-commit", "lost-POST-reply", "native-unknown", "changed-manifest"} {
		t.Run(mode, func(t *testing.T) {
			s, _, op := streamControlFixture(t)
			streamControlReserve(t, s, op)
			model := streamNativeControlModelResult(t, s, op)
			var mu sync.Mutex
			var calls []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				calls = append(calls, r.Method+" "+r.URL.Path)
				mu.Unlock()
				if r.Method == "POST" {
					if r.URL.Path != "/v1/load-balance-stream/controls" {
						t.Error("generic/native route substituted")
					}
					if mode == "lost-POST-reply" {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							conn.Close()
						}
						return
					}
					if mode == "changed-manifest" {
						_, err := s.DB.Exec("UPDATE app_registry_receipts SET version='1.8.5' WHERE app_id='load-balance'")
						if err != nil {
							t.Error(err)
						}
					}
					if mode == "running-commit" || mode == "native-unknown" {
						json.NewEncoder(w).Encode(LoadBalanceStreamNativeResult{Format: 1, RequestID: op.RequestID, Version: loadbalancestream.AppVersion,
							OperationSHA256: loadbalancestream.OperationSHA256(op), State: "running"})
						return
					}
				}
				if mode == "native-unknown" {
					json.NewEncoder(w).Encode(LoadBalanceStreamNativeResult{Format: 1, RequestID: op.RequestID, Version: loadbalancestream.AppVersion,
						OperationSHA256: loadbalancestream.OperationSHA256(op), State: "unknown"})
					return
				}
				json.NewEncoder(w).Encode(model)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			e := &ExecutorClient{Client: &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}}}}
			runLoadBalanceStreamControl(ctx, s, e, op, true)
			row, found, err := readStreamControl(context.Background(), s.DB, op.RequestID)
			expected := "completed"
			if mode == "native-unknown" || mode == "changed-manifest" {
				expected = "unknown"
			}
			if err != nil || !found || row.State != expected {
				t.Fatal("wrong original outcome", row.State, err)
			}
			mu.Lock()
			observed := append([]string(nil), calls...)
			mu.Unlock()
			if len(observed) < 1 || len(observed) > 2 || observed[0] != "POST /v1/load-balance-stream/controls" {
				t.Fatal("original dispatch count changed", observed)
			}
			if len(observed) == 2 && observed[1] != "GET /v1/load-balance-stream/controls/"+op.RequestID {
				t.Fatal("write replay or substituted observation", observed)
			}
			runLoadBalanceStreamControl(ctx, s, e, op, true)
			runLoadBalanceStreamControl(ctx, s, e, op, false)
			mu.Lock()
			count := len(calls)
			mu.Unlock()
			if count != len(observed) {
				t.Fatal("closed/unknown original was dispatched again")
			}
		})
	}
}
