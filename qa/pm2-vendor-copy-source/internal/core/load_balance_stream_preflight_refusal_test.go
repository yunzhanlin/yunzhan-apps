package core

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"local/panel/internal/loadbalancestream"
)

// Protocol/SQLite models only, not native preflight, systemd, installation,
// traffic, signed release or whole-application acceptance.
func streamPreflightModelResult(t *testing.T, s *Store, op loadbalancestream.Operation) LoadBalanceStreamNativeResult {
	t.Helper()
	grant, err := s.LoadBalanceStreamControlAuthority(context.Background(), op)
	if err != nil {
		t.Fatal(err)
	}
	return LoadBalanceStreamNativeResult{Format: 1, RequestID: op.RequestID, Version: loadbalancestream.AppVersion,
		OperationSHA256: grant.OperationSHA256, State: "refused-before-effects",
		Preflight: &LoadBalanceStreamPreflightRefusal{Format: 1, RequestID: op.RequestID, Version: loadbalancestream.AppVersion,
			OperationSHA256: grant.OperationSHA256, ManifestSHA256: grant.ManifestSHA256,
			InstalledSHA256: Hash("model-installation-not-native"), ProgrammeInputsSHA256: Hash("model-programmes-not-native"),
			ActorObservationSHA256: grant.ActorObservationSHA256, OriginalRequestSHA256: grant.OriginalRequestSHA256, Stage: "kernel-preflight"}}
}

func issueStreamPreflightFixture(t *testing.T, s *Store, op loadbalancestream.Operation) {
	t.Helper()
	streamControlReserve(t, s, op)
	if fresh, err := s.issueLoadBalanceStreamControl(context.Background(), op); err != nil || !fresh {
		t.Fatal("original issue", err)
	}
}

func TestLoadBalanceStreamPreflightRefusalWireHasNoCompletionOrUnboundFields(t *testing.T) {
	s, _, op := streamControlFixture(t)
	issueStreamPreflightFixture(t, s, op)
	model := streamPreflightModelResult(t, s, op)
	raw, _ := json.Marshal(model)
	if _, err := DecodeLoadBalanceStreamNativeResult(raw, op); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*LoadBalanceStreamNativeResult){
		func(v *LoadBalanceStreamNativeResult) { v.Preflight = nil },
		func(v *LoadBalanceStreamNativeResult) { v.Preflight.Format++ },
		func(v *LoadBalanceStreamNativeResult) { v.Preflight.RequestID = ID() },
		func(v *LoadBalanceStreamNativeResult) { v.Preflight.Version = "1.8.5" },
		func(v *LoadBalanceStreamNativeResult) { v.Preflight.OperationSHA256 = Hash("other") },
		func(v *LoadBalanceStreamNativeResult) { v.Preflight.ManifestSHA256 = "" },
		func(v *LoadBalanceStreamNativeResult) { v.Preflight.InstalledSHA256 = strings.Repeat("0", 64) },
		func(v *LoadBalanceStreamNativeResult) { v.Preflight.ProgrammeInputsSHA256 = "invalid" },
		func(v *LoadBalanceStreamNativeResult) { v.Preflight.ActorObservationSHA256 = "" },
		func(v *LoadBalanceStreamNativeResult) { v.Preflight.OriginalRequestSHA256 = "" },
		func(v *LoadBalanceStreamNativeResult) { v.Preflight.Stage = "after-journal" },
		func(v *LoadBalanceStreamNativeResult) { v.Seed = "partial" },
		func(v *LoadBalanceStreamNativeResult) { v.Records = []string{"partial"} },
		func(v *LoadBalanceStreamNativeResult) { v.Generation = 1 },
		func(v *LoadBalanceStreamNativeResult) { v.GenerationSHA256 = Hash("generation") },
		func(v *LoadBalanceStreamNativeResult) { v.ServiceReceiptSHA256 = Hash("service") },
		func(v *LoadBalanceStreamNativeResult) { v.State = "running" },
		func(v *LoadBalanceStreamNativeResult) { v.State = "unknown" },
		func(v *LoadBalanceStreamNativeResult) { v.State = "committed" },
	} {
		v := model
		p := *model.Preflight
		v.Preflight = &p
		change(&v)
		bad, _ := json.Marshal(v)
		if _, err := DecodeLoadBalanceStreamNativeResult(bad, op); err == nil {
			t.Fatal("unbound, partial or claimed completion became a refusal", string(bad))
		}
	}
	for _, bad := range []string{string(raw) + "\n", strings.Replace(string(raw), `"stage":"kernel-preflight"`, `"stage":"control-preflight","stage":"kernel-preflight"`, 1), strings.Replace(string(raw), `"stage":"kernel-preflight"`, `"stage":"kernel-preflight","extra":true`, 1)} {
		if _, err := DecodeLoadBalanceStreamNativeResult([]byte(bad), op); err == nil {
			t.Fatal("noncanonical or ambiguous refusal accepted")
		}
	}
}

func TestLoadBalanceStreamPreflightRefusalOnlyCurrentIssuedOriginalCanClose(t *testing.T) {
	for _, fault := range []string{"unknown", "reserved", "revoked", "manifest", "actor-observation", "original-request", "operation", "missing-receipt"} {
		t.Run(fault, func(t *testing.T) {
			s, actor, op := streamControlFixture(t)
			ctx := context.Background()
			issueStreamPreflightFixture(t, s, op)
			model := streamPreflightModelResult(t, s, op)
			switch fault {
			case "unknown", "reserved":
				if _, err := s.DB.Exec("UPDATE load_balance_stream_controls SET state=?", fault); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				if _, err := s.DB.Exec("UPDATE app_user_roles SET role='viewer'WHERE user_id=?", actor.ID); err != nil {
					t.Fatal(err)
				}
			case "manifest":
				model.Preflight.ManifestSHA256 = Hash("changed")
			case "actor-observation":
				model.Preflight.ActorObservationSHA256 = Hash("changed")
			case "original-request":
				model.Preflight.OriginalRequestSHA256 = Hash("changed")
			case "operation":
				op.RequestID = ID()
			case "missing-receipt":
				model.Preflight = nil
			}
			if s.finishLoadBalanceStreamPreflightRefusal(ctx, op, model) == nil {
				t.Fatal("old/unknown/revoked operation was relabelled closed")
			}
			var count int
			if s.DB.QueryRow("SELECT count(*)FROM audit_logs WHERE action='app.load-balance.stream.refused-before-effects'").Scan(&count) != nil || count != 0 {
				t.Fatal("failed refusal mutated its audit")
			}
		})
	}
}

func TestLoadBalanceStreamPreflightRefusalWorkerOriginalPOSTOnlyNeverGETOrRestart(t *testing.T) {
	for _, mode := range []string{"original", "lost-post", "restart", "stale-binding"} {
		t.Run(mode, func(t *testing.T) {
			s, _, op := streamControlFixture(t)
			streamControlReserve(t, s, op)
			if mode == "restart" {
				if fresh, err := s.issueLoadBalanceStreamControl(context.Background(), op); err != nil || !fresh {
					t.Fatal(err)
				}
			}
			var mu sync.Mutex
			var calls []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				calls = append(calls, r.Method)
				mu.Unlock()
				if mode == "lost-post" && r.Method == "POST" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						conn.Close()
					}
					return
				}
				v := streamPreflightModelResult(t, s, op)
				if mode == "stale-binding" {
					v.Preflight.OriginalRequestSHA256 = Hash("different original")
				}
				json.NewEncoder(w).Encode(v)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			e := &ExecutorClient{Client: &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}}}}
			runLoadBalanceStreamControl(ctx, s, e, op, mode != "restart")
			row, found, err := readStreamControl(ctx, s.DB, op.RequestID)
			want := "unknown"
			if mode == "original" {
				want = "completed"
			}
			if err != nil || !found || row.State != want || want == "completed" && (row.Result == nil || row.Result.State != "refused-before-effects") {
				t.Fatal("wrong refusal outcome", row.State, err)
			}
			mu.Lock()
			observed := strings.Join(calls, ",")
			mu.Unlock()
			wantCalls := "POST"
			if mode == "lost-post" {
				wantCalls = "POST,GET"
			} else if mode == "restart" {
				wantCalls = "GET"
			}
			if observed != wantCalls {
				t.Fatal("write replay/substituted refusal observation", observed)
			}
			runLoadBalanceStreamControl(ctx, s, e, op, true)
			runLoadBalanceStreamControl(ctx, s, e, op, false)
			mu.Lock()
			after := strings.Join(calls, ",")
			mu.Unlock()
			if after != observed {
				t.Fatal("closed or unknown operation was retried")
			}
			if mode == "original" {
				if _, err := s.LoadBalanceStreamControlUpgradeHistory(ctx, nil); err != nil {
					t.Fatal("acknowledged rejection blocked read-only history", err)
				}
				op.RequestID = ID()
				streamControlReserve(t, s, op)
			}
		})
	}
}

func TestLoadBalanceStreamPreflightRefusalHistoryExactAuditAndOriginalBinding(t *testing.T) {
	for _, fault := range []string{"none", "missing", "duplicate", "actor", "digest", "orphan", "original-audit", "manifest"} {
		t.Run(fault, func(t *testing.T) {
			s, actor, op := streamControlFixture(t)
			ctx := context.Background()
			issueStreamPreflightFixture(t, s, op)
			if err := s.finishLoadBalanceStreamPreflightRefusal(ctx, op, streamPreflightModelResult(t, s, op)); err != nil {
				t.Fatal(err)
			}
			var query string
			switch fault {
			case "missing":
				query = "DELETE FROM audit_logs WHERE action='app.load-balance.stream.refused-before-effects'"
			case "duplicate":
				query = "INSERT INTO audit_logs(actor,action,target,result,created_at)SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='app.load-balance.stream.refused-before-effects'"
			case "actor":
				query = "UPDATE audit_logs SET actor='other'WHERE action='app.load-balance.stream.refused-before-effects'"
			case "digest":
				query = "UPDATE audit_logs SET result='other'WHERE action='app.load-balance.stream.refused-before-effects'"
			case "orphan":
				query = "INSERT INTO audit_logs(actor,action,target,result,created_at)SELECT actor,action,'orphan',result,created_at FROM audit_logs WHERE action='app.load-balance.stream.refused-before-effects'"
			case "original-audit":
				query = "DELETE FROM audit_logs WHERE action='app.load-balance.stream.control'"
			case "manifest":
				query = "UPDATE load_balance_stream_controls SET manifest_sha256='" + Hash("different manifest") + "'"
			}
			if query != "" {
				if _, err := s.DB.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.DB.Exec("UPDATE app_user_roles SET role='viewer'WHERE user_id=?", actor.ID); err != nil {
				t.Fatal(err)
			}
			counts := streamControlCounts(t, s)
			history, err := s.LoadBalanceStreamControlUpgradeHistory(ctx, nil)
			if fault != "none" {
				if err == nil {
					t.Fatal("tampered/orphan rejection escaped history census", fault)
				}
			} else if err != nil || len(history) != 1 || history[0].ResultState != "refused-before-effects" || history[0].Completion.Format != 0 || s.CheckLoadBalanceStreamControl(ctx, op) == nil {
				t.Fatal("historical refusal became a completion or live grant", err)
			}
			if counts != streamControlCounts(t, s) {
				t.Fatal("SELECT-only history rewrote rejection")
			}
		})
	}
}
