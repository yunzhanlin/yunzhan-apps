//go:build linux

package executor

import (
	"context"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func streamUpgradeControlRecordFixture() core.LoadBalanceStreamControlUpgradeRecord {
	return core.LoadBalanceStreamControlUpgradeRecord{
		Operation: loadbalancestream.Operation{Format: 1, Kind: loadbalancestream.OperationKind, RequestID: core.ID(), ActorID: core.ID(),
			Mutation: loadbalancestream.Mutation{Format: 1, Action: "create", Name: "upgrade.lb.invalid", Policy: &loadbalancestream.Policy{
				Protocol: "tcp", Port: 42000, Nodes: []loadbalancestream.Node{{Address: "192.0.2.10:41001", Weight: 1}, {Address: "192.0.2.11:41002", Weight: 3}},
				Method: "round-robin", ConnectMilliseconds: 2000, SessionSeconds: 30, MaxSessions: 64}}},
		State: "completed", ResultState: "committed",
	}
}

func TestLoadBalanceStreamUpgradeClosedControlsRequireCanonicalCompletedOriginals(t *testing.T) {
	committed, refused := streamUpgradeControlRecordFixture(), streamUpgradeControlRecordFixture()
	refused.ResultState = "refused-before-issue"
	closed, err := streamUpgradeClosedControls([]core.LoadBalanceStreamControlUpgradeRecord{committed, refused})
	if err != nil || len(closed) != 1 || !closed[committed.Operation.RequestID] || closed[refused.Operation.RequestID] {
		t.Fatal("only the fully committed original may have native artifacts", closed, err)
	}
	refused.ResultState = "refused-before-effects"
	closed, err = streamUpgradeClosedControls([]core.LoadBalanceStreamControlUpgradeRecord{committed, refused})
	if err != nil || len(closed) != 1 || !closed[committed.Operation.RequestID] || closed[refused.Operation.RequestID] {
		t.Fatal("acknowledged preflight rejection was treated as a native generation", closed, err)
	}
	for _, state := range []string{"reserved", "issued", "running", "unknown", "failed", "", "COMPLETED"} {
		t.Run("state-"+state, func(t *testing.T) {
			row := streamUpgradeControlRecordFixture()
			row.State = state
			if _, err := streamUpgradeClosedControls([]core.LoadBalanceStreamControlUpgradeRecord{row}); err == nil {
				t.Fatal("nonterminal or unknown row was admitted")
			}
		})
	}
	for _, result := range []string{"running", "unknown", "failed", "", "committed-prefix", "refused"} {
		t.Run("result-"+result, func(t *testing.T) {
			row := streamUpgradeControlRecordFixture()
			row.ResultState = result
			if _, err := streamUpgradeClosedControls([]core.LoadBalanceStreamControlUpgradeRecord{row}); err == nil {
				t.Fatal("unknown completion was admitted")
			}
		})
	}
	for _, invalid := range []func(*loadbalancestream.Operation){
		func(op *loadbalancestream.Operation) { op.RequestID = "own" },
		func(op *loadbalancestream.Operation) { op.ActorID = "" },
		func(op *loadbalancestream.Operation) { op.Kind = "other" },
		func(op *loadbalancestream.Operation) { op.Format = 0 },
		func(op *loadbalancestream.Operation) { op.Mutation.Action = "adopt" },
		func(op *loadbalancestream.Operation) { op.Mutation.Policy = nil },
	} {
		row := streamUpgradeControlRecordFixture()
		invalid(&row.Operation)
		if _, err := streamUpgradeClosedControls([]core.LoadBalanceStreamControlUpgradeRecord{row}); err == nil {
			t.Fatal("invalid operation became a closed original")
		}
	}
	if _, err := streamUpgradeClosedControls([]core.LoadBalanceStreamControlUpgradeRecord{committed, committed}); err == nil {
		t.Fatal("duplicate originals were admitted")
	}
	refused.Operation.RequestID = committed.Operation.RequestID
	if _, err := streamUpgradeClosedControls([]core.LoadBalanceStreamControlUpgradeRecord{committed, refused}); err == nil {
		t.Fatal("a refusal duplicated or shadowed the original")
	}
}

func TestLoadBalanceStreamUpgradeClosedControlsKeepCompleteCensusBounds(t *testing.T) {
	if closed, err := streamUpgradeClosedControls(nil); err != nil || len(closed) != 0 {
		t.Fatal("an actually empty canonical census was rejected", err)
	}
	rows := make([]core.LoadBalanceStreamControlUpgradeRecord, 4097)
	for i := range rows {
		rows[i] = streamUpgradeControlRecordFixture()
		if i >= 128 {
			rows[i].ResultState = "refused-before-issue"
		}
	}
	if closed, err := streamUpgradeClosedControls(rows[:4096]); err != nil || len(closed) != 128 {
		t.Fatal("complete bounded census was rejected", len(closed), err)
	}
	if _, err := streamUpgradeClosedControls(rows); err == nil {
		t.Fatal("history was silently truncated")
	}
	rows[128].ResultState = "committed"
	if _, err := streamUpgradeClosedControls(rows[:129]); err == nil {
		t.Fatal("native lineage exceeded the full 128-generation budget")
	}
}

func TestLoadBalanceStreamUpgradeHistoricalReaderCannotBecomeWriteOrSkipAuthority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, store := range []*loadBalanceStreamConfigurationStore{nil, {}, {closed: map[string]bool{core.ID(): true}}} {
		if store.holdCompletedConfiguration(ctx) == nil || store.beforeCurrent(context.Background()) == nil {
			t.Fatal("a historical reader without live grant and leases acquired write authority")
		}
	}
	for _, held := range []*loadBalanceStreamTrafficUpgrade{nil, {}, {history: []byte("[]"), closed: map[string]bool{core.ID(): true}}} {
		if held.current(context.Background()) == nil || held.current(ctx) == nil {
			t.Fatal("fabricated historical state became upgrade authority")
		}
		held.close()
	}
}
