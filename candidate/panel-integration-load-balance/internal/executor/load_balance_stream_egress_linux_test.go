//go:build linux

package executor

import (
	"context"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamEgressMissingOriginalCannotExecute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, g := range []*loadBalanceStreamHeldEgress{nil, {}, {missing: true}, {unknown: true}, {issued: true}, {retired: true}, {readOnly: true}} {
		for _, parent := range []context.Context{nil, ctx, context.Background()} {
			if g.identityCurrent(parent) || g.current(parent) != loadbalancestream.ErrEgressGuard || g.replaceOriginal(parent, loadbalancestream.EgressGuard{}) != loadbalancestream.ErrEgressGuard {
				t.Fatal("missing or released original selected a native nft command")
			}
			for _, batch := range [][]byte{nil, {}, []byte("flush ruleset\n")} {
				if raw, err := g.command(parent, batch, false); err != loadbalancestream.ErrEgressGuard || raw != nil {
					t.Fatal("unbound data selected a command")
				}
			}
		}
		g.close()
		g.close()
	}
	for _, s := range []*loadBalanceStreamConfigurationStore{nil, {}, {released: true}} {
		if s.holdEgress(context.Background(), loadbalancestream.ServiceFacts{}) != loadbalancestream.ErrEgressGuard {
			t.Fatal("unbound store selected a native nft executable")
		}
	}
	for _, p := range []*loadBalanceStreamConfigurationPublication{nil, {}, {promoted: true}, {syntaxIssued: true, syntaxVerified: true}, {serviceIssued: true}} {
		if p.applyEgressOwned(context.Background(), nil) != loadbalancestream.ErrEgressGuard ||
			p.retireStoppedEgressOwned(context.Background(), nil, nil) != loadbalancestream.ErrEgressGuard ||
			p.serviceEgressCurrent(context.Background()) || p.receiptEgressCurrent(context.Background(), "running") ||
			p.receiptEgressCurrent(context.Background(), "stopped") || p.egressPolicyCurrent(context.Background(), "running") {
			t.Fatal("claim of a previous phase or result selected native egress ownership")
		}
	}
}

func TestLoadBalanceStreamRecordedEgressNeedsCompleteOriginalPolicyBeforeObservation(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled, context.Background()} {
		for _, state := range []string{"", "running", "stopped", "healthy"} {
			for _, uid := range []uint32{0, 991, 1000} {
				held, err := holdLoadBalanceStreamRecordedEgress(ctx, loadbalancestream.ControlSeed{}, state, uid, streamEgressReceipt{})
				if held != nil || err != loadbalancestream.ErrEgressGuard {
					t.Fatal("missing original seed/receipt selected a native observation")
				}
			}
		}
	}
}
