//go:build linux

package executor

import (
	"context"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamServiceObserverMissingOriginalContextHasNoHostEffects(t *testing.T) {
	if got, err := observeLoadBalanceStreamOwnedListeners(context.Background(), nil, nil); err == nil || got != nil {
		t.Fatal("claimed service selected host listener ownership")
	}
	for _, w := range []*loadBalanceStreamServiceObservation{nil, {}, {Format: 1, MainPID: 219}, {installed: &loadBalanceStreamInstalledContext{}}} {
		if err := w.current(context.Background()); err != loadbalancestream.ErrService {
			t.Fatal("claimed saved process/resource facts became current evidence", err)
		}
		if raw, err := w.bytes(context.Background()); err == nil || raw != nil {
			t.Fatal("unproved observer emitted an observation")
		}
		w.close()
	}
	if w, err := observeLoadBalanceStreamService(context.Background(), nil, loadbalancestream.ServicePlan{}, false); err == nil || w != nil {
		t.Fatal("missing installed authority reached host service observer")
	}
	p := &loadBalanceStreamProcessWitness{pidfd: -1}
	if p.current(nil, 991, 991) {
		t.Fatal("unheld process descriptor became live")
	}
	if raw, err := p.read("status"); err == nil || raw != nil {
		t.Fatal("missing process descriptor read a host path")
	}
	p.close()
}
