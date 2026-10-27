//go:build linux

package executor

import (
	"context"
	"testing"
)

func TestLoadBalanceStreamControlGateOldOrFabricatedOpenersNeverAuthorizeEffects(t *testing.T) {
	for _, g := range []*loadBalanceStreamControlGate{nil, {}, {journal: &loadBalanceStreamJournal{}}, {journal: &loadBalanceStreamJournal{creator: true}}, {installed: &loadBalanceStreamInstalledContext{}}, {source: &loadBalanceStreamCoreAuthority{}}} {
		if err := g.current(context.Background()); err != errLoadBalanceStreamInstallationGate {
			t.Fatal("old or fabricated control opener gained authority", err)
		}
		g.close()
	}
	if g, err := bindLoadBalanceStreamControlGate(context.Background(), &loadBalanceStreamJournal{creator: true}, &loadBalanceStreamInstalledContext{}, &loadBalanceStreamCoreAuthority{}); err != errLoadBalanceStreamInstallationGate || g != nil {
		t.Fatal("missing original installed grant/lease reached mutation authority", err)
	}
}
