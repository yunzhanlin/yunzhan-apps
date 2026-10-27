//go:build linux

package executor

import (
	"context"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamPreflightRefusalRequiresOriginalLiveRootPreparer(t *testing.T) {
	seed, err := loadbalancestream.DecodeControlSeed(streamJournalNativeSeed(t))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{SystemRoot: t.TempDir()})
	for _, c := range []*loadBalanceStreamTrafficController{nil, {}, {effectsStarted: true}, {journal: &loadBalanceStreamJournal{}}, {owner: &loadBalanceStreamControlOwner{}}} {
		result, err := c.refuseBeforeEffects(context.Background(), s, seed.Operation, core.LoadBalanceStreamAuthority{}, "kernel-preflight")
		if result != nil || err == nil {
			t.Fatal("missing original became a no-effects acknowledgement")
		}
		if _, ok := err.(*loadBalanceStreamPreflightRefusalError); ok {
			t.Fatal("unbound/partial/after-effects preparation was called safely refused")
		}
	}
}
