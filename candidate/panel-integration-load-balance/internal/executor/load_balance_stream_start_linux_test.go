//go:build linux

package executor

import (
	"context"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamInitialStartOldMissingOrAlreadyIssuedOriginalCannotLaunch(t *testing.T) {
	for _, p := range []*loadBalanceStreamConfigurationPublication{nil, {}, {serviceIssued: true}, {promoted: true}, {syntaxIssued: true, syntaxVerified: true}} {
		if service, err := p.startOwnedInitial(context.Background(), nil); err == nil || service != nil {
			t.Fatal("missing/old original selected a native service launch")
		}
	}
	if p, err := holdLoadBalanceStreamProcess(219, nil); err == nil || p != nil {
		t.Fatal("claimed pid selected process ownership")
	}
	if err := verifyLoadBalanceStreamConfigurationMarkers(context.Background(), nil, nil); err != loadbalancestream.ErrService {
		t.Fatal("claimed marker selected a localhost request", err)
	}
}
