//go:build linux

package executor

import (
	"context"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamAccountPermitMissingOriginalCreatorHasNoEffects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []context.Context{nil, ctx, context.Background()} {
		if p, err := observeLoadBalanceStreamAccountParent(c, nil); err != errLoadBalanceStreamAccount || p != (loadbalancestream.AccountChildPermit{}) {
			t.Fatal("missing original gate produced a parent permit")
		}
		if p, err := writeLoadBalanceStreamAccountPermit(c, nil); err != errLoadBalanceStreamAccount || p != (loadbalancestream.AccountChildPermit{}) {
			t.Fatal("missing original gate wrote private metadata")
		}
	}
	for _, job := range []string{"", ".", "../job", "root", "0123456789ABCDEF0123456789ABCDEF", "00000000000000000000000000000000/other"} {
		if p, err := readLoadBalanceStreamAccountPermit(job); err != errLoadBalanceStreamAccount || p != nil {
			t.Fatal("invalid original ID reached a filesystem record")
		}
	}
	var held *loadBalanceStreamHeldAccountPermit
	if held.current() {
		t.Fatal("absent held record granted continuity")
	}
	held.close()
}
