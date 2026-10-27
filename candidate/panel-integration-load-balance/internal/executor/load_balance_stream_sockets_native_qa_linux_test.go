//go:build linux

package executor

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLoadBalanceStreamSocketsNativeCurrentHostReadOnlyMetadataNotPortOwnership(t *testing.T) {
	if os.Getenv("PANEL_NATIVE_QA") != "1" {
		t.Skip("explicit original read-only socket metadata only; not port/service/application acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := observeLoadBalanceStreamHostSockets(ctx)
	if err != nil || !c.current() {
		t.Fatal("actual kernel namespace/table grammar refused", err)
	}
	defer c.close()
	if len(c.sockets) == 0 {
		t.Fatal("original panel acceptance host unexpectedly has no observed sockets")
	}
	c.close()
	if c.current() {
		t.Fatal("closed namespace descriptor remained current")
	}
}
