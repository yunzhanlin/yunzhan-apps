//go:build linux

package executor

import (
	"context"
	"os"
	"testing"
)

// Explicit read-only native component only; no private fixture masquerades as
// actual host NSS configuration. No getent/useradd/account/service call occurs.
func TestLoadBalanceStreamNSSPolicyNativeCurrentHost(t *testing.T) {
	if os.Getenv("PANEL_NATIVE_QA") != "1" {
		t.Skip("explicit current-host read-only native component required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("actual Root-owned configuration observer required")
	}
	c, err := holdLoadBalanceStreamNSSConfiguration(context.Background())
	if err != nil {
		t.Fatal("actual host NSS backend is not in the closed supported policy", err)
	}
	defer c.close()
	if !c.current() {
		t.Fatal("actual opened/named NSS configuration identity changed")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	for _, invalid := range []context.Context{nil, ctx} {
		if held, err := holdLoadBalanceStreamNSSConfiguration(invalid); held != nil || err != errLoadBalanceStreamNSSPolicy {
			t.Fatal("absent/canceled observer context reached configuration state")
		}
	}
	var empty *loadBalanceStreamNSSConfiguration
	if empty.current() {
		t.Fatal("missing descriptor granted stable configuration identity")
	}
	empty.close()
}
