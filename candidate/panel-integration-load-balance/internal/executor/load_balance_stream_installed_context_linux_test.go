//go:build linux

package executor

import (
	"context"
	"testing"
)

func TestLoadBalanceStreamInstalledContextNeverGrantsControlFromAnOpener(t *testing.T) {
	for _, value := range []*loadBalanceStreamInstalledContext{nil, {}, {receipt: loadBalanceStreamInstallationReceipt{Format: 1}}, {module: &modulePrivateDirectory{}}, {installed: &loadBalanceStreamHeldModule{missing: true}}} {
		if err := value.current(context.Background()); err != errLoadBalanceStreamInstallationGate {
			t.Fatal("fabricated or historical opener became current installation authority", err)
		}
		value.close()
	}
	if loadBalanceStreamCompiledProgrammeInputsSHA256 == "" {
		if value, err := holdLoadBalanceStreamInstalledContext(context.Background()); err != errLoadBalanceStreamInstallationGate || value != nil {
			t.Fatal("unbound prototype reached installed host paths", err)
		}
	}
}
