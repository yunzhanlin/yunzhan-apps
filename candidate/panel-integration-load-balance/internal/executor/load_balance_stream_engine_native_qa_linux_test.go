//go:build linux

package executor

import (
	"context"
	"os"
	"testing"
	"time"
)

// Read and execute only the actual reviewed native -V probe. This does not
// install/activate Nginx, create a stream listener or prove app acceptance.
func TestLoadBalanceStreamEngineNativeReadOnlyCurrentHost(t *testing.T) {
	if os.Getenv("PANEL_NATIVE_QA") != "1" || os.Getenv("PANEL_LBSTREAM_READONLY_GUARD_NATIVE") != "1" {
		t.Skip("explicit fixed current-host readonly engine component only")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("Root readonly native observer required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	engine, err := holdLoadBalanceStreamEngine(ctx)
	if err != nil {
		t.Fatal("actual reviewed installed native engine/stream modules could not be pinned", err)
	}
	defer engine.close()
	if !engine.current() || !loadBalanceStreamAccountHash(engine.binary.sha) || !loadBalanceStreamAccountHash(engine.manifest.sha) {
		t.Fatal("actual native ELF/manifest changed during probe")
	}
	if other, err := holdLoadBalanceStreamRecordedEngine(ctx, "nginx-system"); err == nil || other != nil {
		t.Fatal("arbitrary system engine or path selector accepted")
	}
}
