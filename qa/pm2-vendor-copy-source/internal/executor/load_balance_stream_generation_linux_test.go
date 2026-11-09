//go:build linux

package executor

import (
	"context"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamRecordedGenerationOldOpenersAndClaimsHaveNoAuthority(t *testing.T) {
	for _, v := range []*loadBalanceStreamHeldGeneration{nil, {}, {value: loadbalancestream.GenerationRecord{Format: 1, Version: loadbalancestream.AppVersion, Generation: 1}}, {installed: &loadBalanceStreamInstalledContext{}}, {source: &loadBalanceStreamCoreAuthority{}}} {
		if err := v.current(context.Background()); err != loadbalancestream.ErrGeneration {
			t.Fatal("claimed or old generation opener became current metadata", err)
		}
		v.close()
	}
	if loadBalanceStreamCompiledProgrammeInputsSHA256 == "" {
		if v, err := holdLoadBalanceStreamRecordedGeneration(context.Background(), &loadBalanceStreamInstalledContext{}, &loadBalanceStreamCoreAuthority{}); err != loadbalancestream.ErrGeneration || v != nil {
			t.Fatal("unbound prototype selected host generation paths", err)
		}
	}
}
