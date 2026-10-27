//go:build linux

package executor

import (
	"context"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamConfigurationStoreMissingOriginalCannotInitializeOrRepairHost(t *testing.T) {
	for _, s := range []*loadBalanceStreamConfigurationStore{nil, {}, {first: true}, {installed: &loadBalanceStreamInstalledContext{}}, {source: &loadBalanceStreamCoreAuthority{}}, {lifetime: &memcachedUnixRuntimeLease{}, mutation: &loadBalanceStreamMutationLease{}}} {
		if s.beforeCurrent(context.Background()) != loadbalancestream.ErrRuntime {
			t.Fatal("claimed old store became current original")
		}
		if s.prepareDirectory(context.Background(), nil) == nil {
			t.Fatal("missing original phase initialized a host directory")
		}
		if p, err := s.stage(context.Background(), nil); err == nil || p != nil {
			t.Fatal("missing original creator staged a host configuration")
		}
		s.close()
	}
	if s, err := holdLoadBalanceStreamConfigurationStore(context.Background(), nil, nil, nil, nil, core.LoadBalanceStreamAuthority{}); err == nil || s != nil {
		t.Fatal("missing original bindings selected host paths")
	}
	if streamConfigurationExactDirectories(nil, map[string]bool{}) == nil {
		t.Fatal("missing held root became a complete namespace census")
	}
}
