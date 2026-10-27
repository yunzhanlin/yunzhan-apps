package core

import (
	"strings"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamWorkspaceDoesNotConflateRecordedConfigurationWithBusinessHealth(t *testing.T) {
	base := LoadBalanceStreamWorkspace{Format: 1, Version: loadbalancestream.AppVersion,
		State: "unavailable", Detail: "not published", BindAddress: "127.0.0.1", Entries: []loadbalancestream.Entry{}}
	if ValidateLoadBalanceStreamWorkspace(base) != nil {
		t.Fatal("honest unavailable state refused")
	}
	for _, state := range []string{"empty", "busy-or-unknown", "unknown"} {
		v := base
		v.Available, v.State = true, state
		if ValidateLoadBalanceStreamWorkspace(v) != nil {
			t.Fatal("honest incomplete state refused", state)
		}
		v.ConfigurationVerified = true
		if ValidateLoadBalanceStreamWorkspace(v) == nil {
			t.Fatal("empty/unknown state claimed verified configuration")
		}
	}
	for _, change := range []func(*LoadBalanceStreamWorkspace){
		func(v *LoadBalanceStreamWorkspace) { v.BindAddress = "0.0.0.0" },
		func(v *LoadBalanceStreamWorkspace) { v.Version = "1.8.5" },
		func(v *LoadBalanceStreamWorkspace) { v.State = "running" },
		func(v *LoadBalanceStreamWorkspace) { v.State = "healthy" },
		func(v *LoadBalanceStreamWorkspace) { v.ConfigurationVerified = true },
		func(v *LoadBalanceStreamWorkspace) { v.RequestID = ID() },
		func(v *LoadBalanceStreamWorkspace) { v.ConfigurationSHA256 = Hash("claimed") },
		func(v *LoadBalanceStreamWorkspace) { v.RetiringWorkers = 1 },
		func(v *LoadBalanceStreamWorkspace) { v.AvailableMemoryBytes = -1 },
		func(v *LoadBalanceStreamWorkspace) { v.Entries = nil },
	} {
		v := base
		change(&v)
		if ValidateLoadBalanceStreamWorkspace(v) == nil {
			t.Fatal("claimed identity/policy/configuration accepted")
		}
	}
	s, _, op := streamControlFixture(t)
	streamControlReserve(t, s, op)
	seedRaw, _ := streamControlModelChain(t, s, op)
	seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
	if err != nil {
		t.Fatal(err)
	}
	v := base
	v.Available, v.State, v.Detail, v.ConfigurationVerified = true, "running", "owned config selector only, not backend health", true
	v.Generation, v.RequestID, v.ConfigurationSHA256, v.Entries = 1, op.RequestID, seed.AfterRuntimeSHA256, seed.After
	v.MemoryHighBytes, v.MemoryMaxBytes = 160<<20, 176<<20
	if ValidateLoadBalanceStreamWorkspace(v) != nil {
		t.Fatal("actual complete configuration shape rejected")
	}
	for _, change := range []func(*LoadBalanceStreamWorkspace){
		func(v *LoadBalanceStreamWorkspace) { v.RetiringWorkers = 2 },
		func(v *LoadBalanceStreamWorkspace) { v.MemoryMaxBytes = v.MemoryHighBytes - 1 },
		func(v *LoadBalanceStreamWorkspace) { v.ConfigurationSHA256 = strings.Repeat("f", 64) },
		func(v *LoadBalanceStreamWorkspace) { v.State = "stopped" },
		func(v *LoadBalanceStreamWorkspace) { v.State = "empty"; v.ConfigurationVerified = false },
		func(v *LoadBalanceStreamWorkspace) {
			v.State = "unavailable"
			v.Available = false
			v.ConfigurationVerified = false
		},
	} {
		bad := v
		change(&bad)
		if ValidateLoadBalanceStreamWorkspace(bad) == nil {
			t.Fatal("partial or contradictory configuration shape accepted")
		}
	}
}
