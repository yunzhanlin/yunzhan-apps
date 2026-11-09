package loadbalancestream

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestRuntimeCompletePrivateConfigurationKeepsEveryProtocolProfile(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		for _, method := range []string{"round-robin", "least-connections", "source-ip"} {
			t.Run(protocol+"/"+method, func(t *testing.T) {
				entry := fixture()
				entry.Protocol, entry.Method = protocol, method
				if protocol == "udp" {
					entry.UDPRequests, entry.UDPResponses = 1, 1
				}
				before := clone(entry)
				full, err := RenderRuntime([]Entry{entry}, "/run/panel-load-balance-stream", facts())
				if err != nil || full.ActiveEntries != 1 || len(full.Entries) != 1 || full.PlannedBufferAndZoneBytes != FixedBytesPerEntry+int64(entry.MaxSessions)*BytesPerSession || full.RequiredOpenFiles != 32768 || full.WorkerConnections != 16384 {
					t.Fatalf("complete runtime shape: %+v %v", full, err)
				}
				rendered, err := Render(entry)
				if err != nil || !reflect.DeepEqual(full.Entries[0].Configuration, rendered) || !bytes.Contains(full.Main, rendered.Stream) || !bytes.Contains(full.Main, rendered.HTTP) || !reflect.DeepEqual(entry, before) {
					t.Fatal("runtime changed the closed entry or original exact renderer")
				}
				digest := sha256.Sum256(full.Main)
				if full.SHA256 != hex.EncodeToString(digest[:]) || !bytes.Contains(full.Main, []byte("pid /run/panel-load-balance-stream/nginx.pid;\n")) || bytes.Contains(full.Main, []byte("include ")) || bytes.Contains(full.Main, []byte("user ")) || bytes.Contains(full.Main, []byte("daemon ")) {
					t.Fatal("private runtime identity/path/source is not exact")
				}
			})
		}
	}
}

func TestRuntimeRejectsUnsafePrefixAndEveryCompleteSetConflict(t *testing.T) {
	for _, prefix := range []string{"", "/", "relative", "/run/../tmp", "/run/./panel", "/run//panel", "/run/panel/", "/run/panel cache", "/run/panel;include", "/run/panel\nuser", "/run/panel\r", "/run/panel\x00", "/run/$panel", "/run/$(id)", "/run/panel'", "/run/panel\"", "/run/panel\\name", "/run/中文", "/run/" + strings.Repeat("x", 256), "/run/" + strings.Repeat("a/", 256) + "x"} {
		t.Run(fmt.Sprintf("prefix-%x", []byte(prefix)), func(t *testing.T) {
			got, err := RenderRuntime([]Entry{fixture()}, prefix, facts())
			if err == nil || !reflect.DeepEqual(got, RuntimeConfiguration{}) {
				t.Fatal("unsafe prefix returned a partial or accepted configuration")
			}
		})
	}
	for _, scenario := range []string{"duplicate", "custom-control", "TCP-occupied", "UDP-occupied", "memory", "invalid-tombstone"} {
		t.Run(scenario, func(t *testing.T) {
			entry, context := fixture(), facts()
			set := []Entry{entry}
			switch scenario {
			case "duplicate":
				set = append(set, clone(entry))
			case "custom-control":
				context.PanelControlPorts = append(context.PanelControlPorts, entry.Port)
			case "TCP-occupied":
				context.OccupiedTCPPorts = []int{entry.Port}
			case "UDP-occupied":
				set[0].Protocol, set[0].UDPRequests, set[0].UDPResponses = "udp", 1, 1
				context.OccupiedUDPPorts = []int{entry.Port}
			case "memory":
				context.MemoryBudgetBytes = FixedBytesPerEntry + BytesPerSession*16
			case "invalid-tombstone":
				set[0].Removed, set[0].Revision = true, 0
			}
			got, err := RenderRuntime(set, "/run/panel-load-balance-stream", context)
			if err == nil || !reflect.DeepEqual(got, RuntimeConfiguration{}) {
				t.Fatal("whole-set conflict returned a partial or accepted configuration")
			}
		})
	}
}

func TestRuntimeOrderingTombstonesAndOutputCopiesAreIndependent(t *testing.T) {
	a, b := fixture(), fixture()
	b.Name, b.Port, b.ProbePort = "other.lb.invalid", 42001, 43001
	first, err := RenderRuntime([]Entry{b, a}, "/run/panel-load-balance-stream", facts())
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderRuntime([]Entry{a, b}, "/run/panel-load-balance-stream", facts())
	if err != nil || !reflect.DeepEqual(first, second) || first.Entries[0].Name != a.Name || first.ActiveEntries != 2 {
		t.Fatal("input order changed the complete runtime identity")
	}
	first.Entries[0].Configuration.Stream[0] = 'X'
	first.Main[0] = 'Y'
	third, err := RenderRuntime([]Entry{a, b}, "/run/panel-load-balance-stream", facts())
	if err != nil || !reflect.DeepEqual(second, third) {
		t.Fatal("mutated output aliased original entry or another configuration")
	}
	a.Removed, b.Removed = true, true
	removed, err := RenderRuntime([]Entry{a, b}, "/run/panel-load-balance-stream", facts())
	if err != nil || removed.ActiveEntries != 0 || len(removed.Entries) != 2 || removed.PlannedBufferAndZoneBytes != 0 || bytes.Contains(removed.Main, []byte("listen ")) {
		t.Fatal("retained tombstones reserved listeners or invented buffer use")
	}
	for _, entry := range removed.Entries {
		if len(entry.Configuration.Stream) != 0 || len(entry.Configuration.HTTP) != 0 || entry.Configuration.Fingerprint == "" {
			t.Fatal("removed entry lost identity or retained a business fragment")
		}
	}
}

func TestRuntimeMaximum128RetainsOriginalMemoryAndDescriptorCeilings(t *testing.T) {
	entries := make([]Entry, MaxEntries)
	for i := range entries {
		entry := fixture()
		entry.Name, entry.Port, entry.ProbePort, entry.MaxSessions = fmt.Sprintf("entry%03d.lb.invalid", i), 20000+i, 40000+i, 16
		entries[i] = entry
	}
	context := facts()
	context.MemoryBudgetBytes = MaxMemoryBudget
	full, err := RenderRuntime(entries, "/run/panel-load-balance-stream", context)
	if err != nil || len(full.Entries) != 128 || full.ActiveEntries != 128 || len(full.Main) > MaxRuntimeBytes || full.PlannedBufferAndZoneBytes != int64(128)*(FixedBytesPerEntry+16*BytesPerSession) {
		t.Fatalf("full maximum rejected or changed original resource bounds: %v", err)
	}
	// Worst-case <=1GiB planner admission leaves enough fixed descriptor reserve
	// for both sides of TCP sessions,128 data listeners and128 probe listeners.
	for active := int64(1); active <= MaxEntries; active++ {
		maxSessions := min(active*512, (MaxMemoryBudget-active*FixedBytesPerEntry)/BytesPerSession)
		if maxSessions*2+active*2+128 > RuntimeWorkerConnections || RuntimeWorkerConnections*2 != RuntimeOpenFiles {
			t.Fatal("fixed descriptor budget is insufficient or silently raised")
		}
	}
	entries = append(entries, fixture())
	if _, err := RenderRuntime(entries, "/run/panel-load-balance-stream", context); err == nil {
		t.Fatal("129th entry bypassed the original complete-set guard")
	}
}
