package loadbalancestream

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func serviceFacts() ServiceFacts {
	return ServiceFacts{
		Validation: facts(), AvailableMemoryBytes: 4 << 30, HardOpenFiles: RuntimeOpenFiles,
		UnifiedMemoryAvailable: true, IPFilterAvailable: true, AccountUID: 991, AccountGID: 991,
		AccountRecordSHA256: strings.Repeat("a", 64), NginxVersion: "1.30.6", NginxSHA256: strings.Repeat("b", 64),
	}
}

func TestServiceClosedUnitKeepsBothProtocolsAndOriginalProfiles(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		for _, method := range []string{"round-robin", "least-connections", "source-ip"} {
			t.Run(protocol+"/"+method, func(t *testing.T) {
				entry := fixture()
				entry.Protocol, entry.Method = protocol, method
				if protocol == "udp" {
					entry.UDPRequests, entry.UDPResponses = 1, 1
				}
				before := clone(entry)
				context := serviceFacts()
				plan, err := PlanService([]Entry{entry}, nil, context)
				if err != nil || !plan.ShouldRun || !plan.RequiresOriginalKernelWitness || plan.Current.ActiveEntries != 1 || plan.Retiring.ActiveEntries != 0 || !reflect.DeepEqual(entry, before) {
					t.Fatalf("original closed entry changed: %+v %v", plan, err)
				}
				if plan.SHA256 != serviceDigest(plan.Unit) || !bytes.Contains(plan.Unit, []byte("User=panel-lbstream\nGroup=panel-lbstream\n")) {
					t.Fatal("unit identity changed")
				}
				runtime, err := RenderRuntime([]Entry{entry}, ServiceRuntimePrefix, context.Validation)
				if err != nil || !reflect.DeepEqual(runtime, plan.Current) {
					t.Fatal("service bypassed the original complete configuration")
				}
				for _, value := range []string{"Restart=no\n", "CapabilityBoundingSet=\nAmbientCapabilities=\n", "NoNewPrivileges=yes\n", "MemorySwapMax=0\n", "IPAddressDeny=any\n", "TasksMax=32\n", "LimitNOFILE=32768\n", "KillSignal=SIGQUIT\n", "TimeoutStopSec=630s\n", "CPUQuota=100%\n", "ReadWritePaths=" + ServiceRuntimePrefix + "\n", "MemoryDenyWriteExecute=yes\n", "ProtectSystem=strict\n"} {
					if !bytes.Contains(plan.Unit, []byte(value)) {
						t.Fatal("missing isolation", value)
					}
				}
				for _, forbidden := range []string{"[Install]", "Restart=always", "Restart=on-failure", "/bin/sh", "sudo ", "CAP_", "CAP_SYS_ADMIN", "AmbientCapabilities=CAP", "0.0.0.0/0", "::/0", "IPAddressAllow=any", "ExecStartPre=", "ExecStartPost=", "+", "$", "%i"} {
					if bytes.Contains(plan.Unit, []byte(forbidden)) {
						t.Fatal("unit grants unreviewed restart/authority", forbidden)
					}
				}
				expected := []string{"127.0.0.0/8", "192.0.2.10/32", "2001:db8::2/128", "::1/128"}
				if !reflect.DeepEqual(plan.AllowedIPs, expected) {
					t.Fatal("IP policy is not exact backend+loopback set", plan.AllowedIPs)
				}
			})
		}
	}
}

func TestServiceFactsFailClosedWithoutPartialBytes(t *testing.T) {
	changes := map[string]func(*ServiceFacts){
		"missing-cgroup":       func(f *ServiceFacts) { f.UnifiedMemoryAvailable = false },
		"missing-IP-filter":    func(f *ServiceFacts) { f.IPFilterAvailable = false },
		"root-UID":             func(f *ServiceFacts) { f.AccountUID = 0 },
		"root-GID":             func(f *ServiceFacts) { f.AccountGID = 0 },
		"reserved-UID":         func(f *ServiceFacts) { f.AccountUID = 99 },
		"non-system-UID":       func(f *ServiceFacts) { f.AccountUID = 1000 },
		"non-system-GID":       func(f *ServiceFacts) { f.AccountGID = 1000 },
		"reserved-GID":         func(f *ServiceFacts) { f.AccountGID = 99 },
		"UID-upper":            func(f *ServiceFacts) { f.AccountUID = 60000 },
		"GID-upper":            func(f *ServiceFacts) { f.AccountGID = 60000 },
		"account-empty":        func(f *ServiceFacts) { f.AccountRecordSHA256 = "" },
		"account-zero":         func(f *ServiceFacts) { f.AccountRecordSHA256 = strings.Repeat("0", 64) },
		"account-upper":        func(f *ServiceFacts) { f.AccountRecordSHA256 = strings.Repeat("A", 64) },
		"account-nonhex":       func(f *ServiceFacts) { f.AccountRecordSHA256 = strings.Repeat("z", 64) },
		"nginx-empty":          func(f *ServiceFacts) { f.NginxSHA256 = "" },
		"nginx-zero":           func(f *ServiceFacts) { f.NginxSHA256 = strings.Repeat("0", 64) },
		"nginx-upper":          func(f *ServiceFacts) { f.NginxSHA256 = strings.Repeat("B", 64) },
		"nginx-nonhex":         func(f *ServiceFacts) { f.NginxSHA256 = strings.Repeat("x", 64) },
		"unknown-version":      func(f *ServiceFacts) { f.NginxVersion = "1.30.7" },
		"old-version":          func(f *ServiceFacts) { f.NginxVersion = "1.30.4" },
		"traversal-version":    func(f *ServiceFacts) { f.NginxVersion = "../1.30.6" },
		"shell-version":        func(f *ServiceFacts) { f.NginxVersion = "1.30.6;id" },
		"unit-injection":       func(f *ServiceFacts) { f.NginxVersion = "1.30.6\nUser=root" },
		"openfiles-one-below":  func(f *ServiceFacts) { f.HardOpenFiles = RuntimeOpenFiles - 1 },
		"negative-host-memory": func(f *ServiceFacts) { f.AvailableMemoryBytes = -1 },
		"overflow-host-memory": func(f *ServiceFacts) { f.AvailableMemoryBytes = (1 << 60) + 1 },
		"low-host-memory":      func(f *ServiceFacts) { f.AvailableMemoryBytes = ServiceBaseMemory },
		"zero-planner-memory":  func(f *ServiceFacts) { f.Validation.MemoryBudgetBytes = 0 },
		"above-planner-limit":  func(f *ServiceFacts) { f.Validation.MemoryBudgetBytes = MaxMemoryBudget + 1 },
		"occupied-data":        func(f *ServiceFacts) { f.Validation.OccupiedTCPPorts = []int{42000} },
		"occupied-probe":       func(f *ServiceFacts) { f.Validation.OccupiedTCPPorts = []int{43000} },
		"custom-control":       func(f *ServiceFacts) { f.Validation.PanelControlPorts = append(f.Validation.PanelControlPorts, 42000) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			context := serviceFacts()
			change(&context)
			plan, err := PlanService([]Entry{fixture()}, nil, context)
			if err != ErrService || !reflect.DeepEqual(plan, ServicePlan{}) {
				t.Fatal("unproved host fact returned partial plan", plan, err)
			}
		})
	}
	for _, version := range []string{"1.30.6", "1.31.5"} {
		context := serviceFacts()
		context.NginxVersion = version
		plan, err := PlanService([]Entry{fixture()}, nil, context)
		if err != nil || !bytes.Contains(plan.Unit, []byte("/opt/panel/runtimes/nginx/"+version+"/sbin/nginx")) {
			t.Fatal("closed reviewed version rejected", version, err)
		}
	}
	for _, id := range []uint32{100, 999} {
		context := serviceFacts()
		context.AccountUID, context.AccountGID = id, id
		if _, err := PlanService([]Entry{fixture()}, nil, context); err != nil {
			t.Fatal("closed system identity boundary refused", id, err)
		}
	}
}

func TestServiceBothGenerationsShareUnchangedBudgetAndPreserveOldIPs(t *testing.T) {
	current, prior := fixture(), fixture()
	prior.Nodes = []Node{{Address: "198.51.100.9:41001", Weight: 1}, {Address: "[2001:db8::4]:41002", Weight: 3}}
	current.Revision = 2
	context := serviceFacts()
	plan, err := PlanService([]Entry{current}, []Entry{prior}, context)
	expected := 2 * (FixedBytesPerEntry + int64(current.MaxSessions)*BytesPerSession)
	if err != nil || plan.AggregatePlannedBytes != expected || plan.MemoryHighBytes%int64(8<<20) != 0 || plan.MemoryMaxBytes%int64(16<<20) != 0 || plan.MemoryHighBytes > plan.MemoryMaxBytes || plan.RequiredAvailableMemoryBytes != plan.MemoryMaxBytes+ServiceHostReserve {
		t.Fatal("two-generation memory was not charged", plan, err)
	}
	ips := []string{"127.0.0.0/8", "192.0.2.10/32", "198.51.100.9/32", "2001:db8::2/128", "2001:db8::4/128", "::1/128"}
	if !reflect.DeepEqual(plan.AllowedIPs, ips) {
		t.Fatal("draining backend lost from exact network policy", plan.AllowedIPs)
	}
	context.Validation.MemoryBudgetBytes = expected - 1
	if failed, err := PlanService([]Entry{current}, []Entry{prior}, context); err == nil || !reflect.DeepEqual(failed, ServicePlan{}) {
		t.Fatal("aggregate two-generation budget borrowed from another service")
	}
	context.Validation.MemoryBudgetBytes = expected
	if _, err := PlanService([]Entry{current}, []Entry{prior}, context); err != nil {
		t.Fatal("exact original budget rejected", err)
	}
}
func TestServiceHostReserveBoundaryIsIndependentFromPlanner(t *testing.T) {
	context := serviceFacts()
	plan, err := PlanService([]Entry{fixture()}, nil, context)
	if err != nil {
		t.Fatal(err)
	}
	context.AvailableMemoryBytes = plan.RequiredAvailableMemoryBytes
	if _, err := PlanService([]Entry{fixture()}, nil, context); err != nil {
		t.Fatal("exact host reserve rejected", err)
	}
	context.AvailableMemoryBytes--
	if plan, err := PlanService([]Entry{fixture()}, nil, context); err == nil || !reflect.DeepEqual(plan, ServicePlan{}) {
		t.Fatal("host reserve rounded away")
	}
}

func TestServiceGenerationIdentityRoleAndCrossGenerationCycles(t *testing.T) {
	for _, scenario := range []string{"same-endpoint-foreign-name", "data-to-probe", "probe-to-data", "old-probe-backend", "union-cycle"} {
		t.Run(scenario, func(t *testing.T) {
			prior, current := fixture(), fixture()
			current.Revision++
			switch scenario {
			case "same-endpoint-foreign-name":
				current.Name = "new.lb.invalid"
			case "data-to-probe":
				current.Name, current.Port, current.ProbePort = "new.lb.invalid", 44000, prior.Port
			case "probe-to-data":
				current.Name, current.Port, current.ProbePort = "new.lb.invalid", prior.ProbePort, 44000
			case "old-probe-backend":
				current.Port, current.ProbePort = 44000, 45000
				current.Nodes[0].Address = "127.0.0.1:43000"
			case "union-cycle":
				// Each generation is acyclic in isolation; their draining union is not.
				current.Name, current.Port, current.ProbePort = "other.lb.invalid", 44000, 45000
				prior.Nodes[0].Address = "127.0.0.1:44000"
				current.Nodes[0].Address = "127.0.0.1:42000"
			}
			context := serviceFacts()
			if ValidateSet([]Entry{prior}, context.Validation) != nil || ValidateSet([]Entry{current}, context.Validation) != nil {
				t.Fatal("fixture must be valid in each isolated generation")
			}
			if plan, err := PlanService([]Entry{current}, []Entry{prior}, context); err == nil || !reflect.DeepEqual(plan, ServicePlan{}) {
				t.Fatal("unsafe retiring union admitted", scenario)
			}
		})
	}
	// Retaining the actual same identity and role across a normal reload is legal.
	prior, current := fixture(), fixture()
	current.Revision = 2
	if _, err := PlanService([]Entry{current}, []Entry{prior}, serviceFacts()); err != nil {
		t.Fatal("normal exact-identity reload rejected", err)
	}
}

func TestServiceMaximum128PerGenerationDoesNotDoubleTheOriginalGiBBudget(t *testing.T) {
	entries := make([]Entry, MaxEntries)
	for i := range entries {
		entry := fixture()
		entry.Name, entry.Port, entry.ProbePort, entry.MaxSessions = fmt.Sprintf("entry%03d.lb.invalid", i), 20000+i, 40000+i, 16
		entries[i] = entry
	}
	context := serviceFacts()
	context.Validation.MemoryBudgetBytes = MaxMemoryBudget
	one, err := PlanService(entries, nil, context)
	if err != nil || one.Current.ActiveEntries != 128 || len(one.Unit) > MaxServiceUnitBytes || one.MemoryMaxBytes > ServiceBaseMemory+MaxMemoryBudget+MaxMemoryBudget/4 {
		t.Fatal("valid unchanged maximum rejected", err)
	}
	if both, err := PlanService(entries, entries, context); err == nil || !reflect.DeepEqual(both, ServicePlan{}) {
		t.Fatal("two maximum generations exceeded the unchanged1GiB aggregate")
	}
}

func TestServiceTombstonesAndOutputAliasesCannotEnlargeAuthority(t *testing.T) {
	entry := fixture()
	entry.Removed = true
	idle, err := PlanService([]Entry{entry}, nil, serviceFacts())
	if err != nil || idle.ShouldRun || idle.AggregatePlannedBytes != 0 || !reflect.DeepEqual(idle.AllowedIPs, []string{"127.0.0.0/8", "::1/128"}) || bytes.Contains(idle.Current.Main, []byte("listen ")) {
		t.Fatal("tombstone invented a listener or remote network permission", idle, err)
	}
	entry.Removed = false
	first, err := PlanService([]Entry{entry}, nil, serviceFacts())
	if err != nil {
		t.Fatal(err)
	}
	second, err := PlanService([]Entry{entry}, nil, serviceFacts())
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("nondeterministic service plan")
	}
	first.Unit[0] = 'X'
	first.Current.Main[0] = 'Y'
	first.AllowedIPs[0] = "0.0.0.0/0"
	third, err := PlanService([]Entry{entry}, nil, serviceFacts())
	if err != nil || !reflect.DeepEqual(second, third) {
		t.Fatal("mutable returned bytes changed future authority")
	}
}
