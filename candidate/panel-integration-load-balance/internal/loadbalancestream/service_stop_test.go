package loadbalancestream

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func stoppedServiceEntries(t *testing.T, protocol string) ([]Entry, []Entry) {
	t.Helper()
	entry := fixture()
	entry.Protocol = protocol
	if protocol == "udp" {
		entry.UDPRequests, entry.UDPResponses = 1, 1
	}
	before := []Entry{entry}
	transition, err := PlanMutation(before, Mutation{Format: 1, Action: "remove", Name: entry.Name, ExpectedRevision: entry.Revision, ExpectedFingerprint: Fingerprint(entry)}, 0, serviceFacts().Validation)
	if err != nil {
		t.Fatal(err)
	}
	return before, transition.Entries
}

func TestServiceLastRemovalDoesNotRequireAnotherAllocation(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			before, after := stoppedServiceEntries(t, protocol)
			facts := serviceFacts()
			original, err := PlanService(after, before, facts)
			if err != nil || original.ShouldRun || original.Retiring.ActiveEntries != 1 || original.Current.ActiveEntries != 0 {
				t.Fatal("last removal did not produce an original stop policy", err)
			}
			for _, available := range []int64{0, ServiceBaseMemory, original.RequiredAvailableMemoryBytes - 1} {
				facts.AvailableMemoryBytes = available
				got, err := PlanService(after, before, facts)
				if err != nil || !reflect.DeepEqual(got, original) || facts.AvailableMemoryBytes != available {
					t.Fatal("stop re-admitted an allocation or changed the original policy/facts", available, err)
				}
				observed, err := RecordedServicePlan(after, before, facts)
				if err != nil || !reflect.DeepEqual(observed, got) {
					t.Fatal("stop did not preserve the full recorded policy", err)
				}
				launch, err := PlanServiceLaunch(after, before, facts, strings.Repeat("a", 32))
				if err != nil || !reflect.DeepEqual(launch.Service, original) || len(launch.Start) != 0 || len(launch.Policy) != 0 || len(launch.Syntax) == 0 {
					t.Fatal("stop exposed native start/reload arguments or omitted bounded syntax validation", err)
				}
			}
		})
	}
}

func TestServiceStopPreservesEveryNonAllocationBoundary(t *testing.T) {
	before, after := stoppedServiceEntries(t, "tcp")
	changes := map[string]func(*ServiceFacts){
		"negative-memory":    func(f *ServiceFacts) { f.AvailableMemoryBytes = -1 },
		"overflow-memory":    func(f *ServiceFacts) { f.AvailableMemoryBytes = 1<<60 + 1 },
		"unified-controller": func(f *ServiceFacts) { f.UnifiedMemoryAvailable = false },
		"IP-controller":      func(f *ServiceFacts) { f.IPFilterAvailable = false },
		"root-UID":           func(f *ServiceFacts) { f.AccountUID = 0 },
		"root-GID":           func(f *ServiceFacts) { f.AccountGID = 0 },
		"foreign-account":    func(f *ServiceFacts) { f.AccountRecordSHA256 = "" },
		"foreign-engine":     func(f *ServiceFacts) { f.NginxSHA256 = "" },
		"unknown-engine":     func(f *ServiceFacts) { f.NginxVersion = "1.30.7" },
		"descriptor-limit":   func(f *ServiceFacts) { f.HardOpenFiles = RuntimeOpenFiles - 1 },
		"zero-budget":        func(f *ServiceFacts) { f.Validation.MemoryBudgetBytes = 0 },
		"above-budget-limit": func(f *ServiceFacts) { f.Validation.MemoryBudgetBytes = MaxMemoryBudget + 1 },
		"below-live-budget":  func(f *ServiceFacts) { f.Validation.MemoryBudgetBytes = 1 },
		"control-port": func(f *ServiceFacts) {
			f.Validation.PanelControlPorts = append(f.Validation.PanelControlPorts, before[0].Port)
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			facts := serviceFacts()
			facts.AvailableMemoryBytes = 0
			change(&facts)
			plan, err := PlanService(after, before, facts)
			if err != ErrService || !reflect.DeepEqual(plan, ServicePlan{}) {
				t.Fatal("stop relaxed a non-allocation safety boundary", err)
			}
		})
	}
	foreign := append([]Entry(nil), after...)
	foreign[0].Port++
	facts := serviceFacts()
	facts.AvailableMemoryBytes = 0
	if plan, err := PlanService(foreign, before, facts); err != ErrService || !reflect.DeepEqual(plan, ServicePlan{}) {
		t.Fatal("stop adopted a foreign retiring identity", err)
	}
}

func TestServiceLowMemoryStillRefusesNewAndRemainingActiveGenerations(t *testing.T) {
	entry := fixture()
	other := clone(entry)
	other.Name, other.Port, other.ProbePort = "other.lb.invalid", entry.Port+1, entry.ProbePort+1
	before := []Entry{entry, other}
	transition, err := PlanMutation(before, Mutation{Format: 1, Action: "remove", Name: entry.Name, ExpectedRevision: entry.Revision, ExpectedFingerprint: Fingerprint(entry)}, 0, serviceFacts().Validation)
	if err != nil {
		t.Fatal(err)
	}
	for name, generations := range map[string][2][]Entry{
		"initial-empty":   {nil, nil},
		"create":          {{entry}, nil},
		"replace":         {{entry}, {entry}},
		"partial-removal": {transition.Entries, before},
	} {
		t.Run(name, func(t *testing.T) {
			facts := serviceFacts()
			facts.AvailableMemoryBytes = 0
			if plan, err := PlanService(generations[0], generations[1], facts); err != ErrService || !reflect.DeepEqual(plan, ServicePlan{}) {
				t.Fatal("low-memory stop exception admitted another generation", err)
			}
		})
	}
}

func TestServiceLastRemovalExceptionRequiresAnExactSingleMutation(t *testing.T) {
	before, after := stoppedServiceEntries(t, "tcp")
	tombstone := clone(before[0])
	tombstone.Name, tombstone.Port, tombstone.ProbePort, tombstone.Removed = "old.lb.invalid", 44000, 45000, true
	before, after = append(before, tombstone), append(after, tombstone)
	facts := serviceFacts()
	facts.AvailableMemoryBytes = 0
	if _, err := PlanService(after, before, facts); err != nil {
		t.Fatal("unchanged retained tombstone blocked a legitimate low-memory stop", err)
	}
	for name, change := range map[string]func([]Entry, []Entry) ([]Entry, []Entry){
		"dropped-current": func(a, b []Entry) ([]Entry, []Entry) { return a[:1], b },
		"dropped-prior":   func(a, b []Entry) ([]Entry, []Entry) { return a, b[:1] },
		"foreign-name":    func(a, b []Entry) ([]Entry, []Entry) { a[0].Name = "foreign.lb.invalid"; return a, b },
		"foreign-port":    func(a, b []Entry) ([]Entry, []Entry) { a[0].Port++; return a, b },
		"foreign-probe":   func(a, b []Entry) ([]Entry, []Entry) { a[0].ProbePort++; return a, b },
		"foreign-node":    func(a, b []Entry) ([]Entry, []Entry) { a[0].Nodes[0].Weight++; return a, b },
		"foreign-policy":  func(a, b []Entry) ([]Entry, []Entry) { a[0].Method = "least-connections"; return a, b },
		"stale-revision":  func(a, b []Entry) ([]Entry, []Entry) { a[0].Revision--; return a, b },
		"future-revision": func(a, b []Entry) ([]Entry, []Entry) { a[0].Revision++; return a, b },
		"old-rewritten":   func(a, b []Entry) ([]Entry, []Entry) { a[1].Revision++; return a, b },
		"bulk-removal": func(a, b []Entry) ([]Entry, []Entry) {
			b[1].Removed, a[1].Revision = false, b[1].Revision+1
			return a, b
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, b := make([]Entry, len(after)), make([]Entry, len(before))
			for i := range a {
				a[i], b[i] = clone(after[i]), clone(before[i])
			}
			a, b = change(a, b)
			if plan, err := PlanService(a, b, facts); err != ErrService || !reflect.DeepEqual(plan, ServicePlan{}) {
				t.Fatal("allocation exception adopted a foreign/bulk transition", err)
			}
		})
	}
	// Entry ordering is not identity; the full validated set remains canonical.
	after[0], after[1] = after[1], after[0]
	if _, err := PlanService(after, before, facts); err != nil {
		t.Fatal("canonical set ordering became a new allocation requirement", err)
	}
}

func TestControlSeedLastRemovalSurvivesLowMemoryWithoutChangingOriginalBinding(t *testing.T) {
	before, _ := stoppedServiceEntries(t, "tcp")
	op, binding := streamOperationFixture()
	op.Mutation = Mutation{Format: 1, Action: "remove", Name: before[0].Name, ExpectedRevision: before[0].Revision, ExpectedFingerprint: Fingerprint(before[0])}
	facts := serviceFacts()
	runtime, err := RenderRuntime(before, ServiceRuntimePrefix, facts.Validation)
	if err != nil {
		t.Fatal(err)
	}
	binding.OriginalConfigSHA256, binding.OperationSHA256 = runtime.SHA256, OperationSHA256(op)
	seed, plan, err := PrepareControlSeed(op, binding, before, 0, strings.Repeat("6", 64), facts)
	if err != nil {
		t.Fatal(err)
	}
	original, err := ControlSeedBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	facts.AvailableMemoryBytes = 0
	low, lowPlan, err := PrepareControlSeed(op, binding, before, 0, strings.Repeat("6", 64), facts)
	if err != nil || !reflect.DeepEqual(lowPlan, plan) || !reflect.DeepEqual(low, seed) {
		t.Fatal("last-removal seed requires new memory or loses original identities", err)
	}
	raw, err := ControlSeedBytes(low)
	if err != nil || !bytes.Equal(raw, original) {
		t.Fatal("low-memory stop rewrote original seed bytes", err)
	}
	op.Mutation.ExpectedRevision++
	binding.OperationSHA256 = OperationSHA256(op)
	if _, _, err := PrepareControlSeed(op, binding, before, 0, strings.Repeat("6", 64), facts); err == nil {
		t.Fatal("low-memory stop accepted a stale revision")
	}
}
