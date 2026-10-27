package executor

import (
	"encoding/json"
	"strings"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func streamServiceReceiptFixture(t *testing.T, state string) ([]byte, []byte, streamServiceReceipt) {
	t.Helper()
	facts := loadbalancestream.ServiceFacts{Validation: loadbalancestream.ValidationContext{
		PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget},
		AvailableMemoryBytes: 4 << 30, HardOpenFiles: loadbalancestream.RuntimeOpenFiles,
		UnifiedMemoryAvailable: true, IPFilterAvailable: true, AccountUID: 991, AccountGID: 992,
		AccountRecordSHA256: strings.Repeat("a", 64), NginxVersion: "1.30.6", NginxSHA256: strings.Repeat("b", 64)}
	op := loadbalancestream.Operation{Format: 1, Kind: loadbalancestream.OperationKind, RequestID: core.ID(), ActorID: core.ID(),
		Mutation: loadbalancestream.Mutation{Format: 1, Action: "create", Name: "db.lb.invalid", Policy: &loadbalancestream.Policy{
			Protocol: "tcp", Port: 42000, Nodes: []loadbalancestream.Node{{Address: "192.0.2.10:41001", Weight: 1}, {Address: "192.0.2.11:41002", Weight: 3}},
			Method: "round-robin", ConnectMilliseconds: 2000, SessionSeconds: 30, MaxSessions: 64}}}
	before := []loadbalancestream.Entry{}
	probe := 43000
	if state == "stopped" {
		before = append(before, loadbalancestream.Entry{Format: 1, Revision: 1, Name: op.Mutation.Name, Protocol: "tcp",
			Port: 42000, ProbePort: 43000, Nodes: op.Mutation.Policy.Nodes, Method: "round-robin",
			ConnectMilliseconds: 2000, SessionSeconds: 30, MaxSessions: 64})
		op.Mutation.Action, op.Mutation.ExpectedRevision, op.Mutation.ExpectedFingerprint, op.Mutation.Policy = "remove", 1, loadbalancestream.Fingerprint(before[0]), nil
		probe = 0
	}
	runtime, err := loadbalancestream.RenderRuntime(before, loadbalancestream.ServiceRuntimePrefix, facts.Validation)
	if err != nil {
		t.Fatal(err)
	}
	binding := loadbalancestream.OperationBinding{Format: 1, AppID: "load-balance", AppVersion: loadbalancestream.AppVersion,
		OperationSHA256: loadbalancestream.OperationSHA256(op), ManifestSHA256: strings.Repeat("1", 64), InstalledSHA256: strings.Repeat("2", 64),
		ProgrammeInputs: strings.Repeat("3", 64), ActorObservationSHA: strings.Repeat("4", 64), OriginalConfigSHA256: runtime.SHA256}
	binding.OriginalRequestSHA256 = strings.Repeat("9", 64)
	seed, plan, err := loadbalancestream.PrepareControlSeed(op, binding, before, probe, strings.Repeat("6", 64), facts)
	if err != nil {
		t.Fatal(err)
	}
	seedRaw, err := loadbalancestream.ControlSeedBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	processes := []streamServiceReceiptProcess{{219, 1, 100}, {222, 219, 101}}
	invocation := strings.Repeat("e", 32)
	r := streamServiceReceipt{Format: 1, Version: loadbalancestream.AppVersion, RequestID: op.RequestID, InstallationID: core.ID(),
		SeedSHA256: core.Hash(string(seedRaw)), ConfigurationSHA256: seed.AfterRuntimeSHA256, ServiceUnitSHA256: plan.SHA256, State: state}
	if state == "running" {
		r.CurrentWorker = processes[1]
		n := streamServiceRecordedRunning{Format: 1, InvocationID: invocation, MainPID: 219, AccountUID: 991, AccountGID: 992,
			EngineSHA256: facts.NginxSHA256, UnitSHA256: plan.SHA256, MemoryHigh: plan.MemoryHighBytes, MemoryMax: plan.MemoryMaxBytes,
			IngressPrograms: []uint32{71}, EgressPrograms: []uint32{72}, Processes: processes}
		r.Native, err = json.Marshal(n)
	} else {
		exit := "Id=panel-load-balance-stream.service\nLoadState=loaded\nActiveState=active\nSubState=exited\nMainPID=0\nControlPID=0\nInvocationID=" + invocation + "\nResult=success\nExecMainCode=1\nExecMainStatus=0\nRemainAfterExit=yes\n"
		n := streamServiceRecordedStopped{Format: 1, InvocationID: invocation, AccountUID: 991, AccountGID: 992, EngineSHA256: facts.NginxSHA256,
			FinalExitSHA256: core.Hash(exit), FinalExitProperties: exit, OriginalProcesses: processes,
			OriginalQUITObserved: true, EmptyCgroupBeforeCleanup: true, ManagerCleanupObserved: true}
		r.Native, err = json.Marshal(n)
	}
	if err != nil {
		t.Fatal(err)
	}
	policy, err := streamReceiptEgressPolicy(seed, state, facts.AccountUID)
	if err != nil {
		t.Fatal(err)
	}
	r.Egress = streamEgressReceiptFixture(t, policy)
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n'), seedRaw, r
}

// These synthetic historical bytes exercise decoding only; they grant no
// authority and cannot be used by the Linux live ownership checks.
func streamEgressReceiptFixture(t *testing.T, policy loadbalancestream.EgressGuard) streamEgressReceipt {
	t.Helper()
	rules, err := policy.CreateRules()
	if err != nil {
		t.Fatal(err)
	}
	handles := make([]uint64, strings.Count(string(rules), "add rule "))
	for i := range handles {
		handles[i] = uint64(i + 2)
	}
	return streamEgressReceipt{Format: 1, BootID: "a7000000-0000-4000-8000-000000000001", NetnsDevice: 4, NetnsInode: 4026531992,
		NftSHA256: strings.Repeat("7", 64), Observation: loadbalancestream.EgressGuardObservation{
			PolicySHA256: policy.SHA256(), TableHandle: 17, ChainHandle: 1, RuleHandles: handles}}
}

func TestLoadBalanceStreamServiceReceiptKeepsCompleteNativeBodyAndExactStateBinding(t *testing.T) {
	for _, state := range []string{"running", "stopped"} {
		raw, seed, r := streamServiceReceiptFixture(t, state)
		decoded, err := decodeStreamServiceReceipt(raw, seed)
		if err != nil || decoded.State != state || decoded.RequestID != r.RequestID || len(decoded.Native) == 0 {
			t.Fatal("complete immutable historical body rejected", state, err)
		}
		for _, change := range []func(*streamServiceReceipt){
			func(r *streamServiceReceipt) { r.RequestID = core.ID() },
			func(r *streamServiceReceipt) { r.Version = "1.8.5" },
			func(r *streamServiceReceipt) { r.InstallationID = strings.Repeat("0", 32) },
			func(r *streamServiceReceipt) { r.SeedSHA256 = strings.Repeat("f", 64) },
			func(r *streamServiceReceipt) { r.ConfigurationSHA256 = strings.Repeat("f", 64) },
			func(r *streamServiceReceipt) { r.ServiceUnitSHA256 = strings.Repeat("f", 64) },
			func(r *streamServiceReceipt) { r.Native = json.RawMessage("null") },
			func(r *streamServiceReceipt) { r.CurrentWorker.PID = 219 },
			func(r *streamServiceReceipt) { r.Egress = streamEgressReceipt{} },
			func(r *streamServiceReceipt) { r.Egress.Format = 2 },
			func(r *streamServiceReceipt) { r.Egress.BootID = strings.Repeat("0", 36) },
			func(r *streamServiceReceipt) { r.Egress.BootID = "00000000-0000-0000-0000-000000000000" },
			func(r *streamServiceReceipt) { r.Egress.NetnsDevice = 0 },
			func(r *streamServiceReceipt) { r.Egress.NetnsInode = 0 },
			func(r *streamServiceReceipt) { r.Egress.NftSHA256 = strings.Repeat("0", 64) },
			func(r *streamServiceReceipt) { r.Egress.Observation.PolicySHA256 = strings.Repeat("f", 64) },
			func(r *streamServiceReceipt) { r.Egress.Observation.TableHandle = 0 },
			func(r *streamServiceReceipt) { r.Egress.Observation.ChainHandle = 0 },
			func(r *streamServiceReceipt) { r.Egress.Observation.RuleHandles = nil },
			func(r *streamServiceReceipt) { r.Egress.Observation.RuleHandles = []uint64{0} },
			func(r *streamServiceReceipt) {
				if state == "running" {
					r.State = "stopped"
				} else {
					r.State = "running"
				}
			},
		} {
			bad := r
			change(&bad)
			changed, _ := json.Marshal(bad)
			if _, err := decodeStreamServiceReceipt(append(changed, '\n'), seed); err == nil {
				t.Fatal("other identity, wrong generation or claimed native body accepted", state)
			}
		}
		for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(append([]byte{}, raw...), '\n'), append(append([]byte{}, raw...), 0), []byte(strings.Repeat(" ", streamServiceReceiptMaxBytes+1))} {
			if _, err := decodeStreamServiceReceipt(bad, seed); err == nil {
				t.Fatal("noncanonical or oversized receipt accepted")
			}
		}
	}
}

func TestLoadBalanceStreamServiceReceiptRejectsReplacedWorkerOOMOrAbnormalStopBody(t *testing.T) {
	_, seed, r := streamServiceReceiptFixture(t, "running")
	for _, change := range []func(*streamServiceRecordedRunning){
		func(n *streamServiceRecordedRunning) { n.AccountUID = 0 },
		func(n *streamServiceRecordedRunning) { n.AccountGID = 1000 },
		func(n *streamServiceRecordedRunning) { n.EngineSHA256 = strings.Repeat("0", 64) },
		func(n *streamServiceRecordedRunning) { n.InvocationID = strings.Repeat("0", 32) },
		func(n *streamServiceRecordedRunning) { n.UnitSHA256 = strings.Repeat("f", 64) },
		func(n *streamServiceRecordedRunning) { n.Processes[1].StartTime++ },
		func(n *streamServiceRecordedRunning) { n.Processes[1].ParentPID = 1 },
		func(n *streamServiceRecordedRunning) { n.Processes = append(n.Processes, n.Processes[1]) },
		func(n *streamServiceRecordedRunning) { n.IngressPrograms = nil },
		func(n *streamServiceRecordedRunning) { n.EgressPrograms = []uint32{1, 1} },
		func(n *streamServiceRecordedRunning) { n.MemoryMax = n.MemoryHigh - 1 },
	} {
		var n streamServiceRecordedRunning
		json.Unmarshal(r.Native, &n)
		change(&n)
		bad := r
		bad.Native, _ = json.Marshal(n)
		raw, _ := json.Marshal(bad)
		if _, err := decodeStreamServiceReceipt(append(raw, '\n'), seed); err == nil {
			t.Fatal("changed kernel/process identity accepted")
		}
	}
	_, seed, r = streamServiceReceiptFixture(t, "stopped")
	for _, change := range []func(*streamServiceRecordedStopped){
		func(n *streamServiceRecordedStopped) { n.OriginalQUITObserved = false },
		func(n *streamServiceRecordedStopped) { n.EmptyCgroupBeforeCleanup = false },
		func(n *streamServiceRecordedStopped) { n.ManagerCleanupObserved = false },
		func(n *streamServiceRecordedStopped) { n.FinalExitSHA256 = strings.Repeat("f", 64) },
		func(n *streamServiceRecordedStopped) {
			n.FinalExitProperties = strings.Replace(n.FinalExitProperties, "Status=0", "Status=9", 1)
			n.FinalExitSHA256 = core.Hash(n.FinalExitProperties)
		},
		func(n *streamServiceRecordedStopped) { n.OriginalProcesses[1].ParentPID = 1 },
	} {
		var n streamServiceRecordedStopped
		json.Unmarshal(r.Native, &n)
		change(&n)
		bad := r
		bad.Native, _ = json.Marshal(n)
		raw, _ := json.Marshal(bad)
		if _, err := decodeStreamServiceReceipt(append(raw, '\n'), seed); err == nil {
			t.Fatal("incomplete or abnormal original stop accepted")
		}
	}
}
