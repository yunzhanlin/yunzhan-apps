package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func coldBootFixture(t *testing.T) (Operation, OperationBinding, []Entry, ColdBootRecord) {
	t.Helper()
	op, binding := streamOperationFixture()
	entry := fixture()
	op.Mutation.Action, op.Mutation.ExpectedRevision, op.Mutation.ExpectedFingerprint = "replace", entry.Revision, Fingerprint(entry)
	before := []Entry{entry}
	prior, err := RenderRuntime(before, ServiceRuntimePrefix, serviceFacts().Validation)
	if err != nil {
		t.Fatal(err)
	}
	binding.OriginalConfigSHA256, binding.OperationSHA256 = prior.SHA256, OperationSHA256(op)
	cold := ColdBootRecord{Format: 1, PreviousBootID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", BootID: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
		OriginalGenerationSHA256: strings.Repeat("7", 64), OriginalSeedSHA256: strings.Repeat("8", 64), OriginalServiceSHA256: strings.Repeat("9", 64)}
	return op, binding, before, cold
}

func TestColdBootClosedPlanPreservesOriginalBeforeAndExactPolicy(t *testing.T) {
	op, binding, before, cold := coldBootFixture(t)
	originalBefore, _ := json.Marshal(before)
	seed, plan, err := PrepareColdBootControlSeed(op, binding, before, 0, strings.Repeat("6", 64), serviceFacts(), cold)
	if err != nil || seed.ColdBoot == nil || *seed.ColdBoot != cold || !reflect.DeepEqual(seed.Before, before) ||
		plan.Current.ActiveEntries != 1 || plan.Retiring.ActiveEntries != 0 || len(ControlRetiringEntries(seed)) != 0 {
		t.Fatal("cold plan lost original lineage or invented a resident generation", err)
	}
	afterBefore, _ := json.Marshal(before)
	if !bytes.Equal(originalBefore, afterBefore) || seed.BeforeRuntimeSHA256 != binding.OriginalConfigSHA256 || seed.After[0].Revision != before[0].Revision+1 {
		t.Fatal("caller configuration/revision or original digest changed")
	}
	raw, err := ControlSeedBytes(seed)
	decoded, e2 := DecodeControlSeed(raw)
	if err != nil || e2 != nil || !reflect.DeepEqual(decoded, seed) || !bytes.Contains(raw, []byte(`"cold_boot":`)) {
		t.Fatal("closed cold-boot seed did not round trip", err, e2)
	}
	launch, err := PlanControlServiceLaunch(decoded, serviceFacts(), op.RequestID)
	if err != nil || launch.Service.SHA256 != plan.SHA256 || launch.Service.Retiring.ActiveEntries != 0 || !bytes.Equal(launch.Service.Current.Main, plan.Current.Main) {
		t.Fatal("launch regenerated a different service", err)
	}
	read, err := RecordedControlServicePlan(decoded, serviceFacts())
	if err != nil || !bytes.Equal(read.Unit, plan.Unit) {
		t.Fatal("recorded cold service could not be read exactly", err)
	}
	if _, err := PlanControlServiceLaunch(decoded, serviceFacts(), strings.Repeat("c", 32)); err == nil {
		t.Fatal("another request selected the original launch")
	}
	seed.ColdBoot.BootID = cold.PreviousBootID
	if _, err := ControlSeedBytes(seed); err == nil {
		t.Fatal("same-boot crash relabelled as reboot recovery")
	}
}

func TestColdBootCannotChangeDesiredPolicyOrRelaxResourceAdmission(t *testing.T) {
	changes := map[string]func(*Operation){
		"change-method":  func(op *Operation) { op.Mutation.Policy.Method = "least-connections" },
		"change-port":    func(op *Operation) { op.Mutation.Policy.Port++ },
		"change-backend": func(op *Operation) { op.Mutation.Policy.Nodes[0].Address = "127.0.0.2:8090" },
		"remove":         func(op *Operation) { op.Mutation.Action, op.Mutation.Policy = "remove", nil },
		"create": func(op *Operation) {
			op.Mutation.Action, op.Mutation.Name, op.Mutation.ExpectedRevision, op.Mutation.ExpectedFingerprint = "create", "another", 0, ""
		},
		"wrong-revision": func(op *Operation) { op.Mutation.ExpectedRevision++ },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			op, binding, before, cold := coldBootFixture(t)
			change(&op)
			binding.OperationSHA256 = OperationSHA256(op)
			if _, _, err := PrepareColdBootControlSeed(op, binding, before, 0, strings.Repeat("6", 64), serviceFacts(), cold); err == nil {
				t.Fatal("cold recovery changed original desired policy")
			}
		})
	}
	op, binding, before, cold := coldBootFixture(t)
	seed, plan, err := PrepareColdBootControlSeed(op, binding, before, 0, strings.Repeat("6", 64), serviceFacts(), cold)
	if err != nil {
		t.Fatal(err)
	}
	facts := serviceFacts()
	facts.AvailableMemoryBytes = plan.RequiredAvailableMemoryBytes - 1
	if _, _, err := PrepareColdBootControlSeed(op, binding, before, 0, strings.Repeat("6", 64), facts, cold); err == nil {
		t.Fatal("reboot skipped NEW start memory admission")
	}
	if _, err := PlanControlServiceLaunch(seed, facts, op.RequestID); err == nil {
		t.Fatal("launch skipped fresh resource admission")
	}
	if _, err := RecordedControlServicePlan(seed, facts); err != nil {
		t.Fatal("historical read incorrectly allocated resources", err)
	}
	if _, _, err := PrepareControlSeed(op, binding, before, 0, strings.Repeat("6", 64), serviceFacts()); err != nil {
		t.Fatal("ordinary two-generation control regressed", err)
	}
}

func TestColdBootRejectsMalformedRecordsAndKeepsLegacySeedBytes(t *testing.T) {
	changes := map[string]func(*ColdBootRecord){
		"format":             func(c *ColdBootRecord) { c.Format = 2 },
		"same-boot":          func(c *ColdBootRecord) { c.BootID = c.PreviousBootID },
		"zero-boot":          func(c *ColdBootRecord) { c.BootID = "00000000-0000-0000-0000-000000000000" },
		"trailing-boot":      func(c *ColdBootRecord) { c.BootID += "\n" },
		"uppercase-boot":     func(c *ColdBootRecord) { c.BootID = strings.ToUpper(c.BootID) },
		"missing-generation": func(c *ColdBootRecord) { c.OriginalGenerationSHA256 = "" },
		"zero-seed":          func(c *ColdBootRecord) { c.OriginalSeedSHA256 = strings.Repeat("0", 64) },
		"uppercase-receipt":  func(c *ColdBootRecord) { c.OriginalServiceSHA256 = strings.Repeat("A", 64) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			op, binding, before, cold := coldBootFixture(t)
			change(&cold)
			if _, _, err := PrepareColdBootControlSeed(op, binding, before, 0, strings.Repeat("6", 64), serviceFacts(), cold); err == nil {
				t.Fatal("malformed boot evidence was accepted")
			}
		})
	}
	for _, action := range []string{"create", "replace", "remove"} {
		seed, raw := controlSeedFixture(t, action)
		if seed.ColdBoot != nil || bytes.Contains(raw, []byte("cold_boot")) {
			t.Fatal("new optional field altered ordinary canonical seed")
		}
		read, err := RecordedControlServicePlan(seed, serviceFacts())
		old, oldErr := RecordedServicePlan(seed.After, seed.Before, serviceFacts())
		if err != nil || oldErr != nil || !reflect.DeepEqual(read, old) {
			t.Fatal("legacy plan changed", action, err, oldErr)
		}
		retiring := ControlRetiringEntries(seed)
		if !reflect.DeepEqual(retiring, seed.Before) {
			t.Fatal("ordinary resident generation disappeared")
		}
		if len(retiring) > 0 {
			retiring[0].Nodes[0].Address = "127.0.0.2:8090"
			if seed.Before[0].Nodes[0].Address == retiring[0].Nodes[0].Address {
				t.Fatal("retiring copy aliases original seed")
			}
		}
		withNull := append(bytes.TrimSuffix(bytes.Clone(raw), []byte("}\n")), []byte(",\"cold_boot\":null}\n")...)
		if _, err := DecodeControlSeed(withNull); err == nil {
			t.Fatal("explicit null changed canonical legacy wire")
		}
	}
}
