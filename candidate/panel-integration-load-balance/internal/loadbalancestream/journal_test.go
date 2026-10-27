package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func controlSeedFixture(t *testing.T, action string) (ControlSeed, []byte) {
	t.Helper()
	op, binding := streamOperationFixture()
	before := []Entry{}
	probe := 43000
	if action != "create" {
		entry := fixture()
		before, probe = []Entry{entry}, 0
		op.Mutation.Action, op.Mutation.ExpectedRevision, op.Mutation.ExpectedFingerprint = action, entry.Revision, Fingerprint(entry)
		if action == "remove" {
			op.Mutation.Policy = nil
		} else {
			op.Mutation.Policy.Method = "least-connections"
		}
	}
	facts := serviceFacts()
	prior, err := RenderRuntime(before, ServiceRuntimePrefix, facts.Validation)
	if err != nil {
		t.Fatal(err)
	}
	binding.OriginalConfigSHA256, binding.OperationSHA256 = prior.SHA256, OperationSHA256(op)
	seed, plan, err := PrepareControlSeed(op, binding, before, probe, strings.Repeat("6", 64), facts)
	if err != nil || plan.Current.SHA256 != seed.AfterRuntimeSHA256 || plan.SHA256 != seed.ServiceUnitSHA256 {
		t.Fatal("original exact seed refused", action, err)
	}
	raw, err := controlSeedBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	return seed, raw
}

func controlChainFixture(t *testing.T, seed []byte) [][]byte {
	t.Helper()
	var records [][]byte
	for sequence := range controlPhases {
		evidence := ControlAdvanceEvidence{}
		if sequence == 2 {
			evidence.AccountReceiptSHA256 = strings.Repeat("7", 64)
		}
		if sequence == 10 {
			evidence.ServiceObservationSHA = strings.Repeat("8", 64)
		}
		raw, err := NextControlEvent(seed, records, evidence)
		if err != nil {
			t.Fatal("original sequential record refused", sequence, err)
		}
		records = append(records, raw)
		chain, err := DecodeControlChain(seed, records)
		if err != nil || chain.Complete != (sequence == 11) || chain.OriginalUnknown == chain.Complete {
			t.Fatal("partial original history became completed/retry authority", sequence, chain, err)
		}
	}
	return records
}

func TestControlJournalOriginalThreeTransitionsAndEveryPartialOutcome(t *testing.T) {
	for _, action := range []string{"create", "replace", "remove"} {
		t.Run(action, func(t *testing.T) {
			seed, raw := controlSeedFixture(t, action)
			before := bytes.Clone(raw)
			decoded, err := DecodeControlSeed(raw)
			if err != nil || !reflect.DeepEqual(seed, decoded) || !bytes.Equal(raw, before) {
				t.Fatal("original seed changed/refused", err)
			}
			encoded, err := ControlSeedBytes(decoded)
			if err != nil || !bytes.Equal(encoded, raw) {
				t.Fatal("external Root adapter serialization changed original seed", err)
			}
			records := controlChainFixture(t, raw)
			original := make([][]byte, len(records))
			for i := range records {
				original[i] = bytes.Clone(records[i])
			}
			if next, err := NextControlEvent(raw, records, ControlAdvanceEvidence{}); err == nil || next != nil {
				t.Fatal("completed original history appended another operation")
			}
			for count := 1; count < len(records); count++ {
				partial, err := DecodeControlChain(raw, records[:count])
				if err != nil || partial.Complete || !partial.OriginalUnknown {
					t.Fatal("incomplete original history relabelled success", count, err)
				}
			}
			if !reflect.DeepEqual(records, original) || !bytes.Equal(raw, before) {
				t.Fatal("read-only journal qualification mutated original records")
			}
		})
	}
}

func TestControlJournalSeedRefusesDifferentTransitionAndNoncanonicalEvidence(t *testing.T) {
	seed, raw := controlSeedFixture(t, "create")
	for _, item := range []struct {
		name string
		edit func(*ControlSeed)
	}{
		{"format", func(v *ControlSeed) { v.Format = 2 }},
		{"nil-before", func(v *ControlSeed) { v.Before = nil }},
		{"nil-after", func(v *ControlSeed) { v.After = nil }},
		{"foreign-app", func(v *ControlSeed) { v.Binding.AppID = "memcached" }},
		{"different-actor", func(v *ControlSeed) { v.Operation.ActorID = strings.Repeat("c", 32) }},
		{"different-request", func(v *ControlSeed) { v.Operation.RequestID = strings.Repeat("d", 32) }},
		{"before-digest", func(v *ControlSeed) { v.BeforeRuntimeSHA256 = strings.Repeat("1", 64) }},
		{"after-digest", func(v *ControlSeed) { v.AfterRuntimeSHA256 = strings.Repeat("2", 64) }},
		{"binding-before", func(v *ControlSeed) { v.Binding.OriginalConfigSHA256 = strings.Repeat("3", 64) }},
		{"no-kernel", func(v *ControlSeed) { v.OriginalKernelSHA256 = "" }},
		{"zero-kernel", func(v *ControlSeed) { v.OriginalKernelSHA256 = strings.Repeat("0", 64) }},
		{"zero-unit", func(v *ControlSeed) { v.ServiceUnitSHA256 = strings.Repeat("0", 64) }},
		{"probe-allocation", func(v *ControlSeed) { v.FreshProbePort++ }},
		{"after-identity", func(v *ControlSeed) { v.After[0].Name = "other.lb.invalid" }},
		{"after-revision", func(v *ControlSeed) { v.After[0].Revision++ }},
		{"after-policy", func(v *ControlSeed) { v.After[0].Nodes[0].Weight++ }},
		{"too-many-before", func(v *ControlSeed) { v.Before = make([]Entry, MaxEntries+1) }},
		{"too-many-after", func(v *ControlSeed) { v.After = make([]Entry, MaxEntries+1) }},
	} {
		t.Run(item.name, func(t *testing.T) {
			value, err := DecodeControlSeed(raw)
			if err != nil {
				t.Fatal(err)
			}
			item.edit(&value)
			changed, _ := controlSeedBytes(value)
			if _, err := DecodeControlSeed(changed); err == nil {
				t.Fatal("changed original transition or incomplete private evidence accepted")
			}
		})
	}
	for _, invalid := range [][]byte{nil, []byte("null"), []byte("{}"), []byte("[]"), append([]byte(" "), raw...), append(bytes.Clone(raw), '\n'), bytes.TrimSuffix(raw, []byte("\n")), bytes.Repeat([]byte("x"), MaxControlSeedBytes+1), bytes.Replace(raw, []byte("\"format\":1"), []byte("\"format\":1,\"format\":1"), 1)} {
		if _, err := DecodeControlSeed(invalid); err == nil {
			t.Fatal("incomplete/noncanonical seed accepted")
		}
	}
	if seed.Binding.OperationSHA256 != OperationSHA256(seed.Operation) {
		t.Fatal("original immutable binding changed")
	}
}

func TestControlJournalEveryPhaseBindsOriginalSeedPreviousRecordAndWitnesses(t *testing.T) {
	_, seed := controlSeedFixture(t, "create")
	records := controlChainFixture(t, seed)
	for sequence := range records {
		for _, field := range []string{"Format", "Sequence", "Phase", "SeedSHA256", "PreviousEventSHA256", "AccountReceiptSHA256", "ConfigurationSHA256", "ServiceObservationSHA"} {
			t.Run(controlPhases[sequence]+"/"+field, func(t *testing.T) {
				copyRecords := make([][]byte, len(records))
				for i := range records {
					copyRecords[i] = bytes.Clone(records[i])
				}
				var event ControlEvent
				if json.Unmarshal(copyRecords[sequence], &event) != nil {
					t.Fatal("fixture record")
				}
				value := reflect.ValueOf(&event).Elem().FieldByName(field)
				if value.Kind() == reflect.Int {
					value.SetInt(value.Int() + 1)
				} else {
					value.SetString(strings.Repeat("9", 64))
				}
				copyRecords[sequence], _ = controlEventBytes(event)
				if _, err := DecodeControlChain(seed, copyRecords); err == nil {
					t.Fatal("original chain accepted different phase/identity/previous record or witness")
				}
			})
		}
	}
	for _, scenario := range []string{"empty", "too-long", "reordered", "noncanonical", "foreign-seed"} {
		t.Run(scenario, func(t *testing.T) {
			values := append([][]byte(nil), records...)
			input := seed
			switch scenario {
			case "empty":
				values = nil
			case "too-long":
				values = append(values, records[len(records)-1])
			case "reordered":
				values[0], values[1] = values[1], values[0]
			case "noncanonical":
				values[3] = append(bytes.Clone(values[3]), '\n')
			case "foreign-seed":
				value, _ := DecodeControlSeed(seed)
				value.OriginalKernelSHA256 = strings.Repeat("e", 64)
				input, _ = controlSeedBytes(value)
			}
			if _, err := DecodeControlChain(input, values); err == nil {
				t.Fatal("original chain accepted missing/reordered/foreign records")
			}
		})
	}
}

func TestControlJournalEvidenceOnlyAppearsAtItsOriginalEffectBoundary(t *testing.T) {
	_, seed := controlSeedFixture(t, "create")
	records := controlChainFixture(t, seed)
	for sequence := range controlPhases {
		t.Run(controlPhases[sequence], func(t *testing.T) {
			for _, evidence := range []ControlAdvanceEvidence{
				{AccountReceiptSHA256: strings.Repeat("0", 64)},
				{ServiceObservationSHA: strings.Repeat("0", 64)},
				{AccountReceiptSHA256: strings.Repeat("7", 64), ServiceObservationSHA: strings.Repeat("8", 64)},
			} {
				if raw, err := NextControlEvent(seed, records[:sequence], evidence); err == nil || raw != nil {
					t.Fatal("missing/early/late/mixed witness advanced original phase")
				}
			}
			if sequence == 2 || sequence == 10 {
				if raw, err := NextControlEvent(seed, records[:sequence], ControlAdvanceEvidence{}); err == nil || raw != nil {
					t.Fatal("required original effect observation omitted")
				}
			}
		})
	}
}

func TestControlJournalPrepareCannotBorrowAnotherBeforeStateOrHostAdmission(t *testing.T) {
	seed, _ := controlSeedFixture(t, "create")
	for _, fault := range []string{"before-digest", "kernel-digest", "host-memory", "native-version", "system-UID", "private-control-port", "occupied-probe", "occupied-data"} {
		t.Run(fault, func(t *testing.T) {
			facts := serviceFacts()
			binding, kernel := seed.Binding, seed.OriginalKernelSHA256
			switch fault {
			case "before-digest":
				binding.OriginalConfigSHA256 = strings.Repeat("f", 64)
			case "kernel-digest":
				kernel = ""
			case "host-memory":
				facts.AvailableMemoryBytes = 1
			case "native-version":
				facts.NginxVersion = "../foreign"
			case "system-UID":
				facts.AccountUID = 1000
			case "private-control-port":
				facts.Validation.PanelControlPorts = append(facts.Validation.PanelControlPorts, seed.Operation.Mutation.Policy.Port)
			case "occupied-probe":
				facts.Validation.OccupiedTCPPorts = []int{43000}
			case "occupied-data":
				facts.Validation.OccupiedTCPPorts = []int{seed.Operation.Mutation.Policy.Port}
			}
			actual, plan, err := PrepareControlSeed(seed.Operation, binding, seed.Before, 43000, kernel, facts)
			if err == nil || !reflect.DeepEqual(actual, ControlSeed{}) || !reflect.DeepEqual(plan, ServicePlan{}) {
				t.Fatal("uncheckable original/host state returned a partial executable plan")
			}
		})
	}
}
