package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestGenerationRecordBindsCompleteOriginalWithoutManufacturingCommit(t *testing.T) {
	for _, action := range []string{"create", "replace", "remove"} {
		t.Run(action, func(t *testing.T) {
			seed, raw := controlSeedFixture(t, action)
			records := controlChainFixture(t, raw)
			before, _ := json.Marshal(records)
			proposal, final, err := ProposeGenerationRecord(strings.Repeat("a", 32), 2, raw, records[:11])
			if err != nil || !bytes.Equal(final, records[11]) {
				t.Fatal("bounded exact generation proposal refused", err)
			}
			v, err := DecodeGenerationRecord(proposal)
			if err != nil || v.Generation != 2 || v.RequestID != seed.Operation.RequestID || !reflect.DeepEqual(v.Entries, seed.After) {
				t.Fatal("complete original set/identity not retained", err)
			}
			for n := 0; n < len(records); n++ {
				if GenerationRecordBindsOriginal(proposal, strings.Repeat("a", 32), 2, raw, records[:n]) {
					t.Fatal("missing actual final record was relabelled committed", n)
				}
			}
			if !GenerationRecordBindsOriginal(proposal, strings.Repeat("a", 32), 2, raw, records) {
				t.Fatal("full original recorded binding refused")
			}
			if GenerationRecordBindsOriginal(proposal, strings.Repeat("b", 32), 2, raw, records) || GenerationRecordBindsOriginal(proposal, strings.Repeat("a", 32), 3, raw, records) {
				t.Fatal("different actual installed instance or expected lineage was accepted")
			}
			after, _ := json.Marshal(records)
			if !bytes.Equal(before, after) {
				t.Fatal("proposal appended/mutated actual original journal")
			}
			v.Entries[0].Nodes[0].Weight++
			if reflect.DeepEqual(v.Entries, seed.After) {
				t.Fatal("record reused mutable caller nodes")
			}
		})
	}
}

func TestGenerationRecordRejectsAmbiguousPartialAndMismatchedClaims(t *testing.T) {
	_, raw := controlSeedFixture(t, "create")
	records := controlChainFixture(t, raw)
	valid, _, err := ProposeGenerationRecord(strings.Repeat("a", 32), 1, raw, records[:11])
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"nil-entries", "wrong-instance", "zero-generation", "generation-limit", "wrong-request", "changed-entries", "wrong-config", "wrong-seed", "wrong-final", "wrong-observation", "unknown-field", "duplicate-field", "field-alias", "extra-document"} {
		t.Run(fault, func(t *testing.T) {
			v, err := DecodeGenerationRecord(valid)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "nil-entries":
				v.Entries = nil
			case "wrong-instance":
				v.InstallationID = "../unsafe"
			case "zero-generation":
				v.Generation = 0
			case "generation-limit":
				v.Generation = 1 << 60
			case "wrong-request":
				v.RequestID = strings.Repeat("b", 32)
			case "changed-entries":
				v.Entries[0].Revision++
			case "wrong-config":
				v.ConfigurationSHA256 = strings.Repeat("b", 64)
			case "wrong-seed":
				v.SeedSHA256 = strings.Repeat("b", 64)
			case "wrong-final":
				v.FinalEventSHA256 = strings.Repeat("b", 64)
			case "wrong-observation":
				v.ServiceObservationSHA256 = strings.Repeat("b", 64)
			}
			candidate, _ := json.Marshal(v)
			candidate = append(candidate, '\n')
			switch fault {
			case "unknown-field":
				candidate = bytes.Replace(candidate, []byte(`"format":1`), []byte(`"format":1,"healthy":true`), 1)
			case "duplicate-field":
				candidate = bytes.Replace(candidate, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1)
			case "field-alias":
				candidate = bytes.Replace(candidate, []byte(`"format"`), []byte(`"Format"`), 1)
			case "extra-document":
				candidate = append(candidate, []byte("{}")...)
			}
			if GenerationRecordBindsOriginal(candidate, strings.Repeat("a", 32), 1, raw, records) {
				t.Fatal("claimed/ambiguous generation matched original", fault)
			}
		})
	}
	for _, n := range []int{0, 1, 10, 12} {
		if v, f, err := ProposeGenerationRecord(strings.Repeat("a", 32), 1, raw, records[:n]); err == nil || v != nil || f != nil {
			t.Fatal("partial/wrong phase gained a publication proposal", n)
		}
	}
}
