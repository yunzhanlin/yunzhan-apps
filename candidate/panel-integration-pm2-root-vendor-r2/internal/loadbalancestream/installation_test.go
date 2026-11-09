package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func streamInstallationFixture(t *testing.T, action string) (InstallationSeed, []byte, [][]byte) {
	t.Helper()
	empty, err := RenderRuntime([]Entry{}, ServiceRuntimePrefix, ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: MaxMemoryBudget})
	if err != nil {
		t.Fatal(err)
	}
	s := InstallationSeed{Format: 1, Nonce: strings.Repeat("a", 32), JobID: strings.Repeat("b", 32), ActorID: strings.Repeat("c", 32), Action: action, AppVersion: AppVersion, AccessRevision: 1, ActorObservationSHA256: strings.Repeat("1", 64), ManifestSHA256: strings.Repeat("2", 64), OriginalRequestSHA256: strings.Repeat("3", 64), KeySHA256: strings.Repeat("4", 64), JobCreatedAt: "2026-10-25T00:00:00Z", CatalogSHA256: strings.Repeat("5", 64), SubmissionSHA256: strings.Repeat("6", 64), ProgrammeInputsSHA256: strings.Repeat("7", 64), EmptyConfigurationSHA: empty.SHA256}
	payload := `{"settings":{},"version":"` + AppVersion + `"}`
	if action == "update" {
		s.OriginalModuleVersion = "1.8.5"
		s.OriginalModuleSHA256 = strings.Repeat("8", 64)
		payload = `{"settings":null,"version":"` + AppVersion + `"}`
	}
	s.PayloadSHA256 = serviceDigest([]byte(payload))
	raw, err := InstallationSeedBytes(s)
	if err != nil {
		t.Fatal(err)
	}
	var records [][]byte
	for i := 0; i < InstallationPhaseCount; i++ {
		e := InstallationEvidence{}
		if i == 2 {
			e.AccountReceiptSHA256 = strings.Repeat("9", 64)
		}
		if i == 4 {
			e.PublishedModuleSHA256 = strings.Repeat("a", 64)
		}
		next, err := NextInstallationEvent(raw, records, e)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, next)
	}
	return s, raw, records
}

func TestInstallationDistinctOriginalCompleteAndUnknownPrefixes(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		t.Run(action, func(t *testing.T) {
			s, raw, records := streamInstallationFixture(t, action)
			before := bytes.Clone(raw)
			got, err := DecodeInstallationSeed(raw)
			if err != nil || got != s || !bytes.Equal(raw, before) {
				t.Fatal("original immutable installation seed changed", err)
			}
			for n := 1; n <= InstallationPhaseCount; n++ {
				chain, err := DecodeInstallationChain(raw, records[:n])
				if err != nil || chain.Complete != (n == InstallationPhaseCount) || chain.OriginalUnknown != (n < InstallationPhaseCount) || len(chain.Events) != n {
					t.Fatal("prefix promoted or lost original unknown", n, err)
				}
			}
			if _, err := NextInstallationEvent(raw, records, InstallationEvidence{}); err == nil {
				t.Fatal("terminal installation appended or replayed")
			}
			if _, err := DecodeControlSeed(raw); err == nil {
				t.Fatal("installation seed became ordinary stream control")
			}
		})
	}
}

func TestInstallationSeedExactScopeAndImmutablePins(t *testing.T) {
	fields := []string{"Nonce", "JobID", "ActorID", "ActorObservationSHA256", "ManifestSHA256", "PayloadSHA256", "OriginalRequestSHA256", "KeySHA256", "CatalogSHA256", "SubmissionSHA256", "ProgrammeInputsSHA256", "EmptyConfigurationSHA"}
	for _, field := range fields {
		for _, value := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), "foreign\nvalue"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				s, _, _ := streamInstallationFixture(t, "install")
				reflect.ValueOf(&s).Elem().FieldByName(field).SetString(value)
				if _, err := InstallationSeedBytes(s); err == nil {
					t.Fatal("unbound identity/digest returned installation bytes", field)
				}
			})
		}
	}
	for _, fault := range []string{"old-version", "future-version", "wrong-kind", "revision-zero", "initial-adoption", "unknown-update", "missing-prior-digest", "future-clock", "clock-alias", "not-empty-config"} {
		t.Run(fault, func(t *testing.T) {
			s, _, _ := streamInstallationFixture(t, "update")
			switch fault {
			case "old-version":
				s.AppVersion = "1.8.5"
			case "future-version":
				s.AppVersion = "1.9.1"
			case "wrong-kind":
				s.Action = "recover"
			case "revision-zero":
				s.AccessRevision = 0
			case "initial-adoption":
				s.Action = "install"
			case "unknown-update":
				s.OriginalModuleVersion = "1.7.0"
			case "missing-prior-digest":
				s.OriginalModuleSHA256 = ""
			case "future-clock":
				s.JobCreatedAt = "9999-01-01T00:00:00Z"
			case "clock-alias":
				s.JobCreatedAt = "2026-10-25T08:00:00+08:00"
			case "not-empty-config":
				s.EmptyConfigurationSHA = strings.Repeat("f", 64)
			}
			if _, err := InstallationSeedBytes(s); err == nil {
				t.Fatal("foreign scope/unknown original returned installation bytes", fault)
			}
		})
	}
	_, raw, _ := streamInstallationFixture(t, "install")
	for _, changed := range [][]byte{append([]byte(" "), raw...), bytes.Replace(raw, []byte(`"format":1`), []byte(`"Format":1`), 1), bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1), append(bytes.Clone(raw), []byte("{}")...)} {
		if _, err := DecodeInstallationSeed(changed); err == nil {
			t.Fatal("noncanonical/ambiguous installation seed accepted")
		}
	}
}

func TestInstallationChainRefusesHolesReorderForksAndFalseWitnesses(t *testing.T) {
	_, raw, records := streamInstallationFixture(t, "install")
	for i := range records {
		for _, field := range []string{"Format", "Sequence", "Phase", "SeedSHA256", "PreviousEventSHA256", "AccountReceiptSHA256", "PublishedModuleSHA256"} {
			t.Run(string(rune('0'+i))+"/"+field, func(t *testing.T) {
				copy := append([][]byte(nil), records...)
				var v InstallationEvent
				if json.Unmarshal(copy[i], &v) != nil {
					t.Fatal("fixture")
				}
				rv := reflect.ValueOf(&v).Elem().FieldByName(field)
				if rv.Kind() == reflect.Int {
					rv.SetInt(rv.Int() + 1)
				} else {
					rv.SetString(strings.Repeat("f", 64))
				}
				copy[i], _ = installationEventBytes(v)
				if _, err := DecodeInstallationChain(raw, copy); err == nil {
					t.Fatal("altered original event chain accepted", i, field)
				}
			})
		}
	}
	for _, changed := range [][][]byte{records[1:], append(append([][]byte(nil), records[:2]...), records[3:]...), {records[1], records[0]}, append(append([][]byte(nil), records...), records[len(records)-1])} {
		if _, err := DecodeInstallationChain(raw, changed); err == nil {
			t.Fatal("missing/reordered/extra original events accepted")
		}
	}
	for i := 0; i < InstallationPhaseCount; i++ {
		e := InstallationEvidence{AccountReceiptSHA256: strings.Repeat("9", 64), PublishedModuleSHA256: strings.Repeat("a", 64)}
		if _, err := NextInstallationEvent(raw, records[:i], e); err == nil {
			t.Fatal("out-of-phase or surplus witness accepted", i)
		}
	}
}
