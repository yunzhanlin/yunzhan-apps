//go:build linux

package executor

import (
	"bytes"
	"testing"
)

func intrusionJournalAbsentFixture(t *testing.T, state string) intrusionJournalPlan {
	t.Helper()
	p := intrusionJournalFixture(t)
	p.KernelState, p.BansBefore = state, []string{}
	p.KernelBefore, p.KernelDirectory = nil, nil
	if state == "table_absent" {
		p.KernelDirectory = []byte(`{"nftables":[]}`)
	} else {
		p.KernelBefore = intrusionNftEncode(t, intrusionLazySharedTable(t))
	}
	var err error
	p, err = intrusionJournalDerive(p)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIntrusionJournalKeepsPositiveAbsenceEvidenceWithoutInventingRules(t *testing.T) {
	for _, state := range []string{"table_absent", "scope_absent"} {
		t.Run(state, func(t *testing.T) {
			p := intrusionJournalAbsentFixture(t, state)
			raw, err := intrusionJournalEncode(p)
			if err != nil {
				t.Fatal(err)
			}
			got, err := intrusionJournalDecode(raw)
			if err != nil || got.KernelState != state || len(got.BansBefore) != 0 || !bytes.Equal(got.KernelBefore, p.KernelBefore) || !bytes.Equal(got.KernelDirectory, p.KernelDirectory) {
				t.Fatal(got, err)
			}
			// A deferred historical observation cannot authorize any current
			// rule replacement, especially a reconstruction of historical IPs.
			if _, err = intrusionJournalLivePortPlan(p, p.KernelBefore, nil, "committed"); err == nil {
				t.Fatal("deferred state invented a rule mutation")
			}
		})
	}
}

func TestIntrusionJournalRefusesAmbiguousOrForgedAbsence(t *testing.T) {
	for name, mutate := range map[string]func(*intrusionJournalPlan){
		"unknown-state":       func(p *intrusionJournalPlan) { p.KernelState = "healthy" },
		"missing-state":       func(p *intrusionJournalPlan) { p.KernelState = "" },
		"missing-directory":   func(p *intrusionJournalPlan) { p.KernelDirectory = nil },
		"directory-null":      func(p *intrusionJournalPlan) { p.KernelDirectory = []byte(`{"nftables":null}`) },
		"directory-duplicate": func(p *intrusionJournalPlan) { p.KernelDirectory = []byte(`{"nftables":[],"nftables":[]}`) },
		"table-exists": func(p *intrusionJournalPlan) {
			p.KernelDirectory = []byte(`{"nftables":[{"table":{"family":"inet","name":"f2b-table"}}]}`)
		},
		"historical-ban":     func(p *intrusionJournalPlan) { p.BansBefore = []string{"127.0.0.2"} },
		"mixed-table":        func(p *intrusionJournalPlan) { p.KernelBefore = intrusionJournalFixture(t).KernelBefore },
		"wrong-shared-state": func(p *intrusionJournalPlan) { p.KernelState = "scope_absent" },
	} {
		t.Run(name, func(t *testing.T) {
			p := intrusionJournalAbsentFixture(t, "table_absent")
			mutate(&p)
			before, _ := intrusionJournalEncode(p)
			if err := intrusionJournalValidate(p); err == nil {
				t.Fatal("ambiguous absence authorized")
			}
			after, _ := intrusionJournalEncode(p)
			if !bytes.Equal(before, after) {
				t.Fatal("repaired original false evidence")
			}
		})
	}
	for _, state := range []string{"rules_observed", "scope_absent"} {
		p := intrusionJournalAbsentFixture(t, "scope_absent")
		p.KernelState = state
		p.KernelDirectory = []byte(`{"nftables":[]}`)
		if err := intrusionJournalValidate(p); err == nil {
			t.Fatal("mixed directory and table accepted", state)
		}
	}
}
