//go:build linux

package executor

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

func apacheRuntimeJournalFixture(t *testing.T) (*Service, wafTransaction) {
	t.Helper()
	s, plan := apacheTransactionFixture(t, true, false)
	old := "# managed by panel\nServerRoot \"/opt/panel/runtimes/apache/2.4.68\"\n"
	next := strings.ReplaceAll(old, "2.4.68", "2.4.71")
	plan[0].OldData = []byte(old)
	plan[0].NextData = []byte(next)
	if err := os.WriteFile(plan[0].Path, plan[0].OldData, plan[0].OldMode); err != nil {
		t.Fatal(err)
	}
	tx, err := s.startWAFTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	tx.ApacheRuntime = &apacheRuntimeTransition{JobID: core.ID(), PreviousID: runtimecatalog.ApacheLegacyID, NextID: runtimecatalog.ApacheCurrentID, ApplyOwner: &moduleApplyOwner{PID: 2, StartTime: 3}, BootID: "01234567-89ab-cdef-0123-456789abcdef"}
	if err := s.wafTransactionContract(tx); err != nil {
		t.Fatal(err)
	}
	return s, tx
}

func TestApacheRuntimeJournalOnlyAuthorizesExactReviewedTriplet(t *testing.T) {
	s, base := apacheRuntimeJournalFixture(t)
	changes := map[string]func(*wafTransaction){
		"foreign-application": func(v *wafTransaction) { v.IDS = &threatIDSRecoveryState{} },
		"missing-boot":        func(v *wafTransaction) { v.ApacheRuntime.BootID = "" },
		"missing-owner":       func(v *wafTransaction) { v.ApacheRuntime.ApplyOwner = nil },
		"pid-one":             func(v *wafTransaction) { v.ApacheRuntime.ApplyOwner.PID = 1 },
		"unknown-next":        func(v *wafTransaction) { v.ApacheRuntime.NextID = "apache-2.4.70" },
		"reverse-authority": func(v *wafTransaction) {
			v.ApacheRuntime.PreviousID, v.ApacheRuntime.NextID = v.ApacheRuntime.NextID, v.ApacheRuntime.PreviousID
		},
		"cross-root": func(v *wafTransaction) {
			v.Changes[0].NextData = v.Changes[0].OldData
			v.Digests[v.Changes[0].Path+":next"] = core.Hash(string(v.Changes[0].NextData))
		},
		"wrong-path-order": func(v *wafTransaction) { v.Changes[1], v.Changes[2] = v.Changes[2], v.Changes[1] },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var altered wafTransaction
			if err := apacheBodyDecodeJSON(raw, &altered); err != nil {
				t.Fatal(err)
			}
			mutate(&altered)
			if s.wafTransactionContract(altered) == nil {
				t.Fatal("invalid startup authority accepted")
			}
		})
	}
	other := New(s.Config)
	if other.wafTransactionContract(base) == nil {
		t.Fatal("Apache owner escaped its original namespace")
	}
}

func TestApacheRuntimeJournalInterruptedWriteRestoresOriginalBytesOwnersAndVersion(t *testing.T) {
	for cut := 0; cut <= 3; cut++ {
		t.Run(string(rune('A'+cut)), func(t *testing.T) {
			s, tx := apacheRuntimeJournalFixture(t)
			if err := wafWriteTransaction(s.wafPendingPath(), tx); err != nil {
				t.Fatal(err)
			}
			for _, change := range tx.Changes[:cut] {
				if err := wafApplyChange(change, true); err != nil {
					t.Fatal(err)
				}
			}
			fresh := New(s.Config).apacheWAFTransactionService()
			if _, err := fresh.recoverWAFTransaction(); err != nil {
				t.Fatal(err)
			}
			recovered, err := fresh.readWAFTransaction()
			if err != nil || recovered.State != "recovered" || recovered.ApacheRuntime.JobID != tx.ApacheRuntime.JobID {
				t.Fatal("original runtime switch identity lost", err)
			}
			for _, change := range tx.Changes {
				same, err := fresh.wafCurrentMatches(change, false)
				if err != nil || !same {
					t.Fatal("original triplet not preserved", err)
				}
			}
		})
	}
}
