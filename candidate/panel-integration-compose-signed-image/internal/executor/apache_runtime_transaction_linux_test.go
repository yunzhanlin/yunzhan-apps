//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestApacheRuntimeCommittedHistoryRemainsReadableAndAllowsNextConfigurationWithoutRewritingOriginal(t *testing.T) {
	s, tx, path, _ := apacheHistoryFixture(t)
	tx.Changes[0].OldData = []byte("# managed by panel\nServerRoot \"/opt/panel/runtimes/apache/2.4.68\"\n")
	tx.Changes[0].NextData = []byte("# managed by panel\nServerRoot \"/opt/panel/runtimes/apache/2.4.71\"\n")
	tx.Digests[tx.Changes[0].Path+":old"] = core.Hash(string(tx.Changes[0].OldData))
	tx.Digests[tx.Changes[0].Path+":next"] = core.Hash(string(tx.Changes[0].NextData))
	tx.ApacheRuntime = &apacheRuntimeTransition{JobID: core.ID(), PreviousID: runtimecatalog.ApacheLegacyID, NextID: runtimecatalog.ApacheCurrentID, ApplyOwner: &moduleApplyOwner{PID: 2, StartTime: 3}, BootID: "01234567-89ab-cdef-0123-456789abcdef"}
	if err := wafWriteTransaction(path, tx); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	fresh := New(s.Config).apacheWAFTransactionService()
	fresh.Config.Run = s.Config.Run
	inv, err := fresh.apacheWAFHistoryInventory(context.Background())
	if err != nil || inv.Active != 1 || len(inv.Rows) != 1 || inv.Rows[0].ID != tx.ID {
		t.Fatal("the genuine committed runtime journal blocked following configuration", inv, err)
	}
	next := tx
	next.ID = core.ID()
	next.State = "applying"
	next.ApacheRuntime = nil
	if err := fresh.apacheWAFReserveTransaction(context.Background(), next); err != nil {
		t.Fatal("original runtime metadata blocked a later ordinary WAF operation", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	a := before.Sys().(*syscall.Stat_t)
	b := after.Sys().(*syscall.Stat_t)
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, actual) || a.Uid != b.Uid || a.Gid != b.Gid || a.Ino != b.Ino || before.Mode() != after.Mode() {
		t.Fatal("history compatibility rewrote original data or owner", err)
	}
	if _, err = fresh.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, raw)); err != nil {
		t.Fatal("original runtime journal cannot use normal digest-bound history archive", err)
	}
	moved, err := os.ReadFile(filepath.Join(fresh.apacheWAFArchiveDir(), tx.ID+".json"))
	if err != nil || !bytes.Equal(moved, raw) {
		t.Fatal("archived runtime journal changed", err)
	}
}

func TestApacheRuntimeHistoryMetadataRetainsStrictFieldsAndNestedOwnership(t *testing.T) {
	s, tx := apacheRuntimeJournalFixture(t)
	raw, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var parsed wafTransaction
	if err = decodeApacheWAFHistoryJSON(raw, &parsed); err != nil || s.wafTransactionContract(parsed) != nil {
		t.Fatal("valid journal rejected", err)
	}
	bad := []string{
		strings.Replace(string(raw), "\"apache_runtime\":{", "\"Apache_Runtime\":{", 1),
		strings.Replace(string(raw), "\"job_id\":", "\"Job_ID\":", 1),
		strings.Replace(string(raw), "\"pid\":2", "\"PID\":2", 1),
		strings.Replace(string(raw), "\"pid\":2", "\"pid\":2,\"pid\":2", 1),
		strings.Replace(string(raw), "\"pid\":2", "\"pid\":2,\"future\":true", 1),
		strings.Replace(string(raw), "\"boot_id\":", "\"future_boot_id\":", 1),
		strings.Replace(string(raw), "\"start_time\":3", "\"start_time\":3,\"old_owner\":{}", 1),
	}
	for i, value := range bad {
		var out wafTransaction
		if value == string(raw) || decodeApacheWAFHistoryJSON([]byte(value), &out) == nil {
			t.Fatalf("invalid runtime metadata accepted case=%d", i)
		}
	}
}
