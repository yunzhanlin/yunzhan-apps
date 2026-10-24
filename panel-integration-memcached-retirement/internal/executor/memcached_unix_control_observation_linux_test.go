//go:build linux

package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func memcachedUnixControlObservationFixture(t *testing.T, saveUnknown bool) (*memcachedUnixControlJournal, *memcachedUnixControlLease, memcachedUnixControlSeed) {
	t.Helper()
	store, seed := memcachedUnixControlJournalFixture(t)
	j, fresh, err := store.prepare(seed)
	if err != nil || !fresh {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	lease, err := j.lease()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Close)
	seedRaw, _ := json.Marshal(seed)
	issued := memcachedUnixControlIssued{Format: 1, SeedSHA256: core.Hash(string(seedRaw)), ContainerID: strings.Repeat("c", 64), InitialPID: 789, InitialStartedAt: "2026-10-24T00:00:00Z"}
	if err := lease.issued(issued); err != nil {
		t.Fatal(err)
	}
	if saveUnknown {
		if err := lease.finish(memcachedUnixControlBaseResult(seed.Operation, "unknown")); err != nil {
			t.Fatal(err)
		}
	}
	return j, lease, seed
}
func memcachedUnixControlObservedResult(seed memcachedUnixControlSeed) core.MemcachedUnixControlResult {
	v := memcachedUnixControlBaseResult(seed.Operation, "observed")
	v.FinalState = "running"
	v.RuntimeSHA256 = strings.Repeat("e", 64)
	v.ReviewerID = strings.Repeat("f", 32)
	v.ObservedAt = "2026-10-24T12:00:00Z"
	return v
}
func TestMemcachedUnixControlObservationAppendsWithoutRewritingUnknownOrMissingResult(t *testing.T) {
	for _, saved := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-original-result", true: "unknown-original-result"}[saved], func(t *testing.T) {
			j, lease, seed := memcachedUnixControlObservationFixture(t, saved)
			before, err := j.inventory()
			if err != nil {
				t.Fatal(err)
			}
			originalBytes := map[string][]byte{}
			for n := range before {
				raw, err := os.ReadFile(filepath.Join(j.d.paths[len(j.d.paths)-1], n))
				if err != nil {
					t.Fatal(err)
				}
				originalBytes[n] = raw
			}
			result := memcachedUnixControlObservedResult(seed)
			if lease.finish(result) == nil {
				t.Fatal("observation overwrote the command result")
			}
			if err := lease.observe(result); err != nil {
				t.Fatal(err)
			}
			if lease.observe(result) == nil {
				t.Fatal("immutable observation was replaced")
			}
			after, err := j.inventory()
			if err != nil || len(after) != len(before)+1 {
				t.Fatal(err)
			}
			for n, info := range before {
				raw, err := os.ReadFile(filepath.Join(j.d.paths[len(j.d.paths)-1], n))
				if err != nil || string(raw) != string(originalBytes[n]) || !geoStoreStableInfo(info, after[n]) {
					t.Fatal("original command evidence changed", n, err)
				}
			}
			snap, err := j.read()
			if err != nil || snap.Observation == nil || snap.outcome() == nil || *snap.outcome() != result {
				t.Fatal("separate observed evidence lost", err)
			}
			if saved && (snap.Result == nil || snap.Result.State != "unknown") || !saved && snap.Result != nil {
				t.Fatal("unknown original rewritten or invented")
			}
			if lease.finish(memcachedUnixControlBaseResult(seed.Operation, "refused")) == nil {
				t.Fatal("append-only observation reset the old command")
			}
		})
	}
}
func TestMemcachedUnixControlObservationRejectsUnissuedTerminalBorrowedAndAmbiguousEvidence(t *testing.T) {
	j, _, seed := memcachedUnixControlObservationFixture(t, true)
	original, err := j.read()
	if err != nil {
		t.Fatal(err)
	}
	value := memcachedUnixControlObservation{Format: 1, SeedSHA256: memcachedUnixControlValueSHA(original.Seed), IssuedSHA256: memcachedUnixControlValueSHA(original.Issued), OriginalResultSHA256: memcachedUnixControlValueSHA(original.Result), Result: memcachedUnixControlObservedResult(seed)}
	raw, _ := json.Marshal(value)
	if _, err := decodeMemcachedUnixControlObservation(raw, original); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"unissued", "terminal-original", "existing-observation", "seed", "issued", "old-result", "reviewer", "masquerade", "alias", "duplicate", "extra", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			before := original
			changed := value
			wire := append([]byte(nil), raw...)
			switch kind {
			case "unissued":
				before.Issued = nil
			case "terminal-original":
				v := memcachedUnixControlBaseResult(seed.Operation, "refused")
				before.Result = &v
			case "existing-observation":
				before.Observation = &value
			case "seed":
				changed.SeedSHA256 = strings.Repeat("0", 64)
			case "issued":
				changed.IssuedSHA256 = strings.Repeat("0", 64)
			case "old-result":
				changed.OriginalResultSHA256 = strings.Repeat("0", 64)
			case "reviewer":
				changed.Result.ReviewerID = "root"
			case "masquerade":
				changed.Result.State = "completed"
				changed.Result.FinalState = "stopped"
			case "alias":
				wire = []byte(strings.Replace(string(wire), "\"seed_sha256\"", "\"Seed_SHA256\"", 1))
			case "duplicate":
				wire = append([]byte("{\"format\":1,"), wire[1:]...)
			case "extra":
				wire = append([]byte("{\"execute\":\"restart\","), wire[1:]...)
			case "trailing":
				wire = append(wire, '\n')
			}
			if kind != "alias" && kind != "duplicate" && kind != "extra" && kind != "trailing" {
				wire, _ = json.Marshal(changed)
			}
			if _, err := decodeMemcachedUnixControlObservation(wire, before); err == nil {
				t.Fatal("foreign observation accepted", kind)
			}
		})
	}
}
