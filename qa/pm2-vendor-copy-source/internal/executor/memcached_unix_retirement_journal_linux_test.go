//go:build linux

package executor

import (
	"encoding/json"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestMemcachedUnixRetirementReceiptIsNotADeadContainerGuess(t *testing.T) {
	seed, issued := retirementAbsenceFixture()
	result := memcachedUnixControlBaseResult(seed.Operation, "completed")
	result.FinalState = "retired"
	var err error
	result.RuntimeSHA256, err = memcachedUnixRetirementFingerprint(seed, issued)
	if err != nil {
		t.Fatal(err)
	}
	original := memcachedUnixControlSnapshot{Seed: seed, Issued: &issued, Result: &result}
	matches := func(v memcachedUnixControlSnapshot) bool {
		return memcachedUnixControlIsRetirement(v, seed.Operation.ProjectID, seed.InstalledRecordSHA256, issued.ContainerID, seed.Operation.Input.ConfirmName)
	}
	if !matches(original) {
		t.Fatal("complete original retirement framing refused")
	}
	for _, kind := range []string{"missing", "unknown", "refused", "running", "stopped", "wrong-project", "wrong-install", "wrong-CID", "wrong-name", "running-original", "no-issued", "foreign-operation", "unbound-issued", "foreign-fingerprint", "invalid-original-time"} {
		t.Run(kind, func(t *testing.T) {
			raw, _ := json.Marshal(original)
			var v memcachedUnixControlSnapshot
			if json.Unmarshal(raw, &v) != nil {
				t.Fatal("fixture")
			}
			switch kind {
			case "missing":
				v.Result = nil
			case "unknown":
				v.Result = ptrRetireResult(memcachedUnixControlBaseResult(seed.Operation, "unknown"))
			case "refused":
				v.Result = ptrRetireResult(memcachedUnixControlBaseResult(seed.Operation, "refused"))
			case "running", "stopped":
				v.Result.FinalState = kind
			case "wrong-project":
				v.Seed.Operation.ProjectID = strings.Repeat("9", 32)
			case "wrong-install":
				v.Seed.InstalledRecordSHA256 = strings.Repeat("9", 64)
			case "wrong-CID":
				v.Issued.ContainerID = strings.Repeat("9", 64)
			case "wrong-name":
				v.Seed.Operation.Input.ConfirmName = "other"
			case "running-original":
				v.Issued.InitialPID = 123
			case "no-issued":
				v.Issued = nil
			case "foreign-operation":
				v.Result.OperationSHA256 = strings.Repeat("9", 64)
			case "unbound-issued":
				v.Issued.SeedSHA256 = strings.Repeat("9", 64)
			case "foreign-fingerprint":
				v.Result.RuntimeSHA256 = strings.Repeat("9", 64)
			case "invalid-original-time":
				v.Issued.InitialStartedAt = "not-a-time"
			}
			if matches(v) {
				t.Fatal("unverified retirement borrowed another result", kind)
			}
		})
	}
	unknown := memcachedUnixControlBaseResult(seed.Operation, "unknown")
	observed := result
	observed.State = "observed"
	observed.ReviewerID = strings.Repeat("2", 32)
	observed.ObservedAt = "2026-10-25T00:00:00Z"
	raw, _ := json.Marshal(seed)
	issuedRaw, _ := json.Marshal(issued)
	unknownRaw, _ := json.Marshal(&unknown)
	observation := memcachedUnixControlObservation{Format: 1, SeedSHA256: core.Hash(string(raw)), IssuedSHA256: core.Hash(string(issuedRaw)), OriginalResultSHA256: core.Hash(string(unknownRaw)), Result: observed}
	v := memcachedUnixControlSnapshot{Seed: seed, Issued: &issued, Result: &unknown, Observation: &observation}
	if !matches(v) || v.Result.State != "unknown" {
		t.Fatal("independent observation overwrote original unknown or was ignored")
	}
	v.Observation.SeedSHA256 = strings.Repeat("9", 64)
	if matches(v) {
		t.Fatal("a foreign observation authorized retirement")
	}
}
func ptrRetireResult(v core.MemcachedUnixControlResult) *core.MemcachedUnixControlResult { return &v }
