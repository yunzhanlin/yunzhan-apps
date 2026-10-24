package core

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func memcachedTransactionFixture(t *testing.T) MemcachedUpdateRecord {
	t.Helper()
	target, _, plan := memcachedPlanFixture(t)
	dispatch := MemcachedUpdateDispatch{Format: 1, JobID: strings.Repeat("1", 32), RequestID: strings.Repeat("2", 32), ActorID: strings.Repeat("3", 32), AccessRevision: "1", ProjectID: plan.ProjectID, Input: MemcachedUpdateInput{ExpectedVersion: appcatalog.MemcachedDigestVersion, ExpectedSHA256: strings.Repeat("4", 64), ExpectedProjectSHA256: plan.ProjectSHA256, AcknowledgeCacheLoss: true}}
	record, err := SealMemcachedUpdateRecord(MemcachedUpdateRecord{Format: 1, Dispatch: dispatch, DispatchSHA256: MemcachedUpdateDispatchSHA(dispatch), Plan: plan, EnvelopeSHA256: strings.Repeat("5", 64), CatalogSHA256: strings.Repeat("6", 64), TargetComposeSHA256: Hash(target), Phase: "prepared"})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func memcachedTransactionNext(t *testing.T, before MemcachedUpdateRecord, phase string) MemcachedUpdateRecord {
	t.Helper()
	out := before
	out.Sequence++
	out.PreviousSHA256 = before.RecordSHA256
	out.Phase = phase
	switch phase {
	case "image_verified":
		out.TargetImageID = "sha256:" + strings.Repeat("7", 64)
	case "applied":
		out.Observation = MemcachedUpdateObservation{ContainerID: strings.Repeat("8", 64), ImageID: out.TargetImageID, ComposeSHA256: out.TargetComposeSHA256, RuntimeConfigSHA256: strings.Repeat("9", 64), Health: "healthy"}
	case "rollback_started":
		out.Reason = "target_unhealthy"
	case "rolled_back":
		// Recreating an old container changes its ID and full static runtime
		// fingerprint. Never claim that the old process or cache was restored.
		out.Observation = MemcachedUpdateObservation{ContainerID: strings.Repeat("a", 64), ImageID: out.Plan.RuntimeImageID, ComposeSHA256: out.Plan.RollbackComposeSHA256, RuntimeConfigSHA256: strings.Repeat("b", 64), Health: "healthy"}
	case "failed_safe":
		out.Reason = "precondition_changed"
	case "needs_attention":
		out.Reason = "interrupted"
	}
	var err error
	out, err = SealMemcachedUpdateRecord(out)
	if err != nil {
		t.Fatal("test fixture phase shape", phase, err)
	}
	return out
}

func TestMemcachedTransactionBindsEveryOriginalDispatchField(t *testing.T) {
	original := memcachedTransactionFixture(t).Dispatch
	digest := MemcachedUpdateDispatchSHA(original)
	if !registryDigestValid(digest) {
		t.Fatal("dispatch digest missing")
	}
	for _, scenario := range []string{"actor", "access-revision", "job", "request", "project", "app-hash", "project-hash"} {
		t.Run(scenario, func(t *testing.T) {
			in := original
			switch scenario {
			case "actor":
				in.ActorID = strings.Repeat("a", 32)
			case "access-revision":
				in.AccessRevision = "2"
			case "job":
				in.JobID = strings.Repeat("b", 32)
			case "request":
				in.RequestID = strings.Repeat("c", 32)
			case "project":
				in.ProjectID = strings.Repeat("d", 32)
			case "app-hash":
				in.Input.ExpectedSHA256 = strings.Repeat("e", 64)
			case "project-hash":
				in.Input.ExpectedProjectSHA256 = strings.Repeat("f", 64)
			}
			if ValidateMemcachedUpdateDispatch(in) != nil || MemcachedUpdateDispatchSHA(in) == digest {
				t.Fatal("dispatch borrowed original identity")
			}
		})
	}
	for _, scenario := range []string{"empty", "format", "old-app", "future-app", "version-alias", "uppercase-id", "path", "missing-ack", "uppercase-hash", "short-hash", "zero-revision", "alias-revision", "negative-revision", "overflow-revision"} {
		t.Run(scenario, func(t *testing.T) {
			in := original
			switch scenario {
			case "empty":
				in = MemcachedUpdateDispatch{}
			case "format":
				in.Format = 2
			case "old-app":
				in.Input.ExpectedVersion = "1.6.45-compat1"
			case "future-app":
				in.Input.ExpectedVersion = "1.6.45-compat3"
			case "version-alias":
				in.Input.ExpectedVersion = "1.6.45-compat02"
			case "uppercase-id":
				in.ActorID = strings.Repeat("A", 32)
			case "path":
				in.ProjectID = "../../different-project"
			case "missing-ack":
				in.Input.AcknowledgeCacheLoss = false
			case "uppercase-hash":
				in.Input.ExpectedSHA256 = strings.Repeat("A", 64)
			case "short-hash":
				in.Input.ExpectedProjectSHA256 = "0123"
			case "zero-revision":
				in.AccessRevision = "0"
			case "alias-revision":
				in.AccessRevision = "01"
			case "negative-revision":
				in.AccessRevision = "-1"
			case "overflow-revision":
				in.AccessRevision = "9223372036854775808"
			}
			if ValidateMemcachedUpdateDispatch(in) == nil || MemcachedUpdateDispatchSHA(in) != "" {
				t.Fatal("invalid dispatch acquired identity")
			}
		})
	}
}

func TestMemcachedTransactionCompleteAndRollbackChainsPreserveOriginalEvidence(t *testing.T) {
	for _, rollbackAfter := range []string{"never", "apply_started", "applied"} {
		t.Run(rollbackAfter, func(t *testing.T) {
			first := memcachedTransactionFixture(t)
			current := first
			phases := []string{"pull_started", "image_verified", "apply_started", "applied", "committed"}
			if rollbackAfter == "apply_started" {
				phases = []string{"pull_started", "image_verified", "apply_started", "rollback_started", "rolled_back"}
			} else if rollbackAfter == "applied" {
				phases = []string{"pull_started", "image_verified", "apply_started", "applied", "rollback_started", "rolled_back"}
			}
			for _, phase := range phases {
				next := memcachedTransactionNext(t, current, phase)
				if err := ValidateMemcachedUpdateTransition(current, next); err != nil {
					t.Fatal(current.Phase, phase, err)
				}
				raw, err := json.Marshal(next)
				decoded, de := DecodeMemcachedUpdateRecord(raw)
				if err != nil || de != nil || decoded != next || next.Dispatch != first.Dispatch || next.Plan != first.Plan {
					t.Fatal("canonical roundtrip or original immutable binding changed", err, de)
				}
				current = next
			}
			if rollbackAfter != "never" && (current.Observation.ContainerID == first.Plan.ContainerID || current.Observation.RuntimeConfigSHA256 == first.Plan.RuntimeConfigSHA256 || current.Observation.ImageID != first.Plan.RuntimeImageID || current.Observation.ComposeSHA256 != first.Plan.RollbackComposeSHA256) {
				t.Fatal("rollback pretended original process/cache was restored or did not pin the original image")
			}
		})
	}
}

func TestMemcachedTransactionCannotSkipSafetyStagesReplayOrRewriteTerminal(t *testing.T) {
	prepared := memcachedTransactionFixture(t)
	pull := memcachedTransactionNext(t, prepared, "pull_started")
	image := memcachedTransactionNext(t, pull, "image_verified")
	apply := memcachedTransactionNext(t, image, "apply_started")
	applied := memcachedTransactionNext(t, apply, "applied")
	committed := memcachedTransactionNext(t, applied, "committed")
	rollback := memcachedTransactionNext(t, apply, "rollback_started")
	rolledBack := memcachedTransactionNext(t, rollback, "rolled_back")
	failed := memcachedTransactionNext(t, image, "failed_safe")
	uncertain := memcachedTransactionNext(t, apply, "needs_attention")
	for _, before := range []MemcachedUpdateRecord{committed, rolledBack, failed, uncertain} {
		for _, prototype := range []MemcachedUpdateRecord{prepared, pull, image, apply, applied, committed, rollback, rolledBack, failed, uncertain} {
			t.Run(before.Phase+"/"+prototype.Phase, func(t *testing.T) {
				next := prototype
				next.Sequence, next.PreviousSHA256 = before.Sequence+1, before.RecordSHA256
				next.RecordSHA256 = memcachedRecordSHA(next)
				if ValidateMemcachedUpdateTransition(before, next) == nil {
					t.Fatal("terminal or uncertain transaction resumed, retried or rewritten")
				}
			})
		}
	}
	for _, pair := range [][2]MemcachedUpdateRecord{{prepared, applied}, {pull, apply}, {image, committed}, {apply, committed}, {apply, failed}, {rollback, committed}, {applied, image}, {image, pull}} {
		next := pair[1]
		next.Sequence, next.PreviousSHA256 = pair[0].Sequence+1, pair[0].RecordSHA256
		next.RecordSHA256 = memcachedRecordSHA(next)
		if ValidateMemcachedUpdateTransition(pair[0], next) == nil {
			t.Fatal("unsafe stage skip or regression accepted", pair[0].Phase, next.Phase)
		}
	}
}

func TestMemcachedTransactionTransitionCannotRebindOriginalOrInventResults(t *testing.T) {
	before := memcachedTransactionFixture(t)
	for _, scenario := range []string{"actor", "access-revision", "job", "request", "project", "version", "app-hash", "project-hash", "ack", "dispatch-hash", "plan", "envelope", "catalog", "target-config", "sequence", "previous", "record-hash", "early-image", "early-health", "unexpected-error"} {
		t.Run(scenario, func(t *testing.T) {
			next := memcachedTransactionNext(t, before, "pull_started")
			switch scenario {
			case "actor":
				next.Dispatch.ActorID = strings.Repeat("a", 32)
			case "access-revision":
				next.Dispatch.AccessRevision = "2"
			case "job":
				next.Dispatch.JobID = strings.Repeat("b", 32)
			case "request":
				next.Dispatch.RequestID = strings.Repeat("c", 32)
			case "project":
				next.Dispatch.ProjectID = strings.Repeat("d", 32)
			case "version":
				next.Dispatch.Input.ExpectedVersion = "1.6.45-compat3"
			case "app-hash":
				next.Dispatch.Input.ExpectedSHA256 = strings.Repeat("e", 64)
			case "project-hash":
				next.Dispatch.Input.ExpectedProjectSHA256 = strings.Repeat("f", 64)
			case "ack":
				next.Dispatch.Input.AcknowledgeCacheLoss = false
			case "dispatch-hash":
				next.DispatchSHA256 = strings.Repeat("a", 64)
			case "plan":
				next.Plan.RuntimeConfigSHA256 = strings.Repeat("b", 64)
			case "envelope":
				next.EnvelopeSHA256 = strings.Repeat("c", 64)
			case "catalog":
				next.CatalogSHA256 = strings.Repeat("d", 64)
			case "target-config":
				next.TargetComposeSHA256 = next.Plan.ComposeSHA256
			case "sequence":
				next.Sequence++
			case "previous":
				next.PreviousSHA256 = strings.Repeat("e", 64)
			case "early-image":
				next.TargetImageID = "sha256:" + strings.Repeat("a", 64)
			case "early-health":
				next.Observation.Health = "healthy"
			case "unexpected-error":
				next.Reason = "arbitrary secret or raw Docker error"
			}
			if scenario != "dispatch-hash" {
				next.DispatchSHA256 = MemcachedUpdateDispatchSHA(next.Dispatch)
			}
			next.RecordSHA256 = memcachedRecordSHA(next)
			if scenario == "record-hash" {
				next.RecordSHA256 = strings.Repeat("e", 64)
			}
			if ValidateMemcachedUpdateTransition(before, next) == nil {
				t.Fatal("original request or safety stage rebound", scenario)
			}
		})
	}
}

func TestMemcachedTransactionPrivateRecordRefusesAmbiguousAndNoncanonicalJSON(t *testing.T) {
	in := memcachedTransactionFixture(t)
	wire, _ := json.Marshal(in)
	for _, scenario := range []string{"duplicate", "escaped-duplicate", "case-alias", "unknown", "null", "trailing", "whitespace", "reordered", "over-budget", "bad-hash", "invalid-utf8"} {
		t.Run(scenario, func(t *testing.T) {
			raw := append([]byte(nil), wire...)
			switch scenario {
			case "duplicate":
				raw = append([]byte(`{"format":1,`), raw[1:]...)
			case "escaped-duplicate":
				raw = append([]byte(`{"for\u006dat":1,`), raw[1:]...)
			case "case-alias":
				raw = bytes.Replace(raw, []byte(`"format":1`), []byte(`"FORMAT":1`), 1)
			case "unknown":
				raw = append([]byte(`{"verified":true,`), raw[1:]...)
			case "null":
				raw = bytes.Replace(raw, []byte(`"reason":""`), []byte(`"reason":null`), 1)
			case "trailing":
				raw = append(raw, []byte("{}")...)
			case "whitespace":
				raw = append(raw, '\n')
			case "reordered":
				var fields map[string]json.RawMessage
				json.Unmarshal(raw, &fields)
				raw, _ = json.Marshal(fields)
			case "over-budget":
				raw = bytes.Repeat([]byte(" "), MaxMemcachedUpdateRecordBytes+1)
			case "bad-hash":
				raw = bytes.Replace(raw, []byte(in.RecordSHA256), []byte(strings.Repeat("a", 64)), 1)
			case "invalid-utf8":
				raw = append([]byte(`{"unknown":"`), 0xff, '"', '}')
			}
			if _, err := DecodeMemcachedUpdateRecord(raw); err == nil {
				t.Fatal("ambiguous private journal record adopted", scenario)
			}
		})
	}
}

func TestMemcachedTransactionClosedClientInputRequiresActualCacheLossAcknowledgment(t *testing.T) {
	input := memcachedTransactionFixture(t).Dispatch.Input
	wire, _ := json.Marshal(input)
	decoded, err := DecodeMemcachedUpdateInput(append([]byte(" \n"), append(wire, '\n')...))
	if err != nil || decoded != input {
		t.Fatal("closed complete user input", err)
	}
	for _, scenario := range []string{"duplicate", "escaped-duplicate", "case-alias", "actor-injection", "image-injection", "verified-injection", "missing", "null", "null-ack", "false-ack", "string-ack", "wrong-version", "bad-sha", "old-project", "array", "trailing", "over-budget"} {
		t.Run(scenario, func(t *testing.T) {
			raw := append([]byte(nil), wire...)
			switch scenario {
			case "duplicate":
				raw = append([]byte(`{"acknowledge_cache_loss":false,`), raw[1:]...)
			case "escaped-duplicate":
				raw = append([]byte(`{"acknowledge\u005fcache_loss":false,`), raw[1:]...)
			case "case-alias":
				raw = bytes.Replace(raw, []byte(`"expected_version":`), []byte(`"Expected_Version":`), 1)
			case "actor-injection":
				raw = append([]byte(`{"actor_id":"`+strings.Repeat("a", 32)+`",`), raw[1:]...)
			case "image-injection":
				raw = append([]byte(`{"image":"memcached:latest",`), raw[1:]...)
			case "verified-injection":
				raw = append([]byte(`{"verified":true,`), raw[1:]...)
			case "missing":
				raw = []byte(`{"expected_version":"1.6.45-compat2"}`)
			case "null":
				raw = bytes.Replace(raw, []byte(`"expected_version":"1.6.45-compat2"`), []byte(`"expected_version":null`), 1)
			case "null-ack":
				raw = bytes.Replace(raw, []byte(`"acknowledge_cache_loss":true`), []byte(`"acknowledge_cache_loss":null`), 1)
			case "false-ack":
				raw = bytes.Replace(raw, []byte(`"acknowledge_cache_loss":true`), []byte(`"acknowledge_cache_loss":false`), 1)
			case "string-ack":
				raw = bytes.Replace(raw, []byte(`"acknowledge_cache_loss":true`), []byte(`"acknowledge_cache_loss":"true"`), 1)
			case "wrong-version":
				raw = bytes.Replace(raw, []byte("compat2"), []byte("compat1"), 1)
			case "bad-sha":
				raw = bytes.Replace(raw, []byte(input.ExpectedSHA256), []byte(strings.Repeat("A", 64)), 1)
			case "old-project":
				raw = bytes.Replace(raw, []byte(input.ExpectedProjectSHA256), []byte("old"), 1)
			case "array":
				raw = []byte("[]")
			case "trailing":
				raw = append(raw, []byte("{}")...)
			case "over-budget":
				raw = bytes.Repeat([]byte(" "), MaxMemcachedUpdateInputBytes+1)
			}
			if _, err := DecodeMemcachedUpdateInput(raw); err == nil {
				t.Fatal("unbound or ambiguous update input accepted", scenario)
			}
		})
	}
}
