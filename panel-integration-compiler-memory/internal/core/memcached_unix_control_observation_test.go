package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestMemcachedUnixControlObservationIsNotOriginalSuccessOrNativePermission(t *testing.T) {
	s, actor, op := memcachedUnixControlFixture(t)
	observed := MemcachedUnixControlResult{Format: 1, RequestID: op.RequestID, ProjectID: op.ProjectID, OperationSHA256: MemcachedUnixControlSHA(op), State: "observed", FinalState: "running", RuntimeSHA256: strings.Repeat("e", 64), ReviewerID: ID(), ObservedAt: "2026-10-24T12:00:00Z"}
	// The original stop's result stays unknown. Seeing running is a distinct
	// current-state observation, never a successful stop receipt.
	if ValidateMemcachedUnixControlResult(op, observed) != nil {
		t.Fatal("separate current-state observation refused")
	}
	for _, kind := range []string{"missing-reviewer", "bad-reviewer", "missing-stamp", "noncanonical-stamp", "old-stamp", "offset", "unknown-state", "missing-fingerprint", "completed-masquerade", "refused-masquerade", "unknown-masquerade"} {
		t.Run(kind, func(t *testing.T) {
			v := observed
			switch kind {
			case "missing-reviewer":
				v.ReviewerID = ""
			case "bad-reviewer":
				v.ReviewerID = "root"
			case "missing-stamp":
				v.ObservedAt = ""
			case "noncanonical-stamp":
				v.ObservedAt = "2026-10-24T12:00:00.000Z"
			case "old-stamp":
				v.ObservedAt = "2025-10-24T12:00:00Z"
			case "offset":
				v.ObservedAt = "2026-10-24T12:00:00+00:00"
			case "unknown-state":
				v.FinalState = "unknown"
			case "missing-fingerprint":
				v.RuntimeSHA256 = ""
			case "completed-masquerade":
				v.State = "completed"
				v.FinalState = "stopped"
			case "refused-masquerade":
				v.State = "refused"
				v.FinalState = ""
				v.RuntimeSHA256 = ""
			case "unknown-masquerade":
				v.State = "unknown"
				v.FinalState = ""
				v.RuntimeSHA256 = ""
			}
			if ValidateMemcachedUnixControlResult(op, v) == nil {
				t.Fatal("observation borrowed original success or omitted explicit evidence", kind)
			}
		})
	}
	ctx := context.Background()
	if _, fresh, err := s.reserveMemcachedUnixControl(ctx, op); err != nil || !fresh {
		t.Fatal(err)
	}
	if err := s.finishMemcachedUnixControl(ctx, op, nil); err != nil {
		t.Fatal(err)
	}
	// Persistence framing only. A real handler must obtain this independently
	// from the verified original Root observation, never a browser body.
	if err := s.finishMemcachedUnixControlReview(ctx, actor.ID, op, observed); err != nil {
		t.Fatal(err)
	}
	row, fresh, err := s.reserveMemcachedUnixControl(ctx, op)
	if err != nil || fresh || row.Result == nil || *row.Result != observed || row.State != "completed" {
		t.Fatal("original reservation was redispatched", err)
	}
	if s.CheckMemcachedUnixControl(ctx, op) == nil {
		t.Fatal("observed original became a new native-command grant")
	}
	raw, _ := json.Marshal(row.Result)
	if strings.Contains(string(raw), "\"state\":\"completed\"") {
		t.Fatal("unknown native result relabelled as a completed command")
	}
	if _, _, err := s.memcachedUnixControlForActor(ctx, actor.ID, op.RequestID); err != nil {
		t.Fatal(err)
	}
}
