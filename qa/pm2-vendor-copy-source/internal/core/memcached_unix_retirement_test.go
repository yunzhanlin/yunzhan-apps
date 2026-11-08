package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMemcachedUnixRetirementRequiresSeparateConfirmationAndKeepsOldWire(t *testing.T) {
	old := MemcachedUnixControlOperation{Format: 1, RequestID: strings.Repeat("a", 32), ProjectID: strings.Repeat("b", 32), ActorID: strings.Repeat("c", 32), Input: MemcachedUnixControlInput{Action: "stop", ExpectedRuntimeSHA256: strings.Repeat("d", 64), AcknowledgeCacheLoss: true}}
	raw, _ := json.Marshal(old)
	want := "{\"format\":1,\"request_id\":\"" + old.RequestID + "\",\"project_id\":\"" + old.ProjectID + "\",\"actor_id\":\"" + old.ActorID + "\",\"input\":{\"action\":\"stop\",\"expected_runtime_sha256\":\"" + old.Input.ExpectedRuntimeSHA256 + "\",\"acknowledge_cache_loss\":true}}"
	if string(raw) != want {
		t.Fatal("old command canonical bytes changed", string(raw))
	}
	retire := old
	retire.Input.Action = "retire"
	retire.Input.AcknowledgeCacheLoss = false
	retire.Input.AcknowledgeRemoval = true
	retire.Input.ConfirmName = "own-cache"
	if ValidateMemcachedUnixControlOperation(retire) != nil {
		t.Fatal("explicit stopped-instance retirement framing refused")
	}
	encoded, _ := json.Marshal(retire)
	decoded, e := DecodeMemcachedUnixControlOperation(encoded)
	if e != nil || decoded != retire {
		t.Fatal("retirement canonical framing lost", e)
	}
	for name, change := range map[string]func(*MemcachedUnixControlOperation){
		"no-removal-ack":                func(v *MemcachedUnixControlOperation) { v.Input.AcknowledgeRemoval = false },
		"cache-loss-ack-is-not-removal": func(v *MemcachedUnixControlOperation) { v.Input.AcknowledgeCacheLoss = true },
		"missing-name":                  func(v *MemcachedUnixControlOperation) { v.Input.ConfirmName = "" },
		"name-whitespace":               func(v *MemcachedUnixControlOperation) { v.Input.ConfirmName = " own-cache " },
		"name-path":                     func(v *MemcachedUnixControlOperation) { v.Input.ConfirmName = "../cache" },
		"long-name":                     func(v *MemcachedUnixControlOperation) { v.Input.ConfirmName = strings.Repeat("a", 41) },
		"start-cannot-borrow-ack":       func(v *MemcachedUnixControlOperation) { v.Input.Action = "start" },
		"stop-cannot-borrow-ack":        func(v *MemcachedUnixControlOperation) { v.Input.Action = "stop"; v.Input.AcknowledgeCacheLoss = true },
	} {
		t.Run(name, func(t *testing.T) {
			v := retire
			change(&v)
			if ValidateMemcachedUnixControlOperation(v) == nil {
				t.Fatal("unconfirmed or cross-command retirement accepted")
			}
		})
	}
	for _, action := range []string{"start", "stop", "restart"} {
		v := old
		v.Input.Action = action
		v.Input.AcknowledgeCacheLoss = action != "start"
		if ValidateMemcachedUnixControlOperation(v) != nil {
			t.Fatal("existing command refused", action)
		}
	}
}

func TestMemcachedUnixRetirementOutcomeCannotBeBorrowedByOtherCommands(t *testing.T) {
	op := MemcachedUnixControlOperation{Format: 1, RequestID: strings.Repeat("a", 32), ProjectID: strings.Repeat("b", 32), ActorID: strings.Repeat("c", 32), Input: MemcachedUnixControlInput{Action: "retire", ExpectedRuntimeSHA256: strings.Repeat("d", 64), AcknowledgeRemoval: true, ConfirmName: "own-cache"}}
	result := MemcachedUnixControlResult{Format: 1, RequestID: op.RequestID, ProjectID: op.ProjectID, OperationSHA256: MemcachedUnixControlSHA(op), State: "completed", FinalState: "retired", RuntimeSHA256: strings.Repeat("e", 64)}
	if ValidateMemcachedUnixControlResult(op, result) != nil {
		t.Fatal("exact original retirement outcome refused")
	}
	for _, state := range []string{"running", "stopped", "absent", "removed", "healthy"} {
		v := result
		v.FinalState = state
		if ValidateMemcachedUnixControlResult(op, v) == nil {
			t.Fatal("retirement claimed wrong final state", state)
		}
	}
	observed := result
	observed.State = "observed"
	observed.ReviewerID = strings.Repeat("f", 32)
	observed.ObservedAt = "2026-10-25T00:00:00Z"
	if ValidateMemcachedUnixControlResult(op, observed) != nil {
		t.Fatal("separate acknowledged observation refused")
	}
	for _, action := range []string{"start", "stop", "restart"} {
		v := op
		v.Input.Action = action
		v.Input.AcknowledgeRemoval = false
		v.Input.ConfirmName = ""
		v.Input.AcknowledgeCacheLoss = action != "start"
		for _, state := range []string{"completed", "observed"} {
			r := result
			r.OperationSHA256 = MemcachedUnixControlSHA(v)
			r.State = state
			if state == "observed" {
				r.ReviewerID = observed.ReviewerID
				r.ObservedAt = observed.ObservedAt
			}
			if ValidateMemcachedUnixControlResult(v, r) == nil {
				t.Fatal("old command borrowed retirement", action, state)
			}
		}
	}
	for _, state := range []string{"running", "stopped"} {
		v := observed
		v.FinalState = state
		if ValidateMemcachedUnixControlResult(op, v) != nil {
			t.Fatal("unknown removal observation cannot report a still-existing original container", state)
		}
	}
}
