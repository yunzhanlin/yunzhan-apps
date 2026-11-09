package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestProgramQueueOriginalRefusalDiagnosticIsBoundedPureAndDoesNotChangeError(t *testing.T) {
	message := "native program operation is active, failed or transitional; upgrade refused"
	e := &programQueueNativeRefusal{message: message, observation: programQueueNativeObservation{Format: 1, Kind: "native-program-unit-refusal-v1", Unit: "panel-mysql-overwrite-recovery.service", LoadState: "loaded", ActiveState: "activating", SubState: "start", InventorySHA: strings.Repeat("a", 64)}}
	text := ProgramUpgradeQueueFailureText(e)
	parts := strings.Split(text, "\n")
	if len(parts) != 2 || parts[0] != message || e.Error() != message || len(text) > 1200 {
		t.Fatal("original refusal changed", text)
	}
	var m map[string]any
	if json.Unmarshal([]byte(parts[1]), &m) != nil || len(m) != 7 || m["unit"] != e.observation.Unit || m["active_state"] != "activating" || m["inventory_sha256"] != e.observation.InventorySHA {
		t.Fatal("original closed observation missing", text)
	}
	if ProgramUpgradeQueueFailureText(errors.New(message)) != message || ProgramUpgradeQueueFailureText(nil) != "" {
		t.Fatal("unknown error changed")
	}
	wrapped := fmt.Errorf("unrecognized wrapper: %w", e)
	if ProgramUpgradeQueueFailureText(wrapped) != wrapped.Error() {
		t.Fatal("borrowed outer error authority")
	}
	for _, fault := range []string{"unit", "state", "digest", "kind", "format", "mixed"} {
		copy := *e
		switch fault {
		case "unit":
			copy.observation.Unit = "/etc/private"
		case "state":
			copy.observation.ActiveState = "active\nsecret"
		case "digest":
			copy.observation.InventorySHA = "caller-digest"
		case "kind":
			copy.observation.Kind = "future"
		case "format":
			copy.observation.Format = 2
		case "mixed":
			copy.observation.JobID = "1"
		}
		if ProgramUpgradeQueueFailureText(&copy) != message {
			t.Fatal("malformed diagnostic was serialized", fault)
		}
	}
}

func TestProgramQueueOriginalQueuedJobDiagnosticCannotBorrowUnitStateOrNoncanonicalID(t *testing.T) {
	e := &programQueueNativeRefusal{message: "native program operation is queued; upgrade refused", observation: programQueueNativeObservation{Format: 1, Kind: "native-program-job-refusal-v1", Unit: "panel-mysql-overwrite-recovery.service", JobID: "538093", JobType: "start", JobState: "running", InventorySHA: strings.Repeat("b", 64)}}
	parts := strings.Split(ProgramUpgradeQueueFailureText(e), "\n")
	if len(parts) != 2 {
		t.Fatal("original job observation missing")
	}
	var m map[string]any
	if json.Unmarshal([]byte(parts[1]), &m) != nil || len(m) != 7 || m["job_id"] != "538093" || m["job_state"] != "running" {
		t.Fatal("wrong original job capture")
	}
	for _, id := range []string{"0", "01", "-1", "18446744073709551616"} {
		copy := *e
		copy.observation.JobID = id
		if ProgramUpgradeQueueFailureText(&copy) != e.message {
			t.Fatal("noncanonical job ID", id)
		}
	}
	copy := *e
	copy.observation.LoadState = "loaded"
	if ProgramUpgradeQueueFailureText(&copy) != e.message {
		t.Fatal("mixed unit/job state")
	}
}
