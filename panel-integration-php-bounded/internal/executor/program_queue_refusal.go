package executor

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
)

// Observations are diagnostic data, never authority to close, reset or skip a
// queue. Error() stays byte-compatible with the existing fail-closed contract.
type programQueueNativeObservation struct {
	Format       int    `json:"format"`
	Kind         string `json:"kind"`
	Unit         string `json:"unit"`
	LoadState    string `json:"load_state,omitempty"`
	ActiveState  string `json:"active_state,omitempty"`
	SubState     string `json:"sub_state,omitempty"`
	JobID        string `json:"job_id,omitempty"`
	JobType      string `json:"job_type,omitempty"`
	JobState     string `json:"job_state,omitempty"`
	InventorySHA string `json:"inventory_sha256"`
}
type programQueueNativeRefusal struct {
	message     string
	observation programQueueNativeObservation
}

func (e *programQueueNativeRefusal) Error() string { return e.message }

var programQueueDiagnosticUnit = regexp.MustCompile(`^panel-[a-z0-9@_.-]{1,127}\.(service|scope)$`)
var programQueueDiagnosticState = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
var programQueueDiagnosticSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ProgramUpgradeQueueFailureText appends ONLY the original rejected inventory
// identity. No command, filesystem access, reread, retry or state mutation occurs.
// The first line remains the original fixed message; unknown errors are unchanged.
func ProgramUpgradeQueueFailureText(err error) string {
	if err == nil {
		return ""
	}
	var original *programQueueNativeRefusal
	if !errors.As(err, &original) || original == nil || err.Error() != original.message {
		return err.Error()
	}
	o := original.observation
	if o.Format != 1 || !programQueueDiagnosticUnit.MatchString(o.Unit) || !programQueueDiagnosticSHA.MatchString(o.InventorySHA) {
		return err.Error()
	}
	switch o.Kind {
	case "native-program-unit-refusal-v1":
		if original.message != "native program operation is active, failed or transitional; upgrade refused" || !programQueueDiagnosticState.MatchString(o.LoadState) || !programQueueDiagnosticState.MatchString(o.ActiveState) || !programQueueDiagnosticState.MatchString(o.SubState) || o.JobID != "" || o.JobType != "" || o.JobState != "" {
			return err.Error()
		}
	case "native-program-job-refusal-v1":
		id, e := strconv.ParseUint(o.JobID, 10, 64)
		if original.message != "native program operation is queued; upgrade refused" || e != nil || id == 0 || strconv.FormatUint(id, 10) != o.JobID || !programQueueDiagnosticState.MatchString(o.JobType) || !programQueueDiagnosticState.MatchString(o.JobState) || o.LoadState != "" || o.ActiveState != "" || o.SubState != "" {
			return err.Error()
		}
	default:
		return err.Error()
	}
	raw, e := json.Marshal(o)
	if e != nil || len(raw) > 1024 {
		return err.Error()
	}
	return original.message + "\n" + string(raw)
}
