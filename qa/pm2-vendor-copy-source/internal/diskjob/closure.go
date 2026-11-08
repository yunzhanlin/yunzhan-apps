package diskjob

import "encoding/json"

// A closure ends the original admission, not a fabricated scan. Only a genuine
// result_summary may carry complete/partial; admission_closed and interrupted
// never supply filesystem statistics or an invented Started/policy receipt.
type Closure struct {
	Format          int      `json:"format"`
	JobID           string   `json:"job_id"`
	RequestSHA      string   `json:"request_sha256"`
	OwnerID         string   `json:"owner_id"`
	Kind            string   `json:"kind"`
	State           string   `json:"state"`
	At              string   `json:"at"`
	ExecutorSHA     string   `json:"executor_sha256"`
	ResultSHA       string   `json:"result_sha256"`
	StartedSHA      string   `json:"started_sha256"`
	Started         *Started `json:"started"`
	ScopeEmpty      bool     `json:"scope_empty"`
	AdmissionSealed bool     `json:"admission_sealed"`
}

func ClosureSHA(c Closure) string {
	raw, _ := json.Marshal(c)
	return hashBytes(raw)
}

func ValidateClosure(c Closure, in Request) error {
	if ValidateRequest(in) != nil || c.Format != 1 || c.JobID != in.JobID || c.RequestSHA != RequestSHA(in) || c.OwnerID != in.ActorID || !c.ScopeEmpty || !c.AdmissionSealed {
		return ErrReceipt
	}
	if _, ok := receiptTime(c.At); !ok {
		return ErrReceipt
	}
	if c.ExecutorSHA != "" && !ValidSHA(c.ExecutorSHA) || c.ResultSHA != "" && !ValidSHA(c.ResultSHA) || c.StartedSHA != "" && !ValidSHA(c.StartedSHA) {
		return ErrReceipt
	}
	if c.Started != nil {
		d := Dispatch{Format: 1, JobID: in.JobID, ActorID: in.ActorID, RequestSHA: c.RequestSHA, ExecutorSHA: c.ExecutorSHA}
		if ValidateStarted(*c.Started, d, in) != nil {
			return ErrReceipt
		}
	}
	switch c.Kind {
	case "result_summary":
		if c.Started == nil || !ValidSHA(c.ResultSHA) || !ValidSHA(c.StartedSHA) {
			return ErrReceipt
		}
		switch c.State {
		case "complete", "partial", "canceled", "failed":
		default:
			return ErrReceipt
		}
	case "interrupted":
		if c.Started == nil || !ValidSHA(c.StartedSHA) || c.State != "failed" {
			return ErrReceipt
		}
	case "admission_closed":
		if c.Started != nil || c.State != "canceled" {
			return ErrReceipt
		}
	default:
		return ErrReceipt
	}
	return nil
}

func DecodeClosure(raw []byte, in Request) (Closure, error) {
	var c Closure
	if decodeReceipt(raw, &c, 32768) != nil || ValidateClosure(c, in) != nil {
		return Closure{}, ErrReceipt
	}
	return c, nil
}

type RecoveryRequest struct {
	Format   int              `json:"format"`
	Operator InventoryRequest `json:"operator"`
	Request  Request          `json:"request"`
}

func DecodeRecoveryRequest(raw []byte) (RecoveryRequest, error) {
	var r RecoveryRequest
	if decodeReceipt(raw, &r, 16384) != nil || r.Format != 1 || ValidateRequest(r.Request) != nil {
		return RecoveryRequest{}, ErrReceipt
	}
	rawOp, _ := json.Marshal(r.Operator)
	if _, err := DecodeInventoryRequest(rawOp); err != nil {
		return RecoveryRequest{}, err
	}
	return r, nil
}

type RecoveryAck struct {
	Format          int      `json:"format"`
	JobID           string   `json:"job_id"`
	RequestSHA      string   `json:"request_sha256"`
	State           string   `json:"state"`
	SignalRequested bool     `json:"signal_requested"`
	Closure         *Closure `json:"closure"`
}

func ValidateRecoveryAck(a RecoveryAck, in Request) error {
	if a.Format != 1 || a.JobID != in.JobID || a.RequestSHA != RequestSHA(in) {
		return ErrReceipt
	}
	if a.Closure == nil {
		if a.State != "cancel_requested" {
			return ErrReceipt
		}
		return nil
	}
	if a.SignalRequested || ValidateClosure(*a.Closure, in) != nil || a.State != a.Closure.State {
		return ErrReceipt
	}
	return nil
}
