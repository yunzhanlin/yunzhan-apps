package diskjob

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHostClosureCannotInventSuccessfulScanOrChangeOwner(t *testing.T) {
	in, d, s, r := receiptFixture()
	startRaw, _ := json.Marshal(s)
	c := Closure{Format: 1, JobID: in.JobID, RequestSHA: RequestSHA(in), OwnerID: in.ActorID, Kind: "result_summary", State: r.State, At: r.At, ExecutorSHA: d.ExecutorSHA, ResultSHA: ResultSHA(r), StartedSHA: hashBytes(startRaw), Started: &s, ScopeEmpty: true, AdmissionSealed: true}
	raw, _ := json.Marshal(c)
	if _, err := DecodeClosure(raw, in); err != nil {
		t.Fatal(err)
	}
	c.Kind = "admission_closed"
	c.State = "canceled"
	c.Started = nil
	c.StartedSHA = ""
	c.ResultSHA = ""
	if ValidateClosure(c, in) != nil {
		t.Fatal("explicit admission seal refused")
	}
	for _, mutate := range []func(*Closure){
		func(c *Closure) { c.State = "complete" },
		func(c *Closure) { c.OwnerID = strings.Repeat("1", 32) },
		func(c *Closure) { c.AdmissionSealed = false },
		func(c *Closure) { c.ScopeEmpty = false },
		func(c *Closure) { c.Kind = "result_summary" },
		func(c *Closure) { c.Kind = "interrupted" },
	} {
		bad := c
		mutate(&bad)
		if ValidateClosure(bad, in) == nil {
			t.Fatal("invented result, actor adoption or unverified closure accepted", bad)
		}
	}
	raw, _ = json.Marshal(c)
	bad := strings.Replace(string(raw), `"admission_sealed":true`, `"admission_sealed":true,"admission_sealed":true`, 1)
	if _, err := DecodeClosure([]byte(bad), in); err == nil {
		t.Fatal("duplicate seal state accepted")
	}
	op := InventoryRequest{Format: 1, ActorID: strings.Repeat("2", 32), AccessRevision: "3"}
	req := RecoveryRequest{Format: 1, Operator: op, Request: in}
	raw, _ = json.Marshal(req)
	if _, err := DecodeRecoveryRequest(raw); err != nil {
		t.Fatal(err)
	}
	ack := RecoveryAck{Format: 1, JobID: in.JobID, RequestSHA: RequestSHA(in), State: "cancel_requested", SignalRequested: true}
	if ValidateRecoveryAck(ack, in) != nil {
		t.Fatal("nonterminal signal acknowledgement refused")
	}
	ack.State = "canceled"
	if ValidateRecoveryAck(ack, in) == nil {
		t.Fatal("signal became terminal without an admission seal")
	}
}
