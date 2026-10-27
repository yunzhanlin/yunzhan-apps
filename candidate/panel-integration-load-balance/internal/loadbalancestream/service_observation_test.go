package loadbalancestream

import (
	"bytes"
	"testing"
)

func TestRecordedServicePolicyDoesNotPretendASecondAllocationWasAdmitted(t *testing.T) {
	facts := serviceFacts()
	original, err := PlanService([]Entry{fixture()}, nil, facts)
	if err != nil {
		t.Fatal(err)
	}
	facts.AvailableMemoryBytes = 0
	observed, err := RecordedServicePlan([]Entry{fixture()}, nil, facts)
	if err != nil || observed.SHA256 != original.SHA256 || !bytes.Equal(observed.Unit, original.Unit) || facts.AvailableMemoryBytes != 0 {
		t.Fatal("read-only reconstruction changed original policy or fabricated free memory", err)
	}
	if _, err := PlanService([]Entry{fixture()}, nil, facts); err == nil {
		t.Fatal("read-only policy reconstruction loosened native allocation admission")
	}
	facts.AvailableMemoryBytes = -1
	if _, err := RecordedServicePlan([]Entry{fixture()}, nil, facts); err == nil {
		t.Fatal("malformed observation facts accepted")
	}
}
