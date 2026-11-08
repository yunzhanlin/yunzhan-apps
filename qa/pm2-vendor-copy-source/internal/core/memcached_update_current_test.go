package core

import "testing"

func TestMemcachedAlreadyPinnedReadOnlyInspectionCannotReserveOrRecreateCurrentInstance(t *testing.T) {
	s, actor, original := memcachedStoreFixture(t)
	target, err := MemcachedComposeUpdateTarget(original.Plan)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := MemcachedComposeUpdatePlan(original.Plan.ProjectID, original.Plan.MetadataSHA256, target, original.Plan.HostPort, original.Plan.ContainerID, original.Plan.RuntimeImageID, original.Plan.RuntimeConfigSHA256)
	if err != nil || !plan.AlreadyPinned || ValidateMemcachedUpdatePlan(plan, plan.ProjectID) != nil {
		t.Fatal("valid current-image preview rejected", err)
	}
	before, receipt := memcachedStoreCounts(t, s), memcachedStoreReceipt(t, s, plan.ProjectID)
	candidate := original
	candidate.Plan = plan
	candidate.Dispatch.Input.ExpectedProjectSHA256 = plan.ProjectSHA256
	candidate.DispatchSHA256 = MemcachedUpdateDispatchSHA(candidate.Dispatch)
	candidate.RecordSHA256 = memcachedRecordSHA(candidate)
	if ValidateMemcachedUpdateRecord(candidate) == nil {
		t.Fatal("read-only current-image preview became update authority")
	}
	if _, err := SealMemcachedUpdateRecord(candidate); err == nil {
		t.Fatal("current-image update seed created")
	}
	if _, _, err := s.reserveMemcachedUpdate(t.Context(), actor.ID, candidate); err == nil {
		t.Fatal("current instance was queued")
	}
	if memcachedStoreCounts(t, s) != before || memcachedStoreReceipt(t, s, plan.ProjectID) != receipt {
		t.Fatal("current-image inspection created request/audit or invented receipt")
	}
}
