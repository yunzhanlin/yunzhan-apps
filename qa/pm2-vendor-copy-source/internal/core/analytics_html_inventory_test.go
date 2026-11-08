package core

import (
	"context"
	"testing"
)

func TestAnalyticsHTMLInventoryIncludesQueueAndPreservesTerminalEvidence(t *testing.T) {
	s := testStore(t)
	id, err := s.QueueAnalyticsHTMLBuild("private-inventory", "admin")
	if err != nil {
		t.Fatal(err)
	}
	read := func(native []WAFEngineStatus) WAFEngineStatus {
		t.Helper()
		out, err := s.mergeAnalyticsHTMLInventory(context.Background(), native)
		if err != nil || len(out) != 1 || out[0].JobID != id {
			t.Fatal("missing or incorrect durable inventory", out, err)
		}
		return out[0]
	}
	if out := read(nil); out.State != "queued" || out.IntegrityVerified || !out.BuildOnly {
		t.Fatal("not-yet-dispatched queue was hidden or treated as ready", out)
	}
	native := WAFEngineStatus{JobID: id, State: "ready", IntegrityVerified: true, ABIValidated: true, BuildOnly: true, Steps: []Step{}}
	if out := read([]WAFEngineStatus{native}); out.State != "queued" || out.IntegrityVerified {
		t.Fatal("native readiness beat durable worker completion", out)
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='succeeded' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if out := read([]WAFEngineStatus{native}); out.State != "ready" || !out.IntegrityVerified || !out.ABIValidated {
		t.Fatal("verified owned completion lost", out)
	}
	if out := read(nil); out.State != "needs_attention" {
		t.Fatal("missing actual evidence was reported as successful build", out)
	}
	native.ABIValidated = false
	if out := read([]WAFEngineStatus{native}); out.State != "needs_attention" || out.IntegrityVerified {
		t.Fatal("incomplete actual proof remained selectable", out)
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='failed',error='original owned failure',steps='[{"time":"QA","message":"original failure evidence"}]' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	native.ABIValidated = true
	if out := read([]WAFEngineStatus{native}); out.State != "failed" || out.Error != "original owned failure" || out.IntegrityVerified || len(out.Steps) != 1 || out.Steps[0].Message != "original failure evidence" {
		t.Fatal("late native success overwrote immutable failed job", out)
	}
	orphan := native
	orphan.JobID = ID()
	out, err := s.mergeAnalyticsHTMLInventory(context.Background(), []WAFEngineStatus{orphan})
	if err != nil || len(out) != 2 {
		t.Fatal(out, err)
	}
	for _, entry := range out {
		if entry.JobID == orphan.JobID && (entry.State != "needs_attention" || entry.IntegrityVerified || entry.ABIValidated) {
			t.Fatal("unowned build was adopted", entry)
		}
	}
	if _, err := s.mergeAnalyticsHTMLInventory(context.Background(), []WAFEngineStatus{native, native}); err == nil {
		t.Fatal("duplicate native identity accepted")
	}
}

func TestAnalyticsHTMLQueueCapacityPreservesReplaysAndAllEvidence(t *testing.T) {
	s := testStore(t)
	id, err := s.QueueAnalyticsHTMLBuild("capacity-replay", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='succeeded' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 64; i++ {
		if _, err := s.DB.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,created_at,updated_at) VALUES(?,'website-analytics','analytics_html_build','failed',?,?,?)`, ID(), ID(), Now(), Now()); err != nil {
			t.Fatal(err)
		}
	}
	if repeat, err := s.QueueAnalyticsHTMLBuild("capacity-replay", "admin"); err != nil || repeat != id {
		t.Fatal("full inventory lost original idempotent replay", repeat, err)
	}
	if _, err := s.QueueAnalyticsHTMLBuild("capacity-new", "admin"); err == nil {
		t.Fatal("new build over retained evidence capacity")
	}
	entries, err := s.mergeAnalyticsHTMLInventory(context.Background(), nil)
	if err != nil || len(entries) != 64 {
		t.Fatal("retained inventory disappeared or was truncated", len(entries), err)
	}
	if _, err := s.DB.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,created_at,updated_at) VALUES(?,'website-analytics','analytics_html_build','failed',?,?,?)`, ID(), ID(), Now(), Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.mergeAnalyticsHTMLInventory(context.Background(), nil); err == nil {
		t.Fatal("legacy over-capacity inventory was silently truncated")
	}
}
