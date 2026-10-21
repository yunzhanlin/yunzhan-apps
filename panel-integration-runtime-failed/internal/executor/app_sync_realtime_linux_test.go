//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func realtimeSyncPlan(t *testing.T, s *Service, id string) moduleSyncPlan {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var plan moduleSyncPlan
	if err := moduleRead(s.syncPlanPath(id), &plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestSyncRealtimeActualCopyConflictPauseResumeAndRestart(t *testing.T) {
	svc, source, target := appReliabilityFixture(t)
	fixtureWrite(t, svc, source, "copy.txt", "first")
	input := core.AppModuleInput{ResourceID: "realtime-copy", SiteID: source, TargetSiteID: target, Realtime: true, Enabled: true, Interval: 86400, Excludes: []string{"cache"}}
	if _, err := svc.moduleSyncPlans(context.Background(), "schedule", input); err != nil {
		t.Fatal(err)
	}
	stop := realtimeWorker(t, svc)
	targetPath := filepath.Join(svc.Config.SitesDir, target, "public", "copy.txt")
	realtimeEventually(t, "initial realtime catch-up copy", func() bool { data, err := os.ReadFile(targetPath); return err == nil && string(data) == "first" })
	first := realtimeSyncPlan(t, svc, input.ResourceID)
	fixtureWrite(t, svc, source, "copy.txt", "second")
	realtimeEventually(t, "real close-write increment copied", func() bool { return fixtureRead(t, svc, target, "copy.txt") == "second" })
	if plan := realtimeSyncPlan(t, svc, input.ResourceID); plan.LastTrigger != "inotify" || plan.NextRunAt != first.NextRunAt {
		t.Fatal("real sync event or periodic schedule incorrect", plan)
	}
	fixtureWrite(t, svc, target, "copy.txt", "target-user-edit")
	fixtureWrite(t, svc, source, "copy.txt", "source-new-edit")
	realtimeEventually(t, "changed target becomes conflict", func() bool { return realtimeSyncPlan(t, svc, input.ResourceID).Conflicts == 1 })
	if fixtureRead(t, svc, target, "copy.txt") != "target-user-edit" {
		t.Fatal("realtime mode overwrote a target conflict")
	}
	if err := os.MkdirAll(filepath.Join(svc.Config.SitesDir, source, "public", "new", "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, svc, source, "new/nested/fresh.txt", "nested-first")
	nestedTarget := filepath.Join(svc.Config.SitesDir, target, "public", "new", "nested", "fresh.txt")
	realtimeEventually(t, "new nested directory copied", func() bool {
		data, err := os.ReadFile(nestedTarget)
		return err == nil && string(data) == "nested-first"
	})
	plan := realtimeSyncPlan(t, svc, input.ResourceID)
	svc.mu.Lock()
	_, err := svc.moduleSyncPlans(context.Background(), "pause-plan", core.AppModuleInput{ResourceID: plan.ID, ExpectedRevision: plan.Revision})
	svc.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, svc, source, "new/nested/fresh.txt", "paused-source-change")
	time.Sleep(1100 * time.Millisecond)
	if fixtureRead(t, svc, target, "new/nested/fresh.txt") != "nested-first" {
		t.Fatal("paused realtime plan wrote target")
	}
	plan = realtimeSyncPlan(t, svc, input.ResourceID)
	svc.mu.Lock()
	_, err = svc.moduleSyncPlans(context.Background(), "resume-plan", core.AppModuleInput{ResourceID: plan.ID, ExpectedRevision: plan.Revision})
	svc.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	realtimeEventually(t, "resume catches changes during pause", func() bool { return fixtureRead(t, svc, target, "new/nested/fresh.txt") == "paused-source-change" })
	stop()
	fixtureWrite(t, svc, source, "new/nested/fresh.txt", "changed-offline")
	restarted := New(svc.Config)
	realtimeWorker(t, restarted)
	realtimeEventually(t, "restart reads persisted realtime sync plan", func() bool { return fixtureRead(t, restarted, target, "new/nested/fresh.txt") == "changed-offline" })
	if fixtureRead(t, restarted, target, "copy.txt") != "target-user-edit" {
		t.Fatal("restart lost conflict protection")
	}
}

func TestSyncRealtimeCycleRejectionAndSharedDirectoryWatches(t *testing.T) {
	svc, source, target := appReliabilityFixture(t)
	fixtureWrite(t, svc, source, "keep.txt", "trusted")
	realtimeBaseline(t, svc, "file-monitor", source, false, []string{"cache"})
	input := core.AppModuleInput{ResourceID: "realtime-forward", SiteID: source, TargetSiteID: target, Realtime: true, Enabled: true, Interval: 86400}
	if _, err := svc.moduleSyncPlans(context.Background(), "schedule", input); err != nil {
		t.Fatal(err)
	}
	reverse := core.AppModuleInput{ResourceID: "reverse-scheduled", SiteID: target, TargetSiteID: source, Enabled: true, Interval: 300}
	if _, err := svc.moduleSyncPlans(context.Background(), "schedule", reverse); err == nil {
		t.Fatal("scheduled edge was allowed to close a realtime event loop")
	}
	reverse.Enabled = false
	if _, err := svc.moduleSyncPlans(context.Background(), "schedule", reverse); err != nil {
		t.Fatal("paused reverse edge should not be rejected", err)
	}
	paused := realtimeSyncPlan(t, svc, reverse.ResourceID)
	if _, err := svc.moduleSyncPlans(context.Background(), "resume-plan", core.AppModuleInput{ResourceID: paused.ID, ExpectedRevision: paused.Revision}); err == nil {
		t.Fatal("resume bypassed realtime cycle check")
	}
	w := realtimeManualWatcher(t, svc, 4096)
	w.reconcile(context.Background(), time.Now())
	if len(w.Watches) != 1 || len(w.Sites[source].Plans) != 2 {
		t.Fatal("integrity and sync did not share the same physical directory watch", len(w.Watches), w.Sites)
	}
	fixtureWrite(t, svc, source, "keep.txt", "new-real-content")
	w.flush(time.Now().Add(time.Second))
	if fixtureRead(t, svc, target, "keep.txt") != "new-real-content" {
		t.Fatal("shared watch did not invoke sync")
	}
	realtimeChange(t, svc, "file-monitor", source, "keep.txt", "modified", core.Hash("new-real-content"))
}
