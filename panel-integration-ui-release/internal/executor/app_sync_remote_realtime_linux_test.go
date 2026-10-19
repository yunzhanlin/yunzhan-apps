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

func remoteRealtimePlan(t *testing.T, f *remoteSyncFixture) remoteSyncPlan {
	t.Helper()
	_, err := f.s.moduleRemotePlans("schedule-remote-plan", core.AppModuleInput{ResourceID: "realtime-one", RemoteTargetID: f.cfg.ID, RemoteTargetRevision: f.cfg.Revision, SiteID: f.site, Enabled: true, Realtime: true, Interval: 86400, Excludes: []string{"cache"}})
	if err != nil {
		t.Fatal(err)
	}
	return remotePlanReload(t, f.s, "realtime-one")
}
func remoteKernelFlush(t *testing.T, w *integrityWatcher) {
	t.Helper()
	now := time.Now()
	if w.drain(now) {
		w.reconcile(context.Background(), now)
	}
	// Exercise real native events; this controlled flush does not attest wall
	// clock debounce. The independent production-worker test does that.
	w.flush(now.Add(3 * time.Second))
}
func remoteRealtimeEventually(t *testing.T, label string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(14 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("actual remote realtime worker did not complete", label)
}

func TestRemoteSyncRealtimeKernelCoalescingAndOriginalSequence(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "first")
	p := remoteRealtimePlan(t, f)
	w := realtimeManualWatcher(t, f.s, 4096)
	w.reconcile(context.Background(), time.Now())
	if len(w.Watches) != 1 {
		t.Fatal("source inode was not actually watched", len(w.Watches))
	}
	w.flush(time.Now().Add(3 * time.Second))
	p = remotePlanReload(t, f.s, p.ID)
	if p.ChangeSequence != 1 || p.ConsumedSequence != 0 || p.LastTrigger != "inotify-reconcile" {
		t.Fatal(p)
	}
	f.s.scheduleRemotePlans(time.Now().UTC())
	p = remotePlanReload(t, f.s, p.ID)
	original := p.PendingJobID
	if original == "" || p.PendingSequence != 1 {
		t.Fatal(p)
	}
	for i := 0; i < 8; i++ {
		fixtureWrite(t, f.s, f.site, "copy.txt", "burst-latest")
	}
	remoteKernelFlush(t, w)
	p = remotePlanReload(t, f.s, p.ID)
	if p.ChangeSequence != 2 || p.PendingSequence != 1 || p.PendingJobID != original || p.LastTrigger != "inotify" {
		t.Fatal("event while original pending was lost/rebound", p)
	}
	f.s.scheduleRemotePlans(time.Now().UTC())
	jobs, e := f.s.allRemoteJobs()
	if e != nil || len(jobs) != 1 {
		t.Fatal("event burst created overlapping tasks", e, len(jobs))
	}
	f.s.runOneRemoteSyncJob(context.Background())
	if remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "burst-latest" {
		t.Fatal("actual SFTP copy missing")
	}
	f.s.scheduleRemotePlans(time.Now().UTC())
	p = remotePlanReload(t, f.s, p.ID)
	if p.ConsumedSequence != 1 || p.ChangeSequence != 2 || p.PendingJobID != "" {
		t.Fatal("older task acknowledged a newer kernel change", p)
	}
	f.s.runOneRemoteSyncJob(context.Background())
	f.s.scheduleRemotePlans(time.Now().UTC())
	p = remotePlanReload(t, f.s, p.ID)
	jobs, e = f.s.allRemoteJobs()
	if e != nil || len(jobs) != 2 || p.ConsumedSequence != 2 || p.PendingJobID != "" {
		t.Fatal("newer change not independently settled", p, e, len(jobs))
	}
	for _, j := range jobs {
		if j.State != "succeeded" {
			t.Fatal(j)
		}
	}
	if f.commands.Load() != 0 {
		t.Fatal("remote commands attempted")
	}
}

func TestRemoteSyncRealtimeDynamicDirectoriesExclusionAndSymlinkDegradation(t *testing.T) {
	f := newRemoteSyncFixture(t)
	p := remoteRealtimePlan(t, f)
	public := filepath.Join(f.s.Config.SitesDir, f.site, "public")
	if e := os.MkdirAll(filepath.Join(public, "cache", "private"), 0755); e != nil {
		t.Fatal(e)
	}
	w := realtimeManualWatcher(t, f.s, 4096)
	w.reconcile(context.Background(), time.Now())
	w.flush(time.Now().Add(3 * time.Second))
	f.s.runOneRemoteSyncJob(context.Background())
	f.s.scheduleRemotePlans(time.Now().UTC())
	if e := os.MkdirAll(filepath.Join(public, "new", "nested"), 0755); e != nil {
		t.Fatal(e)
	}
	fixtureWrite(t, f.s, f.site, "new/nested/file.txt", "created-before-new-watch")
	fixtureWrite(t, f.s, f.site, "cache/private/never.txt", "must-stay-local")
	remoteKernelFlush(t, w)
	if len(w.Watches) != 3 {
		t.Fatal("recursive watches/excluded directory incorrect", len(w.Watches))
	}
	f.s.runOneRemoteSyncJob(context.Background())
	f.s.scheduleRemotePlans(time.Now().UTC())
	if remoteFixtureRead(t, filepath.Join(f.root, "new/nested/file.txt")) != "created-before-new-watch" {
		t.Fatal("new-directory event was lost")
	}
	if _, e := os.Lstat(filepath.Join(f.root, "cache")); !os.IsNotExist(e) {
		t.Fatal("excluded remote directory copied", e)
	}
	if e := os.Symlink(t.TempDir(), filepath.Join(public, "unsafe")); e != nil {
		t.Fatal(e)
	}
	w.Sites[f.site].Rebuild = true
	w.reconcile(context.Background(), time.Now())
	view, e := f.s.moduleRemotePlans("remote-plans", core.AppModuleInput{})
	if e != nil {
		t.Fatal(e)
	}
	v := view.(map[string]any)["remote_plans"].([]remotePlanView)[0]
	if v.ID != p.ID || v.WatcherState != "degraded" || v.WatchError == "" || !v.Enabled {
		t.Fatal("unavailable kernel scope incorrectly reported active", v)
	}
}

func TestRemoteSyncRealtimeStaleEventsPauseResumeAndSequenceBounds(t *testing.T) {
	f := newRemoteSyncFixture(t)
	p := remoteRealtimePlan(t, f)
	f.s.markRemotePlanChanged(p.ID, f.site, p.Revision, "inotify")
	p = remotePlanReload(t, f.s, p.ID)
	if _, e := f.s.moduleRemotePlans("pause-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: p.Revision}); e != nil {
		t.Fatal(e)
	}
	f.s.markRemotePlanChanged(p.ID, f.site, p.Revision, "inotify")
	paused := remotePlanReload(t, f.s, p.ID)
	if paused.ChangeSequence != 1 || paused.Enabled {
		t.Fatal("paused old watcher changed policy", paused)
	}
	if _, e := f.s.moduleRemotePlans("resume-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: paused.Revision, RemoteTargetRevision: f.cfg.Revision}); e != nil {
		t.Fatal(e)
	}
	resumed := remotePlanReload(t, f.s, p.ID)
	f.s.markRemotePlanChanged(p.ID, f.site, p.Revision, "inotify")
	if remotePlanReload(t, f.s, p.ID).ChangeSequence != 1 {
		t.Fatal("stale pre-resume watcher accepted")
	}
	f.s.markRemotePlanChanged(p.ID, f.site, resumed.Revision, "inotify-overflow")
	p = remotePlanReload(t, f.s, p.ID)
	if p.ChangeSequence != 2 || p.LastTrigger != "inotify-overflow" {
		t.Fatal(p)
	}
	for _, bad := range []remoteSyncPlan{func() remoteSyncPlan { q := p; q.ConsumedSequence = 3; return q }(), func() remoteSyncPlan { q := p; q.PendingSequence = 1; return q }(), func() remoteSyncPlan { q := p; q.ChangeSequence = remotePlanMaxSequence + 1; return q }(), func() remoteSyncPlan { q := p; q.Realtime = false; return q }()} {
		if validateRemotePlan(bad) == nil {
			t.Fatal("invalid realtime identity accepted", bad)
		}
	}
	p.ChangeSequence = remotePlanMaxSequence
	if e := f.s.writeRemotePlan(p); e != nil {
		t.Fatal(e)
	}
	f.s.markRemotePlanChanged(p.ID, f.site, p.Revision, "inotify")
	p = remotePlanReload(t, f.s, p.ID)
	if p.Enabled || p.LastState != "paused-error" || p.ChangeSequence != remotePlanMaxSequence {
		t.Fatal("sequence exhaustion wrapped or remained active", p)
	}
}

func TestRemoteSyncRealtimeUnsafePrivateStateFencesCurrentExecutor(t *testing.T) {
	f := newRemoteSyncFixture(t)
	p := remoteRealtimePlan(t, f)
	dir := filepath.Dir(f.s.remotePlanPath(p.ID))
	if e := os.Chmod(dir, 0500); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	f.s.markRemotePlanChanged(p.ID, f.site, p.Revision, "inotify")
	if !f.s.moduleAutoBlocked[remotePlanBlockedID(p.ID)] {
		t.Fatal("actual refused private policy read did not fence automation")
	}
	f.s.scheduleRemotePlans(time.Now().UTC().Add(48 * time.Hour))
	jobs, e := f.s.allRemoteJobs()
	if e != nil || len(jobs) != 0 {
		t.Fatal("write after uncertain durable event", e, len(jobs))
	}
	if _, e = f.s.moduleRemotePlans("remote-plans", core.AppModuleInput{}); e == nil {
		t.Fatal("unsafe inventory falsely reported as a complete list")
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	// Repairing private permissions alone cannot clear the original fence.
	f.s.scheduleRemotePlans(time.Now().UTC().Add(48 * time.Hour))
	jobs, e = f.s.allRemoteJobs()
	if e != nil || len(jobs) != 0 {
		t.Fatal("permission repair implicitly resumed remote writes", e)
	}
	view, e := f.s.moduleRemotePlans("remote-plans", core.AppModuleInput{})
	if e != nil {
		t.Fatal(e)
	}
	v := view.(map[string]any)["remote_plans"].([]remotePlanView)[0]
	if v.Enabled || v.LastState != "paused-error" || v.WatcherState != "disabled" {
		t.Fatal(v)
	}
	// No machine-powercut or persistence-failure-across-restart claim here.
}

func TestRemoteSyncRealtimeSharedLocalPlanIdentityAndOverflowFallback(t *testing.T) {
	f := newRemoteSyncFixture(t)
	p := remoteRealtimePlan(t, f)
	entries, e := os.ReadDir(f.s.Config.SitesDir)
	if e != nil {
		t.Fatal(e)
	}
	target := ""
	for _, entry := range entries {
		if entry.Name() != f.site && core.ValidID(entry.Name()) {
			target = entry.Name()
			break
		}
	}
	if target == "" {
		t.Fatal("actual fixture local target missing")
	}
	_, e = f.s.moduleSyncPlans(context.Background(), "schedule", core.AppModuleInput{ResourceID: p.ID, SiteID: f.site, TargetSiteID: target, Realtime: true, Enabled: true, Interval: 86400})
	if e != nil {
		t.Fatal(e)
	}
	fixtureWrite(t, f.s, f.site, "copy.txt", "shared-watch")
	w := realtimeManualWatcher(t, f.s, 4096)
	w.reconcile(context.Background(), time.Now())
	if len(w.Watches) != 1 || len(w.Sites[f.site].Plans) != 2 {
		t.Fatal("local and remote realtime plans did not share directory inode")
	}
	w.flush(time.Now().Add(3 * time.Second))
	if fixtureRead(t, f.s, target, "copy.txt") != "shared-watch" {
		t.Fatal("local plan identity collided with remote plan")
	}
	local := f.s.moduleWatchStatus["files-sync/"+p.ID]
	remote := f.s.moduleWatchStatus[remotePlanBlockedID(p.ID)]
	if local.State != "active" || remote.State != "active" {
		t.Fatal("watcher identities collided", local, remote)
	}
	w.overflow(time.Now())
	w.reconcile(context.Background(), time.Now())
	w.flush(time.Now().Add(3 * time.Second))
	p = remotePlanReload(t, f.s, p.ID)
	if p.ChangeSequence != 2 || p.LastTrigger != "inotify-overflow" || f.s.moduleWatchStatus[remotePlanBlockedID(p.ID)].Overflows != 1 {
		t.Fatal("overflow lost full reconciliation", p)
	}
	f.s.runOneRemoteSyncJob(context.Background())
	f.s.scheduleRemotePlans(time.Now().UTC())
	if remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "shared-watch" {
		t.Fatal("overflow catch-up SFTP missing")
	}
}

func TestRemoteSyncRealtimeUnavailableWatcherRetainsPeriodicPlan(t *testing.T) {
	f := newRemoteSyncFixture(t)
	p := remoteRealtimePlan(t, f)
	fixtureWrite(t, f.s, f.site, "copy.txt", "periodic-fallback")
	w := &integrityWatcher{Service: f.s, FD: -1, Limit: 4096, Sites: map[string]*integrityWatchSite{}, Watches: map[int]map[string]bool{}, Dirty: map[string]integrityDirtySite{}, InitError: "owned kernel unavailable"}
	w.reconcile(context.Background(), time.Now())
	defer w.close()
	view, e := f.s.moduleRemotePlans("remote-plans", core.AppModuleInput{})
	if e != nil {
		t.Fatal(e)
	}
	v := view.(map[string]any)["remote_plans"].([]remotePlanView)[0]
	if v.WatcherState != "unavailable" || v.WatchError == "" || !v.Enabled {
		t.Fatal(v)
	}
	p = remotePlanDue(t, f.s, p)
	f.s.runOneRemoteSyncJob(context.Background())
	f.s.scheduleRemotePlans(time.Now().UTC())
	if remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "periodic-fallback" {
		t.Fatal("periodic fallback did not copy")
	}
	p = remotePlanReload(t, f.s, p.ID)
	if p.ChangeSequence != 0 || p.LastTrigger != "scheduled" {
		t.Fatal("periodic falsely attested kernel event", p)
	}
}

func TestRemoteSyncRealtimeProductionWorkersActualCopyPauseRestartConflict(t *testing.T) {
	f := newRemoteSyncFixture(t)
	p := remoteRealtimePlan(t, f)
	fixtureWrite(t, f.s, f.site, "copy.txt", "first-native")
	start := func(s *Service) func() {
		stopWatch := realtimeWorker(t, s)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); s.runRemoteSyncWorker(ctx) }()
		stop := func() {
			cancel()
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				t.Fatal("actual remote worker did not stop")
			}
			stopWatch()
		}
		t.Cleanup(stop)
		return stop
	}
	stop := start(f.s)
	readPlan := func(s *Service) remoteSyncPlan { s.mu.Lock(); defer s.mu.Unlock(); return remotePlanReload(t, s, p.ID) }
	settled := func(s *Service) bool {
		q := readPlan(s)
		return q.Enabled && q.LastState == "succeeded" && q.PendingJobID == "" && q.ChangeSequence == q.ConsumedSequence
	}
	actualCopy := func(want string) bool {
		raw, e := os.ReadFile(filepath.Join(f.root, "copy.txt"))
		return e == nil && string(raw) == want
	}
	remoteRealtimeEventually(t, "actual startup catch-up SFTP before 86400-second deadline", func() bool { return actualCopy("first-native") && settled(f.s) })
	first := readPlan(f.s)
	fixtureWrite(t, f.s, f.site, "copy.txt", "actual-close-write")
	remoteRealtimeEventually(t, "actual native kernel close-write copied by production queue", func() bool { return actualCopy("actual-close-write") && settled(f.s) })
	current := readPlan(f.s)
	if current.LastTrigger != "inotify" || current.ChangeSequence <= first.ChangeSequence {
		t.Fatal(current)
	}
	f.s.mu.Lock()
	_, e := f.s.moduleRemotePlans("pause-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: current.Revision})
	f.s.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	fixtureWrite(t, f.s, f.site, "copy.txt", "changed-during-pause")
	time.Sleep(1100 * time.Millisecond)
	if !actualCopy("actual-close-write") {
		t.Fatal("paused realtime wrote remote target")
	}
	stop()
	fixtureWrite(t, f.s, f.site, "copy.txt", "changed-offline")
	restarted := New(f.s.Config)
	start(restarted)
	time.Sleep(1100 * time.Millisecond)
	if !actualCopy("actual-close-write") {
		t.Fatal("restart implicitly enabled paused realtime")
	}
	paused := readPlan(restarted)
	restarted.mu.Lock()
	_, e = restarted.moduleRemotePlans("resume-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: paused.Revision, RemoteTargetRevision: f.cfg.Revision})
	restarted.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	remoteRealtimeEventually(t, "explicit resume reconciles offline source", func() bool { return actualCopy("changed-offline") && settled(restarted) })
	remoteFixtureWrite(t, filepath.Join(f.root, "copy.txt"), "external-owner-edit")
	fixtureWrite(t, f.s, f.site, "copy.txt", "must-not-overwrite-external")
	remoteRealtimeEventually(t, "external conflict pauses actual realtime policy", func() bool { q := readPlan(restarted); return !q.Enabled && q.LastState == "paused-error" })
	if !actualCopy("external-owner-edit") {
		t.Fatal("realtime overwrote external edit")
	}
	if q := readPlan(restarted); q.PendingJobID == "" || q.LastJobID != q.PendingJobID {
		t.Fatal("conflict lost original task identity", q)
	}
	if f.commands.Load() != 0 {
		t.Fatal("realtime executed remote shell")
	}
	t.Log("PASS real shared inotify debounce, actual production 5-second remote worker, explicit pause/restart/resume and native SFTP conflict preservation")
}
