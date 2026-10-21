//go:build linux

package executor

import (
	"context"
	"encoding/binary"
	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func realtimeEventually(t *testing.T, description string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("real kernel event did not complete:", description)
}

func realtimeWorker(t *testing.T, s *Service) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.runIntegrityWatcher(ctx) }()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Fatal("inotify worker did not stop or release descriptor")
		}
	}
	t.Cleanup(stop)
	return stop
}

func realtimePolicy(t *testing.T, s *Service, id, site string) moduleIntegrityPolicy {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, err := s.readIntegrityPolicy(id, site)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func realtimeReady(t *testing.T, s *Service, id, site string, directories int) {
	t.Helper()
	realtimeEventually(t, "recursive watches and initial reconciliation", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		status := s.moduleWatchStatus[id+"/"+site]
		policy, err := s.readIntegrityPolicy(id, site)
		return err == nil && status.State == "active" && status.Directories >= directories && policy.LastCheckAt != ""
	})
}

func realtimeBaseline(t *testing.T, s *Service, id, site string, autoRestore bool, excludes []string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.moduleIntegrity(context.Background(), id, "baseline", core.AppModuleInput{SiteID: site, Realtime: true, AutoRestore: autoRestore, Excludes: excludes, Interval: 86400})
	if err != nil {
		t.Fatal(err)
	}
}

func realtimeChange(t *testing.T, s *Service, id, site, path, kind, sha string) {
	t.Helper()
	realtimeEventually(t, path+"/"+kind, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		var report struct {
			Changes []moduleChange `json:"changes"`
		}
		if moduleRead(filepath.Join(s.moduleDir(id), "baselines", site, "last-check.json"), &report) != nil {
			return false
		}
		for _, change := range report.Changes {
			if change.Path == path && change.Kind == kind && (sha == "" || change.After == sha) {
				return true
			}
		}
		return false
	})
}

func TestIntegrityRealtimeActualWriteRenamePermissionsAndDynamicDirectory(t *testing.T) {
	svc, site, _ := appReliabilityFixture(t)
	for _, path := range []string{"write.txt", "atomic.txt", "mode.txt", "delete.txt"} {
		fixtureWrite(t, svc, site, path, "original")
	}
	public := filepath.Join(svc.Config.SitesDir, site, "public")
	if err := os.MkdirAll(filepath.Join(public, "cache", "ignored"), 0755); err != nil {
		t.Fatal(err)
	}
	realtimeBaseline(t, svc, "file-monitor", site, false, []string{"cache"})
	realtimeWorker(t, svc)
	realtimeReady(t, svc, "file-monitor", site, 1)
	next := realtimePolicy(t, svc, "file-monitor", site).NextRunAt
	fixtureWrite(t, svc, site, "write.txt", "changed-by-close-write")
	realtimeChange(t, svc, "file-monitor", site, "write.txt", "modified", core.Hash("changed-by-close-write"))
	policy := realtimePolicy(t, svc, "file-monitor", site)
	if policy.LastTrigger != "inotify" || policy.NextRunAt != next {
		t.Fatal("a normal kernel event must trigger the check without postponing periodic reconciliation", policy)
	}
	fixtureWrite(t, svc, site, "replacement.tmp", "atomic-content")
	if err := os.Rename(filepath.Join(public, "replacement.tmp"), filepath.Join(public, "atomic.txt")); err != nil {
		t.Fatal(err)
	}
	realtimeChange(t, svc, "file-monitor", site, "atomic.txt", "modified", core.Hash("atomic-content"))
	if err := os.Chmod(filepath.Join(public, "mode.txt"), 0600); err != nil {
		t.Fatal(err)
	}
	realtimeChange(t, svc, "file-monitor", site, "mode.txt", "permission", "")
	if err := os.Remove(filepath.Join(public, "delete.txt")); err != nil {
		t.Fatal(err)
	}
	realtimeChange(t, svc, "file-monitor", site, "delete.txt", "deleted", "")
	if err := os.MkdirAll(filepath.Join(public, "new", "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, svc, site, "new/nested/created.txt", "first-before-watch")
	realtimeReady(t, svc, "file-monitor", site, 3)
	realtimeChange(t, svc, "file-monitor", site, "new/nested/created.txt", "created", core.Hash("first-before-watch"))
	fixtureWrite(t, svc, site, "new/nested/created.txt", "second-after-watch")
	realtimeChange(t, svc, "file-monitor", site, "new/nested/created.txt", "created", core.Hash("second-after-watch"))
	svc.mu.Lock()
	status := svc.moduleWatchStatus["file-monitor/"+site]
	svc.mu.Unlock()
	if status.Directories != 3 {
		t.Fatal("excluded directories should not consume watches", status)
	}
}

func TestIntegrityRealtimeRestorePauseResumeAndPersistedRestart(t *testing.T) {
	svc, site, _ := appReliabilityFixture(t)
	fixtureWrite(t, svc, site, "keep.txt", "trusted")
	realtimeBaseline(t, svc, "enterprise-tamper-proof", site, true, nil)
	stop := realtimeWorker(t, svc)
	realtimeReady(t, svc, "enterprise-tamper-proof", site, 1)
	fixtureWrite(t, svc, site, "keep.txt", "malicious-change")
	realtimeEventually(t, "event-triggered signed restore", func() bool { return fixtureRead(t, svc, site, "keep.txt") == "trusted" })
	svc.mu.Lock()
	paused, err := svc.moduleIntegrityControl("enterprise-tamper-proof", "pause", core.AppModuleInput{SiteID: site})
	svc.mu.Unlock()
	if err != nil || paused.(map[string]any)["enabled"] != false {
		t.Fatal(paused, err)
	}
	fixtureWrite(t, svc, site, "keep.txt", "paused-user-edit")
	time.Sleep(1100 * time.Millisecond)
	if fixtureRead(t, svc, site, "keep.txt") != "paused-user-edit" {
		t.Fatal("pause did not immediately prevent automatic writes")
	}
	svc.mu.Lock()
	_, err = svc.moduleIntegrityControl("enterprise-tamper-proof", "resume", core.AppModuleInput{SiteID: site})
	svc.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	realtimeEventually(t, "resume catches writes during pause", func() bool { return fixtureRead(t, svc, site, "keep.txt") == "trusted" })
	stop()
	fixtureWrite(t, svc, site, "keep.txt", "changed-while-offline")
	restarted := New(svc.Config)
	realtimeWorker(t, restarted)
	realtimeReady(t, restarted, "enterprise-tamper-proof", site, 1)
	realtimeEventually(t, "new service reads persisted realtime policy and catches offline changes", func() bool { return fixtureRead(t, restarted, site, "keep.txt") == "trusted" })
	if !realtimePolicy(t, restarted, "enterprise-tamper-proof", site).Realtime {
		t.Fatal("realtime policy not persisted")
	}
}

func TestIntegrityRealtimeModeRevisionAndStaleQueuedEvent(t *testing.T) {
	svc, site, _ := appReliabilityFixture(t)
	fixtureWrite(t, svc, site, "keep.txt", "trusted")
	realtimeBaseline(t, svc, "enterprise-tamper-proof", site, true, nil)
	policy := realtimePolicy(t, svc, "enterprise-tamper-proof", site)
	w := realtimeManualWatcher(t, svc, 4096)
	w.reconcile(context.Background(), time.Now())
	fixtureWrite(t, svc, site, "keep.txt", "preserve-stale-event")
	svc.mu.Lock()
	_, err := svc.moduleIntegrityControl("enterprise-tamper-proof", "watch-mode", core.AppModuleInput{SiteID: site, ExpectedRevision: policy.Revision, Realtime: false, Interval: 300})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.moduleIntegrityControl("enterprise-tamper-proof", "watch-mode", core.AppModuleInput{SiteID: site, ExpectedRevision: policy.Revision, Realtime: true})
	svc.mu.Unlock()
	if err == nil {
		t.Fatal("stale policy revision accepted")
	}
	w.flush(time.Now().Add(time.Second))
	if fixtureRead(t, svc, site, "keep.txt") != "preserve-stale-event" {
		t.Fatal("queued event bypassed mode/revision change")
	}
	svc.mu.Lock()
	_, err = svc.moduleIntegrityControl("enterprise-tamper-proof", "pause", core.AppModuleInput{SiteID: site})
	current, _ := svc.readIntegrityPolicy("enterprise-tamper-proof", site)
	_, modeErr := svc.moduleIntegrityControl("enterprise-tamper-proof", "watch-mode", core.AppModuleInput{SiteID: site, ExpectedRevision: current.Revision, Realtime: true})
	after, _ := svc.readIntegrityPolicy("enterprise-tamper-proof", site)
	svc.mu.Unlock()
	if err != nil || modeErr != nil || after.Enabled || !after.Realtime {
		t.Fatal("mode change incorrectly resumed paused protection", after, err, modeErr)
	}
}

func realtimeManualWatcher(t *testing.T, svc *Service, limit int) *integrityWatcher {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal("real Linux inotify unavailable:", err)
	}
	w := &integrityWatcher{Service: svc, FD: fd, Limit: limit, Sites: map[string]*integrityWatchSite{}, Watches: map[int]map[string]bool{}, Dirty: map[string]integrityDirtySite{}}
	t.Cleanup(w.close)
	return w
}

func TestIntegrityRealtimeQueueOverflowAndBoundedDebounce(t *testing.T) {
	svc, site, second := appReliabilityFixture(t)
	for _, id := range []string{site, second} {
		fixtureWrite(t, svc, id, "keep.txt", "trusted")
		realtimeBaseline(t, svc, "enterprise-tamper-proof", id, true, nil)
	}
	w := realtimeManualWatcher(t, svc, 4096)
	now := time.Now()
	w.reconcile(context.Background(), now)
	fixtureWrite(t, svc, site, "keep.txt", "edit-before-overflow")
	raw := make([]byte, unix.SizeofInotifyEvent)
	binary.NativeEndian.PutUint32(raw, ^uint32(0))
	binary.NativeEndian.PutUint32(raw[4:], unix.IN_Q_OVERFLOW)
	if !w.consume(raw, now) || w.Overflows != 1 || len(w.Dirty) != 2 {
		t.Fatal("overflow did not invalidate all monitored sites")
	}
	for i := 0; i < 100; i++ {
		w.markDirty(site, "inotify", now.Add(time.Duration(i)*50*time.Millisecond))
	}
	if w.Dirty[site].Due.After(now.Add(2*time.Second)) || w.Dirty[site].Trigger != "inotify-overflow" {
		t.Fatal("event burst postponed recovery or hid overflow", w.Dirty[site])
	}
	// Malformed/truncated kernel buffers follow the same explicit recovery
	// path; no parsed event name can become a filesystem write target.
	w.consume([]byte{1, 2, 3}, now)
	if w.Overflows != 2 {
		t.Fatal("truncated event did not request safe reconciliation")
	}
	w.reconcile(context.Background(), now)
	w.flush(now.Add(3 * time.Second))
	if fixtureRead(t, svc, site, "keep.txt") != "trusted" || realtimePolicy(t, svc, "enterprise-tamper-proof", site).LastTrigger != "inotify-overflow" {
		t.Fatal("overflow did not cause a full signed catch-up check")
	}
	var events []moduleEvent
	if err := moduleRead(filepath.Join(svc.moduleDir("enterprise-tamper-proof"), "history.json"), &events); err != nil || len(events) != 2 || events[0].Trigger != "inotify-overflow" || events[1].Trigger != "inotify-overflow" || events[0].Restored+events[1].Restored != 1 {
		t.Fatal(events, err)
	}
}

func TestIntegrityRealtimeWatchLimitPreservesPeriodicFallback(t *testing.T) {
	svc, site, _ := appReliabilityFixture(t)
	public := filepath.Join(svc.Config.SitesDir, site, "public")
	for _, path := range []string{"a", "b", "c"} {
		if err := os.Mkdir(filepath.Join(public, path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	fixtureWrite(t, svc, site, "c/keep.txt", "trusted")
	realtimeBaseline(t, svc, "website-tamper-proof", site, false, nil)
	w := realtimeManualWatcher(t, svc, 2)
	w.reconcile(context.Background(), time.Now())
	status := svc.moduleWatchStatus["website-tamper-proof/"+site]
	if status.State != "degraded" || !strings.Contains(status.Error, "上限") || len(w.Watches) > 2 {
		t.Fatal("watch limit hidden or exceeded", status)
	}
	fixtureWrite(t, svc, site, "c/keep.txt", "changed-outside-partial-watches")
	svc.runDueIntegrity(time.Now().Add(48 * time.Hour))
	realtimeChange(t, svc, "website-tamper-proof", site, "c/keep.txt", "modified", core.Hash("changed-outside-partial-watches"))
}

func TestIntegrityRealtimeCorruptSignatureAndLinksNeverRestore(t *testing.T) {
	for _, unsafe := range []string{"signature", "symlink"} {
		t.Run(unsafe, func(t *testing.T) {
			svc, site, _ := appReliabilityFixture(t)
			fixtureWrite(t, svc, site, "keep.txt", "trusted")
			realtimeBaseline(t, svc, "enterprise-tamper-proof", site, true, nil)
			outside := filepath.Join(t.TempDir(), "outside.txt")
			if err := os.WriteFile(outside, []byte("outside-must-not-change"), 0644); err != nil {
				t.Fatal(err)
			}
			if unsafe == "signature" {
				path := filepath.Join(svc.moduleDir("enterprise-tamper-proof"), "baselines", site, "baseline.json")
				var baseline moduleBaseline
				if err := moduleRead(path, &baseline); err != nil {
					t.Fatal(err)
				}
				baseline.Signature = "invalid"
				if err := moduleWrite(path, baseline); err != nil {
					t.Fatal(err)
				}
				fixtureWrite(t, svc, site, "keep.txt", "untrusted-baseline-preserved")
			} else {
				path := filepath.Join(svc.Config.SitesDir, site, "public", "keep.txt")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			}
			w := realtimeManualWatcher(t, svc, 4096)
			now := time.Now()
			w.reconcile(context.Background(), now)
			w.flush(now.Add(time.Second))
			if svc.moduleWatchStatus["enterprise-tamper-proof/"+site].State != "degraded" {
				t.Fatal("unsafe scope presented as active protection")
			}
			data, err := os.ReadFile(outside)
			if err != nil || string(data) != "outside-must-not-change" {
				t.Fatal("outside data changed", err)
			}
			if unsafe == "signature" && fixtureRead(t, svc, site, "keep.txt") != "untrusted-baseline-preserved" {
				t.Fatal("invalid signature authorized a restoration")
			}
			if realtimePolicy(t, svc, "enterprise-tamper-proof", site).FailureCount != 1 {
				t.Fatal("invalid baseline or unsafe path failure was not persisted")
			}
		})
	}
}

func TestIntegrityRealtimeLegacyPolicyOptInAndDescriptorCleanup(t *testing.T) {
	svc, site, _ := appReliabilityFixture(t)
	fixtureWrite(t, svc, site, "keep.txt", "trusted")
	if _, err := svc.moduleIntegrity(context.Background(), "file-monitor", "baseline", core.AppModuleInput{SiteID: site}); err != nil {
		t.Fatal(err)
	}
	if realtimePolicy(t, svc, "file-monitor", site).Realtime {
		t.Fatal("an existing/default strategy was silently opted into realtime")
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		worker := realtimeWorker(t, svc)
		worker()
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) > len(before)+2 {
		t.Fatal("inotify descriptors leaked across worker shutdowns", len(before), len(after), err)
	}
}
