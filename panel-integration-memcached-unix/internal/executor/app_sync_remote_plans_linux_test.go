//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func newRemotePlanFixture(t *testing.T, f *remoteSyncFixture, enabled bool) remoteSyncPlan {
	t.Helper()
	_, err := f.s.moduleRemotePlans("schedule-remote-plan", core.AppModuleInput{ResourceID: "periodic-one", RemoteTargetID: f.cfg.ID, RemoteTargetRevision: f.cfg.Revision, SiteID: f.site, Enabled: enabled, Interval: 60})
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.s.readRemotePlan("periodic-one")
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func remotePlanDue(t *testing.T, s *Service, p remoteSyncPlan) remoteSyncPlan {
	t.Helper()
	p.NextRunAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339)
	if err := s.writeRemotePlan(p); err != nil {
		t.Fatal(err)
	}
	return p
}
func remotePlanReload(t *testing.T, s *Service, id string) remoteSyncPlan {
	t.Helper()
	p, err := s.readRemotePlan(id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRemoteSyncPlanPolicyAndDistinctRevisions(t *testing.T) {
	f := newRemoteSyncFixture(t)
	base := core.AppModuleInput{ResourceID: "periodic-one", RemoteTargetID: f.cfg.ID, RemoteTargetRevision: 1, SiteID: f.site, Interval: 60}
	for _, alter := range []func(*core.AppModuleInput){func(v *core.AppModuleInput) { v.Interval = 59 }, func(v *core.AppModuleInput) { v.RemoteTargetRevision = 0 }, func(v *core.AppModuleInput) { v.Password = "secret" }, func(v *core.AppModuleInput) { v.Excludes = make([]string, 65) }, func(v *core.AppModuleInput) { v.RemoteRequestID = core.ID() }, func(v *core.AppModuleInput) { v.TargetSiteID = core.ID() }} {
		in := base
		alter(&in)
		if _, e := f.s.moduleRemotePlans("schedule-remote-plan", in); e == nil {
			t.Fatal("unsafe plan accepted", in.Interval)
		}
	}
	p := newRemotePlanFixture(t, f, false)
	if p.Enabled || p.NextRunAt != "" || p.Revision != 1 || p.TargetRevision != f.cfg.Revision {
		t.Fatal(p)
	}
	base.ExpectedRevision = 1
	base.Enabled = true
	if _, e := f.s.moduleRemotePlans("schedule-remote-plan", base); e != nil {
		t.Fatal(e)
	}
	p = remotePlanReload(t, f.s, p.ID)
	if p.Revision != 2 || p.TargetRevision != 1 {
		t.Fatal("plan and connection revision conflated", p)
	}
	if _, e := f.s.moduleRemotePlans("schedule-remote-plan", base); e == nil {
		t.Fatal("stale plan edit accepted")
	}
	base.ExpectedRevision = 2
	base.SiteID = core.ID()
	if _, e := f.s.moduleRemotePlans("schedule-remote-plan", base); e == nil {
		t.Fatal("source rebound")
	}
	base.ExpectedRevision = 0
	base.ResourceID = "second-plan"
	base.SiteID = f.site
	if _, e := f.s.moduleRemotePlans("schedule-remote-plan", base); e == nil {
		t.Fatal("second live plan on one target accepted")
	}
	if e := f.s.remoteSyncUninstallPreflight(); e == nil {
		t.Fatal("uninstalled active plan")
	}
}

func TestRemoteSyncPlanActualPeriodicIncrementalAndCoalescing(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "first")
	p := newRemotePlanFixture(t, f, true)
	f.s.scheduleRemotePlans(time.Now().UTC())
	jobs, e := f.s.allRemoteJobs()
	if e != nil || len(jobs) != 0 {
		t.Fatal("premature job", e)
	}
	p = remotePlanDue(t, f.s, p)
	f.s.scheduleRemotePlans(time.Now().UTC())
	p = remotePlanReload(t, f.s, p.ID)
	id := p.PendingJobID
	if p.LastState != "queued" || id == "" {
		t.Fatal(p)
	}
	for i := 0; i < 3; i++ {
		f.s.scheduleRemotePlans(time.Now().UTC().Add(10 * time.Hour))
	}
	jobs, e = f.s.allRemoteJobs()
	if e != nil || len(jobs) != 1 {
		t.Fatal("overlapping or catch-up burst", e)
	}
	if _, e = f.s.queueRemoteSync(f.cfg, core.AppModuleInput{RemoteRequestID: id, SiteID: f.site, ExpectedRevision: 1}); e == nil {
		t.Fatal("manual replay bypassed plan identity")
	}
	f.s.runOneRemoteSyncJob(context.Background())
	j, e := f.s.readRemoteJob(id)
	if e != nil || j.State != "succeeded" || j.Copied != 1 || j.PlanID != p.ID || j.PlanRevision != p.Revision {
		t.Fatal(j, e)
	}
	b, e := os.ReadFile(filepath.Join(f.root, "copy.txt"))
	if e != nil || string(b) != "first" {
		t.Fatal("actual SFTP copy missing", e)
	}
	f.s.scheduleRemotePlans(time.Now().UTC())
	p = remotePlanReload(t, f.s, p.ID)
	if p.PendingJobID != "" || p.LastJobID != id || p.LastState != "succeeded" {
		t.Fatal(p)
	}
	next, e := time.Parse(time.RFC3339, p.NextRunAt)
	if e != nil || time.Until(next) < 58*time.Second {
		t.Fatal("next interval not based on completed result", p)
	}
	fixtureWrite(t, f.s, f.site, "copy.txt", "second")
	p = remotePlanDue(t, f.s, p)
	f.s.runOneRemoteSyncJob(context.Background())
	p = remotePlanReload(t, f.s, p.ID)
	second, e := f.s.readRemoteJob(p.PendingJobID)
	if e != nil || second.State != "succeeded" || second.ID == id {
		t.Fatal(second, e)
	}
	b, e = os.ReadFile(filepath.Join(f.root, "copy.txt"))
	if e != nil || string(b) != "second" {
		t.Fatal(e)
	}
	cp, e := f.s.readRemoteCheckpoint(f.cfg, f.site)
	if e != nil || cp.Pending != nil || cp.Files["copy.txt"].SHA != core.Hash("second") {
		t.Fatal(cp, e)
	}
	t.Log("PASS real native SFTP periodic incremental writes, fixed pending identity, no overlap and coalesced missed deadlines; interval boundary is fixture-controlled, not a full 60-second wall-clock proof")
}

func TestRemoteSyncPlanConflictPausesAndKeepsExternalTarget(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "keep.txt", "source")
	remoteFixtureWrite(t, filepath.Join(f.root, "keep.txt"), "external")
	p := remotePlanDue(t, f.s, newRemotePlanFixture(t, f, true))
	f.s.runOneRemoteSyncJob(context.Background())
	f.s.scheduleRemotePlans(time.Now().UTC())
	p = remotePlanReload(t, f.s, p.ID)
	if p.Enabled || p.LastState != "paused-error" || p.PendingJobID == "" {
		t.Fatal(p)
	}
	b, e := os.ReadFile(filepath.Join(f.root, "keep.txt"))
	if e != nil || string(b) != "external" {
		t.Fatal("conflict lost", e)
	}
	for i := 0; i < 3; i++ {
		f.s.scheduleRemotePlans(time.Now().UTC().Add(24 * time.Hour))
	}
	jobs, e := f.s.allRemoteJobs()
	if e != nil || len(jobs) != 1 {
		t.Fatal("automatic retry after conflict", e)
	}
	out, e := f.s.moduleRemotePlans("remote-plans", core.AppModuleInput{})
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(fmt.Sprint(out), f.secret) {
		t.Fatal("credential disclosed")
	}
}

func TestRemoteSyncPlanReservationWriteFailureNeverReissuesID(t *testing.T) {
	f := newRemoteSyncFixture(t)
	p := remotePlanDue(t, f.s, newRemotePlanFixture(t, f, true))
	dir := filepath.Join(f.s.remoteSyncDir(), "jobs")
	outside := t.TempDir()
	if e := os.Symlink(outside, dir); e != nil {
		t.Fatal(e)
	}
	f.s.scheduleRemotePlans(time.Now().UTC())
	p = remotePlanReload(t, f.s, p.ID)
	if p.Enabled || p.LastState != "paused-error" || p.PendingJobID == "" {
		t.Fatal(p)
	}
	id := p.PendingJobID
	for i := 0; i < 3; i++ {
		f.s.scheduleRemotePlans(time.Now().UTC().Add(time.Hour))
	}
	p = remotePlanReload(t, f.s, p.ID)
	if p.PendingJobID != id {
		t.Fatal("replaced uncertain identity")
	}
	entries, e := os.ReadDir(outside)
	if e != nil || len(entries) != 0 {
		t.Fatal("write escaped private namespace", e)
	}
	if e = os.Remove(dir); e != nil {
		t.Fatal(e)
	}
	_, e = f.s.moduleRemotePlans("resume-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: p.Revision, RemoteTargetRevision: 1})
	if e != nil {
		t.Fatal("explicit confirmed absent-job resume failed", e)
	}
	p = remotePlanReload(t, f.s, p.ID)
	if p.LastJobID != id || p.PendingJobID != "" || !p.Enabled {
		t.Fatal("original reservation not retained", p)
	}
}

func TestRemoteSyncPlanPauseQueuedResumeAndRemovalTombstone(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "not-yet")
	p := remotePlanDue(t, f.s, newRemotePlanFixture(t, f, true))
	f.s.scheduleRemotePlans(time.Now().UTC())
	p = remotePlanReload(t, f.s, p.ID)
	id := p.PendingJobID
	if _, e := f.s.moduleRemotePlans("pause-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: p.Revision}); e != nil {
		t.Fatal(e)
	}
	p = remotePlanReload(t, f.s, p.ID)
	if p.Enabled || p.Revision != 2 {
		t.Fatal(p)
	}
	f.s.runOneRemoteSyncJob(context.Background())
	if _, e := os.Stat(filepath.Join(f.root, "copy.txt")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("paused queued job wrote", e)
	}
	j, e := f.s.readRemoteJob(id)
	if e != nil || j.State != "failed" {
		t.Fatal(j, e)
	}
	if _, e = f.s.moduleRemotePlans("resume-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: p.Revision, RemoteTargetRevision: 1}); e != nil {
		t.Fatal(e)
	}
	p = remotePlanReload(t, f.s, p.ID)
	if p.PendingJobID != "" || p.LastJobID != id || p.Revision != 3 {
		t.Fatal(p)
	}
	if _, e = f.s.moduleRemotePlans("remove-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: p.Revision}); e != nil {
		t.Fatal(e)
	}
	p = remotePlanReload(t, f.s, p.ID)
	if p.Enabled || p.LastState != "removed" || p.LastJobID != id || p.Revision != 4 {
		t.Fatal("removal deleted identity or evidence", p)
	}
	if _, e = f.s.readRemoteJob(id); e != nil {
		t.Fatal("original job lost", e)
	}
	if e = f.s.remoteSyncUninstallPreflight(); e != nil {
		t.Fatal("inactive terminal plan prevents safe uninstall", e)
	}
}

func TestRemoteSyncPlanCredentialRevisionChangeRequiresExplicitReapproval(t *testing.T) {
	f := newRemoteSyncFixture(t)
	p := remotePlanDue(t, f.s, newRemotePlanFixture(t, f, true))
	_, e := f.s.moduleRemoteSync(context.Background(), "save-remote", core.AppModuleInput{RemoteTargetID: f.cfg.ID, RemoteTarget: &f.cfg.Target, Enabled: true, ExpectedRevision: 1, Password: f.secret})
	if e != nil {
		t.Fatal(e)
	}
	f.s.scheduleRemotePlans(time.Now().UTC())
	p = remotePlanReload(t, f.s, p.ID)
	if p.Enabled || p.PendingJobID != "" || p.LastState != "paused-error" {
		t.Fatal(p)
	}
	for _, rev := range []int64{0, 1} {
		if _, e = f.s.moduleRemotePlans("resume-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: p.Revision, RemoteTargetRevision: rev}); e == nil {
			t.Fatal("stale connection revision approved", rev)
		}
	}
	if _, e = f.s.moduleRemotePlans("resume-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: p.Revision, RemoteTargetRevision: 2}); e != nil {
		t.Fatal(e)
	}
	p = remotePlanReload(t, f.s, p.ID)
	if !p.Enabled || p.TargetRevision != 2 || p.Revision != 2 {
		t.Fatal(p)
	}
}

func TestRemoteSyncPlanPerFilePauseFenceDuringRealSFTP(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "a.txt", "first")
	fixtureWrite(t, f.s, f.site, "z.txt", "must-not-copy")
	p := remotePlanDue(t, f.s, newRemotePlanFixture(t, f, true))
	f.s.scheduleRemotePlans(time.Now().UTC())
	p = remotePlanReload(t, f.s, p.ID)
	j, e := f.s.readRemoteJob(p.PendingJobID)
	if e != nil {
		t.Fatal(e)
	}
	j.State = "running"
	j.StartedAt = core.Now()
	if e = moduleWrite(f.s.remoteJobPath(j.ID), j); e != nil {
		t.Fatal(e)
	}
	paused := false
	guard := func() error {
		if j.Copied == 1 && !paused {
			paused = true
			if _, e := f.s.moduleRemotePlans("pause-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: p.Revision}); e != nil {
				t.Fatal(e)
			}
		}
		return f.s.remotePlanJobAllowed(j)
	}
	if e = f.s.executeRemoteSync(context.Background(), f.cfg, &j, guard); e == nil || !paused || j.Copied != 1 {
		t.Fatal("pause fence ineffective", j, e)
	}
	b, e := os.ReadFile(filepath.Join(f.root, "a.txt"))
	if e != nil || string(b) != "first" {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(f.root, "z.txt")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("next file written after plan paused", e)
	}
	cp, e := f.s.readRemoteCheckpoint(f.cfg, f.site)
	if e != nil || cp.Pending != nil || len(cp.Files) != 1 {
		t.Fatal("completed checkpoint lost", cp, e)
	}
	t.Log("PASS actual native SFTP plan revision fence preserves completed file and blocks subsequent file after pause")
}

func TestRemoteSyncPlanUnsafeRecordsAndPersistenceFence(t *testing.T) {
	f := newRemoteSyncFixture(t)
	p := newRemotePlanFixture(t, f, true)
	before, e := os.ReadFile(f.s.remotePlanPath(p.ID))
	if e != nil {
		t.Fatal(e)
	}
	backup := f.s.remotePlanPath(p.ID) + ".preserved"
	if e = os.Rename(f.s.remotePlanPath(p.ID), backup); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(f.s.remotePlanPath(p.ID), 0700); e != nil {
		t.Fatal(e)
	}
	if e = f.s.writeRemotePlan(p); e == nil || !f.s.moduleAutoBlocked[remotePlanBlockedID(p.ID)] {
		t.Fatal("persistence failure did not fence automation", e)
	}
	if e = os.Remove(f.s.remotePlanPath(p.ID)); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(backup, f.s.remotePlanPath(p.ID)); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(f.s.remotePlanPath(p.ID))
	if e != nil || !bytes.Equal(before, got) {
		t.Fatal("original record modified", e)
	}
	f.s.scheduleRemotePlans(time.Now().UTC().Add(time.Hour))
	jobs, e := f.s.allRemoteJobs()
	if e != nil || len(jobs) != 0 {
		t.Fatal("in-memory persistence fence bypassed", e)
	}
	if e = os.Chmod(f.s.remotePlanPath(p.ID), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.allRemotePlans(); e == nil {
		t.Fatal("public private record accepted")
	}
	if e = os.Chmod(f.s.remotePlanPath(p.ID), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(f.s.remoteSyncDir(), "plans", "unknown"), []byte("evidence"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.allRemotePlans(); e == nil {
		t.Fatal("unknown plan evidence ignored")
	}
}

func TestRemoteSyncPlanRestartRunningTaskPausesWithoutRetransfer(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "not-retransmitted")
	p := remotePlanDue(t, f.s, newRemotePlanFixture(t, f, true))
	f.s.scheduleRemotePlans(time.Now().UTC())
	p = remotePlanReload(t, f.s, p.ID)
	j, e := f.s.readRemoteJob(p.PendingJobID)
	if e != nil {
		t.Fatal(e)
	}
	j.State = "running"
	j.StartedAt = core.Now()
	if e = moduleWrite(f.s.remoteJobPath(j.ID), j); e != nil {
		t.Fatal(e)
	}
	fresh := New(f.s.Config)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { fresh.runRemoteSyncWorker(ctx); close(done) }()
	deadline := time.Now().Add(9 * time.Second)
	for {
		fresh.mu.Lock()
		p, e = fresh.readRemotePlan(p.ID)
		fresh.mu.Unlock()
		if e != nil {
			t.Fatal(e)
		}
		if !p.Enabled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restart did not pause plan")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	j, e = fresh.readRemoteJob(j.ID)
	if e != nil || j.State != "interrupted" || p.PendingJobID != j.ID {
		t.Fatal(j, p, e)
	}
	if _, e = os.Stat(filepath.Join(f.root, "copy.txt")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("restart blindly retransferred", e)
	}
}

func TestRemoteSyncPlanTrueSIGKILLAfterDurableReservation(t *testing.T) {
	if base := os.Getenv("PANEL_REMOTE_PLAN_KILL_CHILD"); base != "" {
		if !filepath.IsAbs(base) || !strings.Contains(base, "TestRemoteSyncPlanTrueSIGKILLAfterDurableReservation") || filepath.Base(base) != "security" {
			t.Fatal("not own fixture")
		}
		s := New(Config{SecurityDir: base})
		p, e := s.readRemotePlan("periodic-one")
		if e != nil {
			t.Fatal(e)
		}
		p.PendingJobID = core.ID()
		p.LastState = "queueing"
		if e = s.writeRemotePlan(p); e != nil {
			t.Fatal(e)
		}
		fmt.Fprintln(os.Stdout, "OWN_REMOTE_PLAN_DURABLE_READY_FOR_SIGKILL")
		select {}
	}
	f := newRemoteSyncFixture(t)
	p := newRemotePlanFixture(t, f, true)
	child := exec.Command(os.Args[0], "-test.run=^TestRemoteSyncPlanTrueSIGKILLAfterDurableReservation$", "-test.v", "-test.timeout=40s")
	child.Env = append(os.Environ(), "PANEL_REMOTE_PLAN_KILL_CHILD="+f.s.Config.SecurityDir)
	stdout, e := child.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	finished := false
	t.Cleanup(func() {
		if !finished {
			child.Process.Kill()
			child.Wait()
		}
	})
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "OWN_REMOTE_PLAN_DURABLE_READY_FOR_SIGKILL" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child did not durably reserve", stderr.String())
		}
	case <-time.After(12 * time.Second):
		t.Fatal("child reserve timed out")
	}
	p = remotePlanReload(t, f.s, p.ID)
	id := p.PendingJobID
	if id == "" || p.LastState != "queueing" {
		t.Fatal(p)
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	exit := child.Wait()
	finished = true
	var ee *exec.ExitError
	if !errors.As(exit, &ee) {
		t.Fatal("not killed", exit)
	}
	status, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("not true SIGKILL")
	}
	fresh := New(f.s.Config)
	fresh.scheduleRemotePlans(time.Now().UTC().Add(time.Hour))
	p = remotePlanReload(t, fresh, p.ID)
	if p.Enabled || p.LastState != "paused-error" || p.PendingJobID != id {
		t.Fatal("uncertain acceptance reissued", p)
	}
	jobs, e := fresh.allRemoteJobs()
	if e != nil || len(jobs) != 0 {
		t.Fatal("replacement accepted", e)
	}
	if _, e = fresh.readRemoteJob(id); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
	t.Log("PASS true SIGKILL after durable remote-plan reservation; actual new executor state retains original ID and pauses without a replacement or remote write")
}

func TestRemoteSyncPlanRealBackgroundTickAndPrivateBindings(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "actual-background")
	p := remotePlanDue(t, f.s, newRemotePlanFixture(t, f, true))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { f.s.runRemoteSyncWorker(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, e := os.ReadFile(filepath.Join(f.root, "copy.txt"))
		// A published path precedes directory fsync/checkpoint/job commit.
		// Cancelling at that intermediate point correctly interrupts SFTP;
		// it must not be confused with a completed production task.
		f.s.mu.Lock()
		current, planErr := f.s.readRemotePlan(p.ID)
		job, jobErr := f.s.readRemoteJob(current.PendingJobID)
		f.s.mu.Unlock()
		if planErr == nil && jobErr == nil && job.State != "queued" && job.State != "running" && job.State != "succeeded" {
			t.Fatal("actual background task ended unsuccessfully", job.State, job.Error)
		}
		if e == nil && string(b) == "actual-background" && planErr == nil && jobErr == nil && job.State == "succeeded" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real 5-second background tick did not transfer")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	p = remotePlanReload(t, f.s, p.ID)
	j, e := f.s.readRemoteJob(p.PendingJobID)
	if e != nil || j.State != "succeeded" {
		t.Fatal(j, e)
	}
	if j.PlanID != p.ID || j.PlanRevision != p.Revision || j.Revision != p.TargetRevision {
		t.Fatal("binding lost", j, p)
	}
	if !reflect.DeepEqual(j.Excludes, p.Excludes) {
		t.Fatal("excludes changed")
	}
	t.Log("PASS real production 5-second remote-plan background scheduler and actual native SFTP copy with browser absent; not a full external-network or 60-second cadence acceptance")
}

func TestRemoteSyncPlanTaskCapacityStopsWithoutEvidenceDeletion(t *testing.T) {
	f := newRemoteSyncFixture(t)
	p := remotePlanDue(t, f.s, newRemotePlanFixture(t, f, true))
	for i := 0; i < 128; i++ {
		j := remoteSyncJob{ID: core.ID(), TargetID: f.cfg.ID, SiteID: f.site, Revision: 1, SpecSHA: f.cfg.SpecSHA, Excludes: []string{}, Conflicts: []string{}, State: "succeeded", CreatedAt: core.Now(), FinishedAt: core.Now()}
		if e := moduleWrite(f.s.remoteJobPath(j.ID), j); e != nil {
			t.Fatal(e)
		}
	}
	f.s.scheduleRemotePlans(time.Now().UTC())
	p = remotePlanReload(t, f.s, p.ID)
	if p.Enabled || p.PendingJobID == "" || p.LastState != "paused-error" {
		t.Fatal("full queue not safely paused", p)
	}
	jobs, e := f.s.allRemoteJobs()
	if e != nil || len(jobs) != 128 {
		t.Fatal("deleted or replaced capacity evidence", e)
	}
}

func TestRemoteSyncPlanUnknownCancelKeepsReservationAndExplicitResume(t *testing.T) {
	f := newRemoteSyncFixture(t)
	p := newRemotePlanFixture(t, f, true)
	p.PendingJobID = core.ID()
	p.LastState = "queueing"
	if e := f.s.writeRemotePlan(p); e != nil {
		t.Fatal(e)
	}
	id := p.PendingJobID
	if _, e := f.s.moduleRemotePlans("pause-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: p.Revision}); e == nil {
		t.Fatal("unknown cancellation claimed confirmed")
	}
	p = remotePlanReload(t, f.s, p.ID)
	if p.Enabled || p.PendingJobID != id || p.LastState != "paused-error" {
		t.Fatal(p)
	}
	if _, e := f.s.moduleRemotePlans("resume-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: p.Revision, RemoteTargetRevision: 1}); e != nil {
		t.Fatal(e)
	}
	p = remotePlanReload(t, f.s, p.ID)
	if !p.Enabled || p.PendingJobID != "" || p.LastJobID != id {
		t.Fatal("unrecoverable uncertain reservation", p)
	}
}

func TestRemoteSyncPlanRemovedTerminalCanBeExplicitlyResaved(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "actual")
	p := remotePlanDue(t, f.s, newRemotePlanFixture(t, f, true))
	f.s.runOneRemoteSyncJob(context.Background())
	p = remotePlanReload(t, f.s, p.ID)
	id := p.PendingJobID
	if _, e := f.s.moduleRemotePlans("remove-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: p.Revision}); e != nil {
		t.Fatal(e)
	}
	p = remotePlanReload(t, f.s, p.ID)
	if _, e := f.s.moduleRemotePlans("schedule-remote-plan", core.AppModuleInput{ResourceID: p.ID, ExpectedRevision: p.Revision, RemoteTargetID: f.cfg.ID, RemoteTargetRevision: 1, SiteID: f.site, Interval: 120, Enabled: false}); e != nil {
		t.Fatal(e)
	}
	p = remotePlanReload(t, f.s, p.ID)
	if p.Enabled || p.PendingJobID != "" || p.LastJobID != id || p.Interval != 120 || p.Revision != 3 {
		t.Fatal("explicit tombstone reuse lost identity", p)
	}
	j, e := f.s.readRemoteJob(id)
	if e != nil || j.State != "succeeded" {
		t.Fatal("original result lost", j, e)
	}
}

func TestRemoteSyncPlanHTTPHistoryAndReportFailurePauseAcceptedPolicy(t *testing.T) {
	for _, name := range []string{"history.json", "last-report.json"} {
		t.Run(name, func(t *testing.T) {
			f := newRemoteSyncFixture(t)
			blocked := filepath.Join(f.s.moduleDir("files-sync"), name)
			if e := os.Mkdir(blocked, 0700); e != nil {
				t.Fatal(e)
			}
			input := core.AppModuleInput{ResourceID: "periodic-one", RemoteTargetID: f.cfg.ID, RemoteTargetRevision: 1, SiteID: f.site, Enabled: true, Interval: 60}
			body, e := json.Marshal(input)
			if e != nil {
				t.Fatal(e)
			}
			r := httptest.NewRequest("POST", "/v1/app-modules/files-sync/schedule-remote-plan", bytes.NewReader(body))
			w := httptest.NewRecorder()
			f.s.Handler().ServeHTTP(w, r)
			if w.Code != 409 && w.Code != 500 {
				t.Fatal("persistence failure claimed success", w.Code, w.Body.String())
			}
			p := remotePlanReload(t, f.s, input.ResourceID)
			if p.Enabled || p.LastState != "paused-error" || !f.s.moduleAutoBlocked[remotePlanBlockedID(p.ID)] {
				t.Fatal("accepted policy kept writing after report/history failure", p)
			}
			f.s.scheduleRemotePlans(time.Now().UTC().Add(time.Hour))
			jobs, e := f.s.allRemoteJobs()
			if e != nil || len(jobs) != 0 {
				t.Fatal("failed control persistence enqueued", e)
			}
		})
	}
}
