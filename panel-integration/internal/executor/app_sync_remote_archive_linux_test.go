//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func remoteArchiveInput(j remoteSyncJob) core.AppModuleInput {
	return core.AppModuleInput{RemoteRequestID: j.ID, ExpectedSHA: remoteJobSHA(j), Confirm: "ARCHIVE REMOTE " + j.ID}
}

func TestRemoteSyncArchiveKeepsReplayAndFreesQueueSlot(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "actual-before-archive")
	j := f.run(t, core.ID())
	if j.State != "succeeded" {
		t.Fatal(j)
	}
	old, e := os.ReadFile(f.s.remoteJobPath(j.ID))
	if e != nil {
		t.Fatal(e)
	}
	// Even a whitespace-only physical-record change invalidates confirmation.
	stale := remoteArchiveInput(j)
	old = append([]byte(" \n"), old...)
	if e = os.WriteFile(f.s.remoteJobPath(j.ID), old, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.archiveRemoteJob(stale); e == nil {
		t.Fatal("full physical record digest ignored whitespace change")
	}
	j, e = f.s.readRemoteJob(j.ID)
	if e != nil || remoteJobSHA(j) != core.Hash(string(old)) {
		t.Fatal("not exact file-byte digest", e)
	}
	info, e := os.Stat(f.s.remoteJobPath(j.ID))
	if e != nil {
		t.Fatal(e)
	}
	// Synthetic terminal records exercise capacity; only j is a real transfer.
	for i := 1; i < 128; i++ {
		record := j
		record.ID = core.ID()
		if e = moduleWrite(f.s.remoteJobPath(record.ID), record); e != nil {
			t.Fatal(e)
		}
	}
	in := core.AppModuleInput{RemoteRequestID: core.ID(), RemoteTargetID: f.cfg.ID, SiteID: f.site, ExpectedRevision: f.cfg.Revision}
	if _, e = f.s.queueRemoteSync(f.cfg, in); e == nil {
		t.Fatal("full active queue was accepted")
	}
	bad := remoteArchiveInput(j)
	bad.ExpectedSHA = strings.Repeat("0", 64)
	if _, e = f.s.archiveRemoteJob(bad); e == nil {
		t.Fatal("stale digest accepted")
	}
	out, e := f.s.archiveRemoteJob(remoteArchiveInput(j))
	if e != nil || out.(map[string]any)["remote_files_changed"] != false {
		t.Fatal(out, e)
	}
	after, e := os.ReadFile(f.s.remoteArchivePath(j.ID))
	if e != nil || !bytes.Equal(old, after) {
		t.Fatal("complete private record not retained", e)
	}
	archivedInfo, e := os.Stat(f.s.remoteArchivePath(j.ID))
	if e != nil || !os.SameFile(info, archivedInfo) || archivedInfo.Mode().Perm() != 0600 {
		t.Fatal("record identity/permissions changed", e)
	}
	if _, e = os.Lstat(f.s.remoteJobPath(j.ID)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("active record remained", e)
	}
	archived, e := f.s.readRemoteJob(j.ID)
	if e != nil || !archived.Archived || remoteJobSHA(archived) != remoteJobSHA(j) {
		t.Fatal("original identity changed", e)
	}
	if _, e = f.s.archiveRemoteJob(remoteArchiveInput(archived)); e != nil {
		t.Fatal("lost archive reply could not replay", e)
	}
	replay := in
	replay.RemoteRequestID = j.ID
	r, e := f.s.queueRemoteSync(f.cfg, replay)
	if e != nil || r.(map[string]any)["replayed"] != true || r.(map[string]any)["job"].(map[string]any)["job_archived"] != true {
		t.Fatal("original archived task requeued", r, e)
	}
	public := r.(map[string]any)["job"].(map[string]any)
	for _, key := range []string{"excludes", "spec_sha256", "cipher", "remote_private_key"} {
		if _, ok := public[key]; ok {
			t.Fatal("private policy exposed", key)
		}
	}
	replay.Excludes = []string{"changed"}
	if _, e = f.s.queueRemoteSync(f.cfg, replay); e == nil {
		t.Fatal("different original request adopted")
	}
	if _, e = f.s.queueRemoteSync(f.cfg, in); e != nil {
		t.Fatal("safe archive did not free active capacity", e)
	}
	if remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "actual-before-archive" || f.commands.Load() != 0 {
		t.Fatal("archive/replay executed remote content or commands")
	}
	t.Log("PASS actual private no-overwrite archive preserves inode, bytes and original replay; one active slot freed, remote bytes unchanged")
}

func TestRemoteSyncArchiveRejectsUnknownWorkAndUnsafeNamespaces(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "one")
	j := f.queue(t, core.ID())
	if _, e := f.s.archiveRemoteJob(remoteArchiveInput(j)); e == nil {
		t.Fatal("queued task archived")
	}
	f.s.runOneRemoteSyncJob(context.Background())
	j, e := f.s.readRemoteJob(j.ID)
	if e != nil || j.State != "succeeded" {
		t.Fatal(j, e)
	}
	bad := remoteArchiveInput(j)
	bad.Confirm = "ARCHIVE OTHER"
	if _, e = f.s.archiveRemoteJob(bad); e == nil {
		t.Fatal("incorrect confirmation accepted")
	}
	cp, e := f.s.readRemoteCheckpoint(f.cfg, f.site)
	if e != nil {
		t.Fatal(e)
	}
	cp.Pending = &remoteSyncPending{ID: core.ID(), JobID: core.ID(), Path: "copy.txt", New: moduleFile{SHA: core.Hash("two"), Size: 3, Mode: 0644}}
	if e = moduleWrite(f.s.remoteCheckpointPath(f.cfg.ID), cp); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.archiveRemoteJob(remoteArchiveInput(j)); e == nil {
		t.Fatal("pending checkpoint archived")
	}
	cp.Pending = nil
	if e = moduleWrite(f.s.remoteCheckpointPath(f.cfg.ID), cp); e != nil {
		t.Fatal(e)
	}
	archive := filepath.Join(f.s.remoteSyncDir(), "archive")
	outside := t.TempDir()
	if e = os.Symlink(outside, archive); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.readRemoteJob(j.ID); e == nil {
		t.Fatal("unsafe archive namespace ignored for active identity")
	}
	if _, e = f.s.queueRemoteSync(f.cfg, core.AppModuleInput{RemoteRequestID: core.ID(), SiteID: f.site, ExpectedRevision: f.cfg.Revision}); e == nil {
		t.Fatal("unsafe namespace accepted a new ID")
	}
	if e = os.Remove(archive); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(archive, 0755); e != nil {
		t.Fatal(e)
	}
	// The owned service uses umask 0077; explicitly establish and attest the
	// unsafe mode instead of mistaking a freshly tightened 0700 dir for public.
	if e = os.Chmod(archive, 0755); e != nil {
		t.Fatal(e)
	}
	if st, err := os.Lstat(archive); err != nil || st.Mode().Perm() != 0755 {
		t.Fatal("public-directory fixture not established", err)
	}
	if _, e = f.s.archiveRemoteJob(remoteArchiveInput(j)); e == nil {
		t.Fatal("public archive directory accepted")
	}
	if e = os.Chmod(archive, 0700); e != nil {
		t.Fatal(e)
	}
	if e = moduleWrite(f.s.remoteArchivePath(j.ID), j); e != nil {
		t.Fatal(e)
	}
	active, e := os.ReadFile(f.s.remoteJobPath(j.ID))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.archiveRemoteJob(remoteArchiveInput(j)); e == nil {
		t.Fatal("duplicate namespace was overwritten")
	}
	if bytesNow, e := os.ReadFile(f.s.remoteJobPath(j.ID)); e != nil || !bytes.Equal(bytesNow, active) {
		t.Fatal("duplicate refusal changed active record", e)
	}
	if e = os.Remove(f.s.remoteArchivePath(j.ID)); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(t.TempDir(), "extra-record-link")
	if e = os.Link(f.s.remoteJobPath(j.ID), link); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.archiveRemoteJob(remoteArchiveInput(j)); e == nil {
		t.Fatal("multiply linked job archived")
	}
	if e = os.Remove(link); e != nil {
		t.Fatal(e)
	}
	interrupted := j
	interrupted.State = "interrupted"
	if e = moduleWrite(f.s.remoteJobPath(j.ID), interrupted); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.archiveRemoteJob(remoteArchiveInput(interrupted)); e == nil {
		t.Fatal("unknown outcome archived")
	}
	if remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "one" {
		t.Fatal("archive refusal changed remote data")
	}
}

func TestRemoteSyncArchiveBoundsAndReadOnlyPagination(t *testing.T) {
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "actual-native")
	j := f.run(t, core.ID())
	if _, e := f.s.archiveRemoteJob(remoteArchiveInput(j)); e != nil {
		t.Fatal(e)
	}
	for i := 1; i < 40; i++ {
		copy := j
		copy.ID = core.ID()
		if e := moduleWrite(f.s.remoteArchivePath(copy.ID), copy); e != nil {
			t.Fatal(e)
		}
	}
	jobs, size, e := f.s.allArchivedRemoteJobs()
	if e != nil || len(jobs) != 40 || size <= 0 {
		t.Fatal(jobs, size, e)
	}
	before, e := os.ReadFile(f.s.remoteArchivePath(j.ID))
	if e != nil {
		t.Fatal(e)
	}
	report, e := f.s.remoteArchiveReport(core.AppModuleInput{Limit: 32, Offset: 32})
	if e != nil {
		t.Fatal(e)
	}
	v := report.(map[string]any)
	if v["total"] != 40 || len(v["remote_jobs"].([]map[string]any)) != 8 {
		t.Fatal("not paginated", v)
	}
	for _, in := range []core.AppModuleInput{{Limit: 33}, {Offset: 2049}, {Limit: -1}, {Offset: -1}} {
		if _, e = f.s.remoteArchiveReport(in); e == nil {
			t.Fatal("unbounded page accepted")
		}
	}
	after, e := os.ReadFile(f.s.remoteArchivePath(j.ID))
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("readonly listing mutated record", e)
	}
	unknown := filepath.Join(f.s.remoteSyncDir(), "archive", "unknown-entry")
	if e = os.WriteFile(unknown, []byte("unknown"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.remoteArchiveReport(core.AppModuleInput{}); e == nil {
		t.Fatal("partial inventory hid unknown file")
	}
	if e = os.Remove(unknown); e != nil {
		t.Fatal(e)
	}
	large := f.s.remoteArchivePath(core.ID())
	out, e := os.OpenFile(large, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = out.Truncate(4<<20 + 1); e != nil {
		t.Fatal(e)
	}
	out.Close()
	if _, e = f.s.remoteArchiveReport(core.AppModuleInput{}); e == nil {
		t.Fatal("oversized record accepted")
	}
	if e = os.Remove(large); e != nil {
		t.Fatal(e)
	}
	for i := 40; i <= remoteArchiveMaxJobs; i++ {
		copy := j
		copy.ID = core.ID()
		if e = moduleWrite(f.s.remoteArchivePath(copy.ID), copy); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = f.s.remoteArchiveReport(core.AppModuleInput{}); e == nil {
		t.Fatal("overflow silently truncated inventory")
	}
	if remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "actual-native" {
		t.Fatal("listing changed remote content")
	}
}

func TestRemoteSyncArchiveTrueProcessExitPreservesIdentity(t *testing.T) {
	if base := os.Getenv("PANEL_REMOTE_ARCHIVE_EXIT_CHILD"); base != "" {
		if !filepath.IsAbs(base) || !strings.Contains(base, "TestRemoteSyncArchiveTrueProcessExitPreservesIdentity") || filepath.Base(base) != "security" {
			t.Fatal("not owned test namespace")
		}
		s := New(Config{SecurityDir: base})
		j, e := s.readRemoteJob(os.Getenv("PANEL_REMOTE_ARCHIVE_EXIT_JOB"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.archiveRemoteJob(remoteArchiveInput(j)); e != nil {
			t.Fatal(e)
		}
		fmt.Fprintln(os.Stdout, "OWN_REMOTE_ARCHIVE_READY_FOR_SIGKILL")
		select {} // Parent kills this owned companion AFTER durable archive, not mid-rename.
	}
	f := newRemoteSyncFixture(t)
	fixtureWrite(t, f.s, f.site, "copy.txt", "actual-native-before-kill")
	j := f.run(t, core.ID())
	child := exec.Command(os.Args[0], "-test.run=^TestRemoteSyncArchiveTrueProcessExitPreservesIdentity$", "-test.v", "-test.timeout=40s")
	child.Env = append(os.Environ(), "PANEL_REMOTE_ARCHIVE_EXIT_CHILD="+f.s.Config.SecurityDir, "PANEL_REMOTE_ARCHIVE_EXIT_JOB="+j.ID)
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
			if scanner.Text() == "OWN_REMOTE_ARCHIVE_READY_FOR_SIGKILL" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child did not finish durable archive", stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("archive child readiness timed out")
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	e = child.Wait()
	finished = true
	var exit *exec.ExitError
	if !errors.As(e, &exit) {
		t.Fatal("not killed", e)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("not true SIGKILL", e)
	}
	fresh := New(f.s.Config)
	retained, e := fresh.readRemoteJob(j.ID)
	if e != nil || !retained.Archived || remoteJobSHA(retained) != remoteJobSHA(j) {
		t.Fatal("archive identity lost after actual process exit", e)
	}
	r, e := fresh.queueRemoteSync(f.cfg, core.AppModuleInput{RemoteRequestID: j.ID, SiteID: f.site, ExpectedRevision: f.cfg.Revision})
	if e != nil || r.(map[string]any)["replayed"] != true {
		t.Fatal("archived old ID reexecuted after restart", r, e)
	}
	active, e := fresh.allRemoteJobs()
	if e != nil || len(active) != 0 {
		t.Fatal("replay produced active task", e)
	}
	if remoteFixtureRead(t, filepath.Join(f.root, "copy.txt")) != "actual-native-before-kill" || !reflect.DeepEqual(retained.Conflicts, j.Conflicts) {
		t.Fatal("original record/remote data changed")
	}
	t.Log("PASS true SIGKILL after durable private task archive; new Service reads original ID without queueing transfer; not a mid-rename powercut claim")
}
