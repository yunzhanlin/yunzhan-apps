//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"

	"local/panel/internal/core"
)

func TestRemoteBackupFilesystemSpaceAdmission(t *testing.T) {
	stats := func(blocks, inodes, flags uint64) *sftp.StatVFS {
		return &sftp.StatVFS{Frsize: 4096, Blocks: 16384, Bfree: 400, Bavail: blocks, Files: 200, Favail: inodes, Flag: flags}
	}
	cases := []struct {
		name  string
		stats *sftp.StatVFS
		size  int64
		state string
		err   error
	}{
		{"non-root blocks", stats(1, 200, 0), 1, "available", errRemoteBackupSpace},
		{"partial block rounded up", stats(2, 200, 0), 4097, "available", errRemoteBackupSpace},
		{"exact space", stats(3, 2, 0), 4097, "available", nil},
		{"empty stage needs directory", stats(0, 200, 0), 0, "available", errRemoteBackupSpace},
		{"inodes", stats(30, 1, 0), 4096, "available", errRemoteBackupSpace},
		{"read-only", stats(30, 200, 1), 4096, "read_only", errRemoteBackupReadOnly},
		{"no bounded inode inventory", &sftp.StatVFS{Frsize: 4096, Blocks: 10, Bavail: 3, Favail: ^uint64(0)}, 4097, "available", nil},
		{"invalid stats", stats(^uint64(0), 200, 0), 4096, "unavailable", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			space := remoteBackupSpaceFromStats(c.stats)
			if err := space.admit(c.size); space.state != c.state || !errors.Is(err, c.err) {
				t.Fatalf("capacity state %s, admission %v", space.state, err)
			}
		})
	}
}

func TestRemoteSyncNativeFilesystemExhaustionPreservesExistingFiles(t *testing.T) {
	mode := os.Getenv("PANEL_REMOTE_SYNC_FULL_TMPFS")
	if mode == "" {
		t.Skip("requires an explicitly owned bounded native tmpfs")
	}
	if mode != "bytes" && mode != "inodes" {
		t.Fatal("unknown native fixture mode")
	}
	filler := os.Getenv("PANEL_REMOTE_SYNC_FULL_TMPFS_ROOT")
	var fs unix.Statfs_t
	if err := unix.Statfs(filler, &fs); err != nil || fs.Type != unix.TMPFS_MAGIC ||
		fs.Bsize <= 0 || fs.Blocks > (16<<20)/uint64(fs.Bsize) || fs.Files == 0 || fs.Files > 1024 ||
		!strings.HasPrefix(filler, "/var/tmp/panel-c148-sftp-") {
		t.Fatal("capacity exhaustion requires a dedicated bounded tmpfs", err)
	}
	base, err := os.MkdirTemp(filler, "remote-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	f := newRemoteSyncFixtureAt(t, base)
	original := filepath.Join(f.root, "a-copy.txt")
	const originalContent = "old remote content"
	fixtureWrite(t, f.s, f.site, "a-copy.txt", originalContent)
	if first := f.run(t, core.ID()); first.State != "succeeded" {
		t.Fatal(first)
	}
	stageDir := filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID)
	entries, err := os.ReadDir(stageDir)
	if err != nil || len(entries) != 1 {
		t.Fatal(err, entries)
	}
	priorStage := filepath.Join(stageDir, entries[0].Name(), "staged")
	originalMeta, err := os.Stat(original)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := os.ReadFile(f.s.remoteCheckpointPath(f.cfg.ID))
	if err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, f.s, f.site, "a-copy.txt", "new remote content")
	fillDir, err := os.MkdirTemp(filler, "capacity-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(fillDir) })
	if err = unix.Statfs(filler, &fs); err != nil {
		t.Fatal(err)
	}
	if mode == "bytes" {
		available := fs.Bavail * uint64(fs.Bsize)
		if available == 0 {
			t.Fatal("insufficient space to arrange a controlled refusal", available)
		}
		file, err := os.Create(filepath.Join(fillDir, "allocated"))
		if err != nil {
			t.Fatal(err)
		}
		if err = unix.Fallocate(int(file.Fd()), 0, 0, int64(available)); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		for i := 0; i < int(fs.Ffree); i++ {
			if err = os.WriteFile(filepath.Join(fillDir, fmt.Sprint(i)), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	report, err := f.s.moduleRemoteSync(context.Background(), "remote-backups", remoteBackupQuery(f))
	if err != nil {
		t.Fatal(err)
	}
	value := report.(map[string]any)
	if value["remote_filesystem_capacity_state"] != "available" ||
		mode == "bytes" && value["remote_filesystem_available_bytes"] != uint64(0) ||
		mode == "inodes" && value["remote_filesystem_available_inodes"] != uint64(0) {
		t.Fatal("read-only SFTP query failed to report actual capacity", value)
	}
	j := f.run(t, core.ID())
	if j.State != "failed" || j.Copied != 0 || !strings.Contains(j.Error, errRemoteBackupSpace.Error()) {
		t.Fatal("unexpected job outcome under native SFTP capacity exhaustion", j)
	}
	preserved, err := os.Stat(original)
	if err != nil || !os.SameFile(originalMeta, preserved) || remoteFixtureRead(t, original) != originalContent || remoteFixtureRead(t, priorStage) != originalContent {
		t.Fatal("prior files changed during failed admission", err)
	}
	after, err := os.ReadFile(f.s.remoteCheckpointPath(f.cfg.ID))
	if err != nil || string(after) != string(checkpoint) {
		t.Fatal("admission changed the original checkpoint", err)
	}
	afterEntries, err := os.ReadDir(stageDir)
	if err != nil || len(afterEntries) != len(entries) {
		t.Fatal("admission created a transaction or changed the inventory", afterEntries, err)
	}
	if err = os.RemoveAll(fillDir); err != nil {
		t.Fatal(err)
	}
	if resumed := f.run(t, core.ID()); resumed.State != "succeeded" || resumed.Copied != 1 {
		t.Fatal("a new explicit request did not resume successfully", resumed)
	}
	t.Log("PASS native SFTP capacity query, refusal before staging, original inode/backup/checkpoint and new explicit request")
}

func TestRemoteSyncNativeExhaustionDuringStaging(t *testing.T) {
	root := os.Getenv("PANEL_REMOTE_SYNC_FULL_TMPFS_ROOT")
	if root == "" {
		t.Skip("requires an explicitly owned bounded native tmpfs")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil || fs.Type != unix.TMPFS_MAGIC ||
		fs.Bsize <= 0 || fs.Blocks > (16<<20)/uint64(fs.Bsize) || fs.Files == 0 || fs.Files > 1024 ||
		!strings.HasPrefix(root, "/var/tmp/panel-c148-sftp-") {
		t.Fatal("write exhaustion needs a dedicated bounded tmpfs", err)
	}
	dir, err := os.MkdirTemp(root, "during-upload-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := newRemoteSyncFixtureAt(t, dir)
	const oldContent = "original remote"
	const targetName = "copy.txt"
	fixtureWrite(t, f.s, f.site, targetName, oldContent)
	id := core.ID()
	if first := f.run(t, id); first.State != "succeeded" || first.Copied != 1 {
		t.Fatal("initial upload", first)
	}
	target := filepath.Join(f.root, targetName)
	original, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	data := strings.Repeat("x", 1<<20)
	fixtureWrite(t, f.s, f.site, targetName, data)
	f.queue(t, core.ID())
	backup := filepath.Join(f.backup, "yunzhan-sync-"+f.cfg.ID)
	gate := &remoteBackupReplyGate{source: backup, action: 14, reached: make(chan struct{}), release: make(chan struct{})}
	f.archiveReplyGate.Store(gate)
	unblock := func() {
		if f.archiveReplyGate.Swap(nil) != nil {
			close(gate.release)
		}
	}
	defer unblock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.s.runOneRemoteSyncJob(context.Background())
	}()
	select {
	case <-gate.reached:
	case <-done:
		t.Fatal("job returned before the real SFTP mkdir")
	case <-time.After(12 * time.Second):
		t.Fatal("the native staging transaction did not reach mkdir")
	}
	cp, err := f.s.readRemoteCheckpoint(f.cfg, f.site)
	if err != nil || cp.Pending == nil || cp.Pending.Stage != remoteStageUploading {
		t.Fatal("missing durable pre-upload state", cp.Pending, err)
	}
	_, staged, previous := remoteTransactionPaths(f.cfg, *cp.Pending)
	fill, err := os.CreateTemp(root, "allocated-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(fill.Name())
	if err = unix.Statfs(root, &fs); err != nil {
		fill.Close()
		t.Fatal(err)
	}
	available := fs.Bavail * uint64(fs.Bsize)
	if available <= 64<<10 {
		fill.Close()
		t.Fatal("tmpfs unexpectedly lacks capacity before filling it", available)
	}
	if err = unix.Fallocate(int(fill.Fd()), 0, 0, int64(available-(64<<10))); err != nil {
		fill.Close()
		t.Fatal(err)
	}
	if err := fill.Close(); err != nil {
		t.Fatal(err)
	}
	unblock()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("SFTP write did not return after the filesystem filled")
	}
	j, err := f.s.readRemoteJob(cp.Pending.JobID)
	if err != nil || j.State != "interrupted" || j.Copied != 0 {
		t.Fatal("expected interrupted original task", j, err)
	}
	stagedBytes := remoteFixtureRead(t, staged)
	if len(stagedBytes) == 0 || len(stagedBytes) >= len(data) || !strings.HasPrefix(data, stagedBytes) {
		t.Fatal("did not retain a genuine partial upload", len(stagedBytes))
	}
	if _, err := os.Lstat(previous); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial upload touched previous", err)
	}
	if err := os.Remove(fill.Name()); err != nil {
		t.Fatal(err)
	}
	out, err := f.s.recoverRemoteSync(context.Background(), f.cfg)
	if err != nil || out.(map[string]any)["outcome"] != "staging-aborted" {
		t.Fatal("could not explicitly recover the unchanged target", out, err)
	}
	after, err := os.Stat(target)
	if err != nil || !os.SameFile(original, after) || remoteFixtureRead(t, target) != oldContent ||
		remoteFixtureRead(t, staged) != stagedBytes {
		t.Fatal("explicit recovery changed original or partial staging", err)
	}
	settled, err := f.s.readRemoteCheckpoint(f.cfg, f.site)
	if err != nil || settled.Pending != nil || settled.Files[targetName] != cp.Files[targetName] {
		t.Fatal("could not settle only pending work", err)
	}
	if job := f.run(t, core.ID()); job.State != "succeeded" || job.Copied != 1 ||
		remoteFixtureRead(t, target) != data || remoteFixtureRead(t, staged) != stagedBytes {
		t.Fatal("new explicit submission did not converge while retaining evidence", job)
	}
	t.Logf("PASS native ENOSPC after admission retained %d staged bytes, original inode, and explicit recovery", len(stagedBytes))
}
