//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func independentCopyFixture(t *testing.T) (*remoteSyncFixture, string, core.AppModuleInput) {
	t.Helper()
	f, id, in := backupArchiveFixture(t)
	if _, err := f.s.moduleRemoteSync(t.Context(), "archive-remote-backup", in); err != nil {
		t.Fatal(err)
	}
	// Private unit fixture only; signed installed application acceptance remains
	// a separate normal package/update and Core/Root/native-server workflow.
	if err := moduleWrite(filepath.Join(f.s.moduleDir("files-sync"), "installed.json"), map[string]any{"id": "files-sync", "version": appcatalog.FilesSyncIndependentBackupVersion, "settings": map[string]any{}, "installed_at": core.Now()}); err != nil {
		t.Fatal(err)
	}
	in.Confirm = "COPY BACKUP " + id
	return f, id, in
}
func seedIndependentAttempt(t *testing.T, f *remoteSyncFixture, id string, content []byte) (remoteCopyRecord, string, string) {
	t.Helper()
	source, err := f.s.readRemoteBackupArchiveRecord(f.cfg.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	d, err := f.s.remoteCopyDirectory(f.cfg.ID, id, "", true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = remoteCopyPublish(d, "intent.json", remoteCopyIntent{Format: 1, Version: appcatalog.FilesSyncIndependentBackupVersion, Source: source, CreatedAt: core.Now()})
	d.Close()
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.s.readRemoteCopyRecord(f.cfg.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	attempt := core.ID()
	d, err = f.s.remoteCopyDirectory(f.cfg.ID, id, attempt, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = remoteCopyPublish(d, "attempt.json", remoteCopyAttempt{Format: 1, ID: attempt, IntentSHA: r.SHA, CreatedAt: core.Now()})
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	file := filepath.Join(d.paths[len(d.paths)-1], source.Snapshot.Files[0].Name)
	if content != nil {
		if err = os.WriteFile(file, content, 0600); err != nil {
			d.Close()
			t.Fatal(err)
		}
	}
	d.Close()
	r, err = f.s.readRemoteCopyRecord(f.cfg.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	return r, attempt, file
}
func independentOriginal(t *testing.T, f *remoteSyncFixture, id string) (remoteCopyRecord, string) {
	t.Helper()
	r, err := f.s.readRemoteCopyRecord(f.cfg.ID, id)
	if err != nil || r.Result == nil || len(r.Result.Files) != 1 {
		t.Fatal(r, err)
	}
	d, err := f.s.remoteCopyDirectory(f.cfg.ID, id, r.Result.AttemptID, false)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(d.paths[len(d.paths)-1], r.Result.Files[0].Name)
	d.Close()
	return r, file
}
func TestRemoteIndependentCopyHeldRemoteWriterCannotChangePrivateBytes(t *testing.T) {
	f, id, in := independentCopyFixture(t)
	_, _, remote := remoteBackupArchivePaths(f.cfg, id)
	old, err := os.OpenFile(filepath.Join(remote, "staged"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	publicBefore, _ := os.ReadFile(filepath.Join(f.root, "copy.txt"))
	checkpointBefore, _ := os.ReadFile(f.s.remoteCheckpointPath(f.cfg.ID))
	archiveRecordBefore, _ := os.ReadFile(f.s.remoteBackupArchiveRecordPath(f.cfg.ID, id))
	if _, err = f.s.moduleRemoteSync(t.Context(), "copy-remote-backup", in); err != nil {
		t.Fatal(err)
	}
	r, local := independentOriginal(t, f, id)
	info, _ := os.Stat(local)
	before, _ := os.ReadFile(local)
	if string(before) != "old" || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatal("not an actual exclusive private copy", string(before), info)
	}
	if _, err = old.WriteAt([]byte("BAD"), 0); err != nil || old.Sync() != nil {
		t.Fatal(err)
	}
	remoteBytes, _ := os.ReadFile(filepath.Join(remote, "staged"))
	after, _ := os.ReadFile(local)
	if string(remoteBytes) != "BAD" || !reflect.DeepEqual(before, after) {
		t.Fatal("held remote writer affected independent bytes")
	}
	if err = f.s.verifyRemoteCopy(r); err != nil {
		t.Fatal(err)
	}
	f.listener.Close() // The complete copy and download must work offline.
	in = core.AppModuleInput{RemoteTargetID: f.cfg.ID, ExpectedRevision: f.cfg.Revision, ResourceID: id}
	if _, err = f.s.moduleRemoteSync(t.Context(), "verify-remote-copy", in); err != nil {
		t.Fatal("offline verification connected to remote", err)
	}
	chunk, err := f.s.remoteIndependentChunk(f.cfg.ID, id, "staged", 0, r.SHA)
	if err != nil || string(chunk.Bytes) != "old" || chunk.FileSHA != core.Hash("old") {
		t.Fatal(chunk, err)
	}
	publicAfter, _ := os.ReadFile(filepath.Join(f.root, "copy.txt"))
	checkpointAfter, _ := os.ReadFile(f.s.remoteCheckpointPath(f.cfg.ID))
	archiveRecordAfter, _ := os.ReadFile(f.s.remoteBackupArchiveRecordPath(f.cfg.ID, id))
	if !reflect.DeepEqual(publicBefore, publicAfter) || !reflect.DeepEqual(checkpointBefore, checkpointAfter) || !reflect.DeepEqual(archiveRecordBefore, archiveRecordAfter) {
		t.Fatal("copy changed original target, checkpoint or archive authority")
	}
}
func TestRemoteIndependentCopyRejectsChangedSourceBeforeLocalPublication(t *testing.T) {
	f, id, in := independentCopyFixture(t)
	_, _, remote := remoteBackupArchivePaths(f.cfg, id)
	if err := os.WriteFile(filepath.Join(remote, "staged"), []byte("BAD"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.moduleRemoteSync(t.Context(), "copy-remote-backup", in); err == nil {
		t.Fatal("changed original bytes accepted")
	}
	if _, err := os.Lstat(filepath.Join(f.s.remoteSyncDir(), "independent-backups")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("new local copy namespace published for changed source", err)
	}
}
func TestRemoteIndependentCopyRecoveryKeepsOriginalPartialAttempt(t *testing.T) {
	f, id, in := independentCopyFixture(t)
	original, oldAttempt, partial := seedIndependentAttempt(t, f, id, []byte("o"))
	before, _ := os.Stat(partial)
	if _, err := f.s.moduleRemoteSync(t.Context(), "copy-remote-backup", in); err == nil {
		t.Fatal("copy was replayed over incomplete original")
	}
	if pending, err := f.s.remoteCopyPending(f.cfg.ID, ""); err != nil || !pending {
		t.Fatal(pending, err)
	}
	in.Confirm = "RECOVER COPY " + id
	in.ExpectedSHA = remoteCopyStateSHA(original)
	if _, err := f.s.moduleRemoteSync(t.Context(), "recover-remote-copy", in); err != nil {
		t.Fatal(err)
	}
	r, _ := independentOriginal(t, f, id)
	after, _ := os.Stat(partial)
	data, _ := os.ReadFile(partial)
	if !os.SameFile(before, after) || string(data) != "o" || len(r.Attempts) != 2 || r.Result.AttemptID == oldAttempt || r.Bytes != 4 {
		t.Fatal("partial fragment was truncated, replaced or hidden", r, string(data))
	}
	if pending, err := f.s.remoteCopyPending(f.cfg.ID, ""); err != nil || pending {
		t.Fatal(pending, err)
	}
}
func TestRemoteIndependentCopyRecoveryConfirmsExistingCompleteAttemptOffline(t *testing.T) {
	f, id, in := independentCopyFixture(t)
	original, attempt, file := seedIndependentAttempt(t, f, id, []byte("old"))
	before, _ := os.Stat(file)
	f.listener.Close()
	in.Confirm = "RECOVER COPY " + id
	in.ExpectedSHA = remoteCopyStateSHA(original)
	out, err := f.s.moduleRemoteSync(t.Context(), "recover-remote-copy", in)
	if err != nil || out.(map[string]any)["remote_connected"] != false || out.(map[string]any)["used_existing_complete_attempt"] != true {
		t.Fatal(out, err)
	}
	r, _ := independentOriginal(t, f, id)
	after, _ := os.Stat(file)
	if r.Result.AttemptID != attempt || len(r.Attempts) != 1 || !os.SameFile(before, after) {
		t.Fatal("complete original was copied a second time")
	}
}
func TestRemoteIndependentCopyRetainsPartialWithoutDeclaringSuccess(t *testing.T) {
	f, id, in := independentCopyFixture(t)
	r, _, file := seedIndependentAttempt(t, f, id, []byte("o"))
	before, _ := os.Stat(file)
	f.listener.Close()
	in.ExpectedSHA, in.Confirm = remoteCopyStateSHA(r), "RETAIN COPY "+id
	out, err := f.s.moduleRemoteSync(t.Context(), "retain-remote-copy", in)
	if err != nil || out.(map[string]any)["backup_complete"] != false {
		t.Fatal(out, err)
	}
	r, err = f.s.readRemoteCopyRecord(f.cfg.ID, id)
	if err != nil || r.Retained == nil || r.Result != nil || len(r.Retained.Files) != 1 || r.Retained.Files[0].SHA != core.Hash("o") {
		t.Fatal(r, err)
	}
	after, _ := os.Stat(file)
	if !os.SameFile(before, after) || remoteCopyPublic(r, f.cfg.Revision, false)["independent_copy_state"] != "retained-incomplete" {
		t.Fatal("fragment lost its original identity or became a completed backup")
	}
	if pending, err := f.s.remoteCopyPending(f.cfg.ID, ""); err != nil || pending {
		t.Fatal(pending, err)
	}
	if _, err = f.s.remoteIndependentChunk(f.cfg.ID, id, "staged", 0, r.SHA); err == nil {
		t.Fatal("incomplete fragment downloaded as an original complete file")
	}
}
func TestRemoteIndependentCopyRejectsLinkedPrivateFragment(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			f, id, _ := independentCopyFixture(t)
			_, _, file := seedIndependentAttempt(t, f, id, nil)
			outside := filepath.Join(t.TempDir(), "original")
			if err := os.WriteFile(outside, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			link := os.Link
			if kind == "symlink" {
				link = os.Symlink
			}
			if err := link(outside, file); err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.readRemoteCopyRecord(f.cfg.ID, id); err == nil {
				t.Fatal("linked fragment treated as a private independent copy")
			}
			b, _ := os.ReadFile(outside)
			if string(b) != "old" {
				t.Fatal("outside bytes changed")
			}
		})
	}
}
func TestRemoteIndependentCopyRefusesOldInstalledVersion(t *testing.T) {
	f, _, in := independentCopyFixture(t)
	if err := moduleWrite(filepath.Join(f.s.moduleDir("files-sync"), "installed.json"), map[string]any{"id": "files-sync", "version": "1.9.0", "installed_at": core.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.moduleRemoteSync(context.Background(), "copy-remote-backup", in); err == nil {
		t.Fatal("new label capability borrowed from old installation")
	}
}

func TestRemoteIndependentCopyRecoveryRejectsStaleAttemptState(t *testing.T) {
	f, id, in := independentCopyFixture(t)
	original, _, partial := seedIndependentAttempt(t, f, id, []byte("o"))
	before, _ := os.Stat(partial)
	in.ExpectedSHA, in.Confirm = remoteCopyStateSHA(original), "RECOVER COPY "+id
	attempt := core.ID()
	d, err := f.s.remoteCopyDirectory(f.cfg.ID, id, attempt, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = remoteCopyPublish(d, "attempt.json", remoteCopyAttempt{Format: 1, ID: attempt, IntentSHA: original.SHA, CreatedAt: core.Now()})
	d.Close()
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.s.readRemoteCopyRecord(f.cfg.ID, id)
	if err != nil || remoteCopyStateSHA(current) == in.ExpectedSHA {
		t.Fatal(current, err)
	}
	if _, err = f.s.moduleRemoteSync(t.Context(), "recover-remote-copy", in); err == nil {
		t.Fatal("late request admitted a second new attempt")
	}
	after, err := f.s.readRemoteCopyRecord(f.cfg.ID, id)
	if err != nil || !reflect.DeepEqual(current, after) {
		t.Fatal("stale request changed original record", err)
	}
	info, _ := os.Stat(partial)
	data, _ := os.ReadFile(partial)
	if !os.SameFile(before, info) || string(data) != "o" {
		t.Fatal("original fragment changed")
	}
}

func TestRemoteIndependentCopyAttemptLimitPreservesEveryFragment(t *testing.T) {
	f, id, in := independentCopyFixture(t)
	original, _, partial := seedIndependentAttempt(t, f, id, []byte("o"))
	for n := 1; n < remoteCopyMaxAttempts; n++ {
		attempt := core.ID()
		d, err := f.s.remoteCopyDirectory(f.cfg.ID, id, attempt, true)
		if err != nil {
			t.Fatal(err)
		}
		_, err = remoteCopyPublish(d, "attempt.json", remoteCopyAttempt{Format: 1, ID: attempt, IntentSHA: original.SHA, CreatedAt: core.Now()})
		if err == nil {
			file, openErr := d.OpenFile("staged", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			err = openErr
			if err == nil {
				_, err = file.Write([]byte("o"))
				closeErr := file.Close()
				if err == nil {
					err = closeErr
				}
			}
		}
		d.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	before, err := f.s.readRemoteCopyRecord(f.cfg.ID, id)
	if err != nil || len(before.Attempts) != 8 || before.Bytes != 8 {
		t.Fatal(before, err)
	}
	in.ExpectedSHA, in.Confirm = remoteCopyStateSHA(before), "RECOVER COPY "+id
	if _, err = f.s.moduleRemoteSync(t.Context(), "recover-remote-copy", in); err == nil {
		t.Fatal("attempt budget silently exceeded")
	}
	after, err := f.s.readRemoteCopyRecord(f.cfg.ID, id)
	data, _ := os.ReadFile(partial)
	if err != nil || !reflect.DeepEqual(before, after) || string(data) != "o" {
		t.Fatal("capacity refusal deleted or rewrote old fragments", err)
	}
}

func TestRemoteIndependentCopyUnknownOrNoncanonicalRecordsFailClosed(t *testing.T) {
	for _, kind := range []string{"unknown-entry", "noncanonical-intent", "missing-intent"} {
		t.Run(kind, func(t *testing.T) {
			f, id, in := independentCopyFixture(t)
			original, _, partial := seedIndependentAttempt(t, f, id, []byte("o"))
			base := filepath.Dir(filepath.Dir(filepath.Dir(partial)))
			switch kind {
			case "unknown-entry":
				if err := os.WriteFile(filepath.Join(base, "unknown.json"), []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
			case "noncanonical-intent":
				p := filepath.Join(base, "intent.json")
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(p, append(b, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-intent":
				if err := os.Rename(filepath.Join(base, "intent.json"), filepath.Join(base, "original-intent-preserved.json")); err != nil {
					t.Fatal(err)
				}
			}
			in.ExpectedSHA, in.Confirm = remoteCopyStateSHA(original), "RECOVER COPY "+id
			if _, err := f.s.moduleRemoteSync(t.Context(), "recover-remote-copy", in); err == nil {
				t.Fatal("unknown record was automatically adopted")
			}
			if _, _, err := f.s.allRemoteCopyRecords(); err == nil {
				t.Fatal("incomplete inventory declared valid")
			}
			data, _ := os.ReadFile(partial)
			if string(data) != "o" {
				t.Fatal("unknown original fragment changed")
			}
		})
	}
}
