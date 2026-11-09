//go:build linux

package executor

import (
	"bytes"
	"errors"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func unpublishedFixture(t *testing.T, content []byte) (*Service, remoteSyncConfig, core.AppModuleInput, string) {
	t.Helper()
	s, _, _ := appReliabilityFixture(t)
	cfg := remoteSyncConfig{ID: "owned-target", Revision: 7, SpecSHA: core.Hash("current explicitly reviewed connection"), Enabled: false}
	id := core.ID()
	d, err := s.remoteCopyDirectory(cfg.ID, id, "", true)
	if err != nil {
		t.Fatal(err)
	}
	base := d.paths[len(d.paths)-1]
	if content != nil {
		f, err := d.OpenFile("record-"+core.ID()+".part", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(content); err != nil {
			t.Fatal(err)
		}
		if err = f.Sync(); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err = remoteCopySync(d); err != nil {
		t.Fatal(err)
	}
	d.Close()
	in := core.AppModuleInput{RemoteTargetID: cfg.ID, ExpectedRevision: cfg.Revision, ResourceID: id, Confirm: "RETAIN FRAGMENTS " + id}
	return s, cfg, in, base
}

func TestRemoteUnpublishedCopyOpaqueBytesRetainedWithoutBackupAuthority(t *testing.T) {
	// Intentionally incomplete and untrusted-looking bytes. They are hashed,
	// never decoded as an intent, remote identity, source or executable command.
	data := []byte(`{"format":1,"source":{"path":"/unrelated","sha256":"invented"},`)
	s, cfg, in, base := unpublishedFixture(t, data)
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	part := filepath.Join(base, entries[0].Name())
	before, _ := os.Lstat(part)
	originalDir, _ := os.Lstat(base)
	observed, err := s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID)
	if err != nil || observed.Retained != nil || len(observed.Snapshot.Fragments) != 1 || observed.Snapshot.Fragments[0].SHA != core.Hash(string(data)) {
		t.Fatal(observed, err)
	}
	if _, _, err := s.allRemoteCopyRecords(); err == nil {
		t.Fatal("unreviewed master absence silently unblocked normal copies")
	}
	in.ExpectedSHA = observed.SHA
	out, err := s.retainUnpublishedRemoteCopy(cfg, in)
	if err != nil {
		t.Fatal(err)
	}
	response := out.(map[string]any)
	row := response["unpublished_record"].(map[string]any)
	if response["backup_complete"] != false || row["backup_complete"] != false || row["source_authority"] != false || row["downloadable"] != false || row["fragment_state"] != "unpublished-retained" {
		t.Fatal("opaque fragments became a successful/downloadable backup", row)
	}
	current, err := s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID)
	if err != nil || current.Retained == nil || current.SHA != observed.SHA || !reflect.DeepEqual(current.Snapshot, observed.Snapshot) {
		t.Fatal(current, err)
	}
	after, _ := os.Lstat(part)
	afterDir, _ := os.Lstat(base)
	actual, _ := os.ReadFile(part)
	if !os.SameFile(before, after) || !os.SameFile(originalDir, afterDir) || !bytes.Equal(actual, data) || after.Mode().Perm() != 0600 || after.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatal("original directory, fragment bytes or inode changed")
	}
	retainedBefore, _ := os.Lstat(filepath.Join(base, remoteUnpublishedReceipt))
	if _, err = s.retainUnpublishedRemoteCopy(cfg, in); err != nil {
		t.Fatal("same condition did not observe original retained result", err)
	}
	retainedAfter, _ := os.Lstat(filepath.Join(base, remoteUnpublishedReceipt))
	if !os.SameFile(retainedBefore, retainedAfter) {
		t.Fatal("retention was replayed into a replacement receipt")
	}
	rows, total, count, err := s.remoteCopyBudget()
	if err != nil || len(rows) != 0 || count != 1 || total != 0 {
		t.Fatal("retained original namespace omitted or metadata presented as backup content", rows, total, count, err)
	}
	all, err := s.allRemoteCopyInventory()
	if err != nil || all.UnpublishedBytes != current.Bytes || all.UnpublishedBytes <= int64(len(data)) {
		t.Fatal("original fragments or closure receipt omitted from bounded metadata budget", all, err)
	}
	if _, err = s.readRemoteCopyRecord(cfg.ID, in.ResourceID); err == nil {
		t.Fatal("unpublished fragments became a normal source/copy record")
	}
	if _, err = s.remoteIndependentChunk(cfg.ID, in.ResourceID, "staged", 0, observed.SHA); err == nil {
		t.Fatal("unknown fragments were delivered as a complete source file")
	}
}

func TestRemoteUnpublishedCopyEmptyDurableDirectoryCanBeRetained(t *testing.T) {
	s, cfg, in, base := unpublishedFixture(t, nil)
	before, _ := os.Lstat(base)
	v, err := s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID)
	if err != nil || len(v.Snapshot.Fragments) != 0 || v.Bytes != 0 {
		t.Fatal(v, err)
	}
	in.ExpectedSHA = v.SHA
	if _, err = s.retainUnpublishedRemoteCopy(cfg, in); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Lstat(base)
	if !os.SameFile(before, after) {
		t.Fatal("original empty namespace replaced")
	}
	if _, err = os.Lstat(filepath.Join(base, "intent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing intent synthesized", err)
	}
}

func TestRemoteUnpublishedCopyStateChangeAndWrongAuthorityDoNotPublish(t *testing.T) {
	for _, kind := range []string{"stale-bytes", "wrong-target", "stale-revision", "wrong-confirmation", "old-copy-confirmation", "wrong-digest"} {
		t.Run(kind, func(t *testing.T) {
			s, cfg, in, base := unpublishedFixture(t, []byte("original opaque fragment"))
			v, err := s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID)
			if err != nil {
				t.Fatal(err)
			}
			in.ExpectedSHA = v.SHA
			switch kind {
			case "stale-bytes":
				if err := os.WriteFile(filepath.Join(base, v.Snapshot.Fragments[0].Name), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-target":
				in.RemoteTargetID = "other-target"
			case "stale-revision":
				in.ExpectedRevision--
			case "wrong-confirmation":
				in.Confirm = ""
			case "old-copy-confirmation":
				in.Confirm = "COPY BACKUP " + in.ResourceID
			case "wrong-digest":
				in.ExpectedSHA = core.Hash("unreviewed")
			}
			if _, err = s.retainUnpublishedRemoteCopy(cfg, in); err == nil {
				t.Fatal("unreviewed or stale retention accepted")
			}
			if _, err = os.Lstat(filepath.Join(base, remoteUnpublishedReceipt)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed condition created a receipt", err)
			}
		})
	}
}

func TestRemoteUnpublishedCopyRejectsExistingUnknownOrUnsafeEntries(t *testing.T) {
	for _, kind := range []string{"existing-intent", "attempt-directory", "source-file", "unknown-entry", "symlink", "hardlink", "wide-mode", "oversize", "too-many-parts", "corrupt-retention"} {
		t.Run(kind, func(t *testing.T) {
			s, cfg, in, base := unpublishedFixture(t, []byte("original"))
			entries, _ := os.ReadDir(base)
			original := filepath.Join(base, entries[0].Name())
			name := filepath.Join(base, "record-"+core.ID()+".part")
			switch kind {
			case "existing-intent":
				if err := os.WriteFile(filepath.Join(base, "intent.json"), []byte("partial"), 0600); err != nil {
					t.Fatal(err)
				}
			case "attempt-directory":
				if err := os.Mkdir(filepath.Join(base, "attempts"), 0700); err != nil {
					t.Fatal(err)
				}
			case "source-file":
				if err := os.WriteFile(filepath.Join(base, "staged"), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown-entry":
				if err := os.WriteFile(filepath.Join(base, "original-intent-preserved.json"), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(original, name); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(original, name); err != nil {
					t.Fatal(err)
				}
			case "wide-mode":
				if err := os.Chmod(original, 0644); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.Truncate(original, remoteCopyRecordLimit+1); err != nil {
					t.Fatal(err)
				}
			case "too-many-parts":
				for i := 0; i < remoteUnpublishedMaxParts; i++ {
					if err := os.WriteFile(filepath.Join(base, "record-"+core.ID()+".part"), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "corrupt-retention":
				if err := os.WriteFile(filepath.Join(base, remoteUnpublishedReceipt), []byte("partial"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID); err == nil {
				t.Fatal("unsafe or unknown namespace accepted", kind)
			}
			if _, err := s.allRemoteCopyInventory(); err == nil {
				t.Fatal("unsafe record omitted from full inventory", kind)
			}
			if _, err := os.Lstat(original); err != nil {
				t.Fatal("original evidence removed", err)
			}
		})
	}
}

func TestRemoteUnpublishedCopyForwardsOnlyExactRecoveryCapableVersion(t *testing.T) {
	s, cfg, _, base := unpublishedFixture(t, []byte("partial master"))
	installed := filepath.Join(s.moduleDir("files-sync"), "installed.json")
	if err := moduleWrite(installed, map[string]any{"id": "files-sync", "version": appcatalog.FilesSyncIndependentBackupVersion, "settings": map[string]any{}, "installed_at": core.Now()}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(base, func() string { e, _ := os.ReadDir(base); return e[0].Name() }()))
	if err := s.remoteCopyVersionPreflight(appcatalog.FilesSyncUnpublishedRetentionVersion, true); err != nil {
		t.Fatal("known original master absence blocked its exact forward inspection handler", err)
	}
	for _, version := range []string{appcatalog.FilesSyncIndependentBackupVersion, "1.9.0", "2.0.2", "2.0.1-compat1"} {
		if err := s.remoteCopyVersionPreflight(version, true); err == nil {
			t.Fatal("old/unknown label hid unpublished fragments", version)
		}
	}
	if _, err := s.moduleRemoteCopy(t.Context(), "remote-copy-fragments", core.AppModuleInput{RemoteTargetID: cfg.ID, ExpectedRevision: cfg.Revision}); err == nil || !strings.Contains(err.Error(), "2.0.1") {
		t.Fatal("old installed200 borrowed forensic action", err)
	}
	after, _ := os.ReadFile(filepath.Join(base, func() string { e, _ := os.ReadDir(base); return e[0].Name() }()))
	if !bytes.Equal(before, after) {
		t.Fatal("forward-version preflight changed original fragment")
	}
	if err := os.WriteFile(filepath.Join(base, "intent.json"), []byte("unknown existing intent"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.remoteCopyVersionPreflight(appcatalog.FilesSyncUnpublishedRetentionVersion, true); err == nil {
		t.Fatal("unknown existing intent bypassed original upgrade guard")
	}
}

func TestRemoteUnpublishedCopyDirectoryReplacementFencesOriginalObservation(t *testing.T) {
	s, cfg, in, base := unpublishedFixture(t, []byte("same bytes cannot replace the original namespace"))
	v, err := s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	in.ExpectedSHA = v.SHA
	preserved := filepath.Join(t.TempDir(), "original-directory")
	if err = os.Rename(base, preserved); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	name := v.Snapshot.Fragments[0].Name
	data, err := os.ReadFile(filepath.Join(preserved, name))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(base, name), data, 0600); err != nil {
		t.Fatal(err)
	}
	current, err := s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID)
	if err != nil || current.SHA == v.SHA {
		t.Fatal("same bytes borrowed the original directory identity", err)
	}
	if _, err = s.retainUnpublishedRemoteCopy(cfg, in); err == nil {
		t.Fatal("stale original namespace authorized a replacement")
	}
	if _, err = os.Lstat(filepath.Join(base, remoteUnpublishedReceipt)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed identity check published a receipt", err)
	}
	original, err := os.ReadFile(filepath.Join(preserved, name))
	if err != nil || !bytes.Equal(original, data) {
		t.Fatal("original moved evidence changed", err)
	}
}

func TestRemoteUnpublishedCopyRetainedTamperFailsClosedWithoutReplacingReceipt(t *testing.T) {
	s, cfg, in, base := unpublishedFixture(t, []byte("original opaque bytes"))
	v, err := s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	in.ExpectedSHA = v.SHA
	if _, err = s.retainUnpublishedRemoteCopy(cfg, in); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(base, remoteUnpublishedReceipt)
	before, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(base, v.Snapshot.Fragments[0].Name), []byte("Root-modified bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.allRemoteCopyInventory(); err == nil {
		t.Fatal("changed retained bytes were silently accepted or omitted")
	}
	if _, err = s.retainUnpublishedRemoteCopy(cfg, in); err == nil {
		t.Fatal("old condition accepted changed retained evidence")
	}
	after, err := os.ReadFile(receipt)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("original retention receipt overwritten", err)
	}
}

func TestRemoteUnpublishedCopyForwardUpdateStillRejectsRegularPendingCopy(t *testing.T) {
	s, _, _ := appReliabilityFixture(t)
	id, now := core.ID(), core.Now()
	snapshot := remoteBackupSnapshot{TargetID: "owned-target", TransactionID: id, Revision: 1, SpecSHA: core.Hash("original pending source snapshot"), Owner: 501, Files: []remoteBackupArchiveFile{{Name: "staged", File: moduleFile{Size: 1, SHA: core.Hash("x"), Mode: 0644}}}}
	source := remoteBackupArchiveRecord{Snapshot: snapshot, SHA: remoteBackupSnapshotSHA(snapshot), State: "committed", CreatedAt: now, CompletedAt: now}
	d, err := s.remoteCopyDirectory("owned-target", id, "", true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = remoteCopyPublish(d, "intent.json", remoteCopyIntent{Format: 1, Version: appcatalog.FilesSyncIndependentBackupVersion, Source: source, CreatedAt: now})
	d.Close()
	if err != nil {
		t.Fatal(err)
	}
	// This gate only inspects canonical local metadata. It neither attests a
	// remote account nor needs the separate unprivileged native SFTP fixture.
	if _, err = s.readRemoteCopyRecord("owned-target", id); err != nil {
		t.Fatal(err)
	}
	before := privateFixtureTree(t, s.moduleDir("files-sync"))
	if err := s.remoteCopyVersionPreflight(appcatalog.FilesSyncUnpublishedRetentionVersion, true); err == nil {
		t.Fatal("new forensic handler bypassed ordinary pending-copy guard")
	}
	if after := privateFixtureTree(t, s.moduleDir("files-sync")); !reflect.DeepEqual(before, after) {
		t.Fatal("failed pending-copy preflight changed originals")
	}
}

func TestRemoteUnpublishedCopyAtFullContentBudgetRetainsMetadataAndCountsTombstone(t *testing.T) {
	s, cfg, in, base := unpublishedFixture(t, nil)
	zeroSHA := core.Hash(string(make([]byte, remoteCopyFileLimit)))
	for i := 0; i < remoteCopyMaxRecords-1; i++ {
		tx, attempt, now := core.ID(), core.ID(), core.Now()
		files := []remoteBackupArchiveFile{{Name: "staged", File: moduleFile{Size: remoteCopyFileLimit, SHA: zeroSHA, Mode: 0644}}}
		if i == 0 {
			files = append([]remoteBackupArchiveFile{{Name: "previous", File: moduleFile{Size: remoteCopyFileLimit, SHA: zeroSHA, Mode: 0644}}}, files...)
		}
		snapshot := remoteBackupSnapshot{TargetID: cfg.ID, TransactionID: tx, Revision: 1, SpecSHA: core.Hash("owned full content-budget fixture"), Owner: 501, Files: files}
		source := remoteBackupArchiveRecord{Snapshot: snapshot, SHA: remoteBackupSnapshotSHA(snapshot), State: "committed", CreatedAt: now, CompletedAt: now}
		d, err := s.remoteCopyDirectory(cfg.ID, tx, "", true)
		if err != nil {
			t.Fatal(err)
		}
		_, err = remoteCopyPublish(d, "intent.json", remoteCopyIntent{Format: 1, Version: appcatalog.FilesSyncIndependentBackupVersion, Source: source, CreatedAt: now})
		d.Close()
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.readRemoteCopyRecord(cfg.ID, tx)
		if err != nil {
			t.Fatal(err)
		}
		d, err = s.remoteCopyDirectory(cfg.ID, tx, attempt, true)
		if err != nil {
			t.Fatal(err)
		}
		_, err = remoteCopyPublish(d, "attempt.json", remoteCopyAttempt{Format: 1, ID: attempt, IntentSHA: r.SHA, CreatedAt: now})
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			f, err := d.OpenFile(file.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			err = f.Truncate(remoteCopyFileLimit)
			closeErr := f.Close()
			if err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
		}
		d.Close()
	}
	all, err := s.allRemoteCopyInventory()
	if err != nil || all.count() != 128 || all.Bytes != remoteCopyMaxBytes || all.UnpublishedBytes != 0 {
		t.Fatal(all.count(), all.Bytes, all.UnpublishedBytes, err)
	}
	v, err := s.readUnpublishedRemoteCopy(cfg.ID, in.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	in.ExpectedSHA = v.SHA
	originalDir, _ := os.Lstat(base)
	if _, err = s.retainUnpublishedRemoteCopy(cfg, in); err != nil {
		t.Fatal("full content budget incorrectly blocked a bounded forensic metadata receipt", err)
	}
	rows, total, count, err := s.remoteCopyBudget()
	if err != nil || len(rows) != 127 || total != remoteCopyMaxBytes || count != 128 {
		t.Fatal("tombstone lost its namespace slot", len(rows), total, count, err)
	}
	all, err = s.allRemoteCopyInventory()
	if err != nil || all.UnpublishedBytes <= 0 || all.UnpublishedBytes > remoteCopyRecordLimit {
		t.Fatal("metadata quota not separate and bounded", all.UnpublishedBytes, err)
	}
	currentDir, _ := os.Lstat(base)
	if !os.SameFile(originalDir, currentDir) {
		t.Fatal("original empty directory replaced at full quota")
	}
	// Sparse fixtures prove inventory/count accounting, not transfer or full
	// content verification of 1 GiB. The existing full-content gate is separate.
	t.Logf("original_regular_records=127 logical_content_bytes=%d retained_unpublished_namespaces=1 total_namespaces=%d unpublished_metadata_bytes=%d full_content_claim=false", total, count, all.UnpublishedBytes)
	d, err := s.remoteCopyDirectory(cfg.ID, core.ID(), "", true)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	if _, err = s.allRemoteCopyInventory(); err == nil {
		t.Fatal("129th namespace was omitted from complete inventory")
	}
}
