//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestApacheCCArchiveHistoryPreservesWholeDirectoryAndOriginalIdentity(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(map[bool]string{false: "completed", true: "retained-unknown"}[retained], func(t *testing.T) {
			ctx := context.Background()
			data := []byte("original event\noriginal partial tail")
			s, live, body, bodyBytes := apacheCCArchiveFixture(t, data)
			lock, err := s.lockWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			id := core.ID()
			var row apacheCCArchiveEntry
			if retained {
				_, err = s.archiveApacheCCLogAt(ctx, id, func(at string) error {
					if at == "names-exchanged" {
						return errors.New("owned original interrupted exchange")
					}
					return nil
				})
				if err == nil {
					t.Fatal("fault not reached")
				}
				snap, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
				if err != nil {
					t.Fatal(err)
				}
				row, err = s.retainApacheCCArchiveUnderLock(ctx, lock, id, apacheCCArchiveSnapshotSHA(snap), nil)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				row, err = s.archiveApacheCCLogAt(ctx, id, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			before, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			dirBefore, err := os.Lstat(filepath.Join(s.apacheCCArchiveDirectory(), id))
			if err != nil {
				t.Fatal(err)
			}
			currentBefore, err := os.Lstat(live)
			if err != nil {
				t.Fatal(err)
			}
			currentBytes, _ := os.ReadFile(live)
			moved, err := s.preserveApacheCCArchiveHistoryUnderLock(ctx, lock, id, apacheCCArchiveSnapshotSHA(before), nil)
			if err != nil || !reflect.DeepEqual(row, moved) {
				t.Fatal("original outcome changed", moved, err)
			}
			if _, err := os.Lstat(filepath.Join(s.apacheCCArchiveDirectory(), id)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("old location retained or inaccessible", err)
			}
			dirAfter, err := os.Lstat(filepath.Join(s.apacheCCArchiveHistoryDirectory(), id))
			if err != nil || !os.SameFile(dirBefore, dirAfter) {
				t.Fatal("whole original directory not preserved", err)
			}
			after, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("original file identities or bytes changed", err)
			}
			currentAfter, _ := os.Lstat(live)
			raw, _ := os.ReadFile(live)
			if !os.SameFile(currentBefore, currentAfter) || !bytes.Equal(currentBytes, raw) {
				t.Fatal("active log changed")
			}
			if raw, _ := os.ReadFile(body); !bytes.Equal(raw, bodyBytes) {
				t.Fatal("body log changed")
			}
			active, err := s.apacheCCArchiveInventory(ctx)
			if err != nil || len(active) != 0 {
				t.Fatal(active, err)
			}
			history, err := s.apacheCCArchiveHistoryInventory(ctx)
			if err != nil || len(history) != 1 || !reflect.DeepEqual(row, history[0]) {
				t.Fatal(history, err)
			}
			if err := s.apacheCCArchiveReadFence(ctx); err != nil {
				t.Fatal("history unreadable by read-only upgrade", err)
			}
			chunk, err := s.apacheCCArchiveChunk(ctx, id, 0)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := base64.StdEncoding.DecodeString(chunk["data_base64"].(string))
			if err != nil || !bytes.Equal(decoded, data) || chunk["original_outcome_unknown"] != retained {
				t.Fatal("history raw download changed", err)
			}
			prior := programQueueTree(t, s.Config.SystemRoot)
			again, err := s.preserveApacheCCArchiveHistoryUnderLock(ctx, lock, id, apacheCCArchiveSnapshotSHA(before), nil)
			if err != nil || !reflect.DeepEqual(row, again) || !reflect.DeepEqual(prior, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("original history observation replayed a mutation", err)
			}
			if _, err := s.closeUnstartedApacheCCArchiveUnderLock(ctx, lock, core.ApacheCCArchiveRequest{RequestID: id, ExpectedRevision: 1, AllowIncomplete: true}); err == nil {
				t.Fatal("historical original treated as unstarted")
			}
			if _, err := s.archiveApacheCCLogAt(ctx, id, nil); retained && err == nil {
				t.Fatal("historical unknown archive was replayed")
			}
			if !reflect.DeepEqual(prior, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("original archive observation changed historical evidence")
			}
		})
	}
}

func TestApacheCCArchiveHistoryLostRepliesNeverLoseOriginalOrReplayRename(t *testing.T) {
	for _, stage := range []string{"original-history-snapshot-verified", "history-directory-moved", "history-directories-durable"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			s, live, _, _ := apacheCCArchiveFixture(t, []byte("original\n"))
			lock, err := s.lockWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			id := core.ID()
			if _, err := s.archiveApacheCCLogAt(ctx, id, nil); err != nil {
				t.Fatal(err)
			}
			snapshot, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.preserveApacheCCArchiveHistoryUnderLock(ctx, lock, id, apacheCCArchiveSnapshotSHA(snapshot), func(at string) error {
				if at == stage {
					return errors.New("owned original reply loss")
				}
				return nil
			})
			if err == nil {
				t.Fatal("fault not reached")
			}
			dir, historical, err := s.apacheCCArchiveEntryDirectory(id)
			if err != nil || historical != (stage != "original-history-snapshot-verified") {
				t.Fatal("original directory lost or ambiguous", dir, err)
			}
			after, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
			if err != nil || !reflect.DeepEqual(snapshot, after) {
				t.Fatal("original bytes lost after interrupted transfer", err)
			}
			prior := programQueueTree(t, s.Config.SystemRoot)
			if _, err := s.readApacheCCArchive(ctx, id); err != nil {
				t.Fatal(err)
			}
			if err := s.apacheCCArchiveReadFence(ctx); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(prior, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("read-only observer replayed original transfer")
			}
			if raw, _ := os.ReadFile(live); len(raw) != 0 {
				t.Fatal("history fault changed current log")
			}
		})
	}
}

func TestApacheCCArchiveHistoryCapacityReleasesActiveSlotsWithoutDeletingFiles(t *testing.T) {
	ctx := context.Background()
	s, live, _, _ := apacheCCArchiveFixture(t, []byte("original\n"))
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	for i := 0; i < apacheCCArchiveHistoryCount; i++ {
		if i > 0 {
			if err := os.WriteFile(live, []byte("next original\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		id := core.ID()
		if _, err := s.archiveApacheCCLogAt(ctx, id, nil); err != nil {
			t.Fatal(i, err)
		}
		snapshot, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.preserveApacheCCArchiveHistoryUnderLock(ctx, lock, id, apacheCCArchiveSnapshotSHA(snapshot), nil); err != nil {
			t.Fatal(i, err)
		}
	}
	if err := os.WriteFile(live, []byte("final original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	id := core.ID()
	if _, err := s.archiveApacheCCLogAt(ctx, id, nil); err != nil {
		t.Fatal("active slot was not released", err)
	}
	snapshot, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	prior := programQueueTree(t, s.Config.SystemRoot)
	if _, err := s.preserveApacheCCArchiveHistoryUnderLock(ctx, lock, id, apacheCCArchiveSnapshotSHA(snapshot), nil); err == nil || !strings.Contains(err.Error(), "32") {
		t.Fatal("history overflow not refused", err)
	}
	if !reflect.DeepEqual(prior, programQueueTree(t, s.Config.SystemRoot)) {
		t.Fatal("history capacity refusal changed or deleted original data")
	}
	rows, err := s.apacheCCArchiveHistoryInventory(ctx)
	if err != nil || len(rows) != 32 {
		t.Fatal(len(rows), err)
	}
}

func TestApacheCCArchiveHistoryRefusesForeignOrChangedEvidenceWithoutRepair(t *testing.T) {
	for _, kind := range []string{"stale-digest", "foreign-parent", "duplicate-id", "unknown-result", "fake-lock"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			s, _, _, _ := apacheCCArchiveFixture(t, []byte("original\n"))
			lock, err := s.lockWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			id := core.ID()
			var fault func(string) error
			if kind == "unknown-result" {
				fault = func(at string) error {
					if at == "intent-durable" {
						return errors.New("owned unknown original")
					}
					return nil
				}
			}
			if _, err := s.archiveApacheCCLogAt(ctx, id, fault); err != nil && kind != "unknown-result" {
				t.Fatal(err)
			}
			snapshot, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			digest := apacheCCArchiveSnapshotSHA(snapshot)
			switch kind {
			case "stale-digest":
				digest = strings.Repeat("f", 64)
			case "foreign-parent":
				if err := os.Symlink(s.apacheCCArchiveDirectory(), s.apacheCCArchiveHistoryDirectory()); err != nil {
					t.Fatal(err)
				}
			case "duplicate-id":
				if err := s.apacheNumericLogPrivateDirectory(s.apacheCCArchiveHistoryDirectory(), true); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(s.apacheCCArchiveHistoryDirectory(), id), 0700); err != nil {
					t.Fatal(err)
				}
			case "fake-lock":
				lock = nil
			}
			prior := programQueueTree(t, s.Config.SystemRoot)
			if _, err := s.preserveApacheCCArchiveHistoryUnderLock(ctx, lock, id, digest, nil); err == nil {
				t.Fatal("unsafe history transfer admitted", kind)
			}
			if !reflect.DeepEqual(prior, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("history refusal repaired/deleted original evidence", kind)
			}
		})
	}
}
