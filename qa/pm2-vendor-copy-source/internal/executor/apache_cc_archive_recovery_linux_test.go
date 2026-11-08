//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestApacheCCArchiveUnknownRetentionPreservesEveryOriginalAndCurrentLog(t *testing.T) {
	for _, stage := range []string{"intent-durable", "copy-created", "copy-durable", "prepared-durable", "names-exchanged", "sealed-durable", "partial-intent", "empty-directory"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			data := []byte("original event\npartial tail")
			s, live, body, originalBody := apacheCCArchiveFixture(t, data)
			lock, err := s.lockWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			id := core.ID()
			if stage == "empty-directory" {
				if err := s.apacheNumericLogPrivateDirectory(s.apacheCCArchiveDirectory(), true); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(s.apacheCCArchiveDirectory(), id), 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				faultAt := stage
				if stage == "partial-intent" {
					faultAt = "intent-durable"
				}
				if _, err := s.archiveApacheCCLogAt(ctx, id, func(at string) error {
					if at == faultAt {
						return errors.New("owned interrupted archive")
					}
					return nil
				}); err == nil {
					t.Fatal("original checkpoint not reached")
				}
				if stage == "partial-intent" {
					if err := os.WriteFile(filepath.Join(s.apacheCCArchiveDirectory(), id, "intent.json"), []byte("{\"format\":"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			liveBefore, _ := os.Lstat(live)
			bytesBefore, _ := os.ReadFile(live)
			entry, err := s.retainApacheCCArchiveUnderLock(ctx, lock, id, apacheCCArchiveSnapshotSHA(before), nil)
			if err != nil || entry.State != "retained-unknown" || entry.Retained == nil || !entry.Retained.OriginalOutcomeUnknown || !entry.Retained.NoReplay || !entry.Retained.NoExchange {
				t.Fatal("unknown result was not preserved", entry, err)
			}
			if !reflect.DeepEqual(before, entry.Retained.Snapshot) {
				t.Fatal("original snapshot was rewritten")
			}
			liveAfter, _ := os.Lstat(live)
			bytesAfter, _ := os.ReadFile(live)
			if !os.SameFile(liveBefore, liveAfter) || liveBefore.Mode() != liveAfter.Mode() || !bytes.Equal(bytesBefore, bytesAfter) {
				t.Fatal("retention changed current log")
			}
			if raw, _ := os.ReadFile(body); !bytes.Equal(raw, originalBody) {
				t.Fatal("retention changed separate body namespace")
			}
			for name, wanted := range before.Files {
				path := filepath.Join(s.apacheCCArchiveDirectory(), id, name)
				raw, err := os.ReadFile(path)
				info, statErr := os.Lstat(path)
				if name == "next.log" {
					if err != nil || statErr != nil || !before.SourceIdentityOnly {
						t.Fatal("original source identity missing", err)
					}
					continue
				}
				if err != nil || statErr != nil || int64(len(raw)) != wanted.Bytes || core.Hash(string(raw)) != wanted.SHA256 || info.Sys() == nil {
					t.Fatal("original phase or data bytes lost", name, err)
				}
			}
			if err := s.apacheCCArchiveReadFence(ctx); err != nil {
				t.Fatal("fully retained unknown blocked read-only programme qualification", err)
			}
			prior := programQueueTree(t, s.Config.SystemRoot)
			again, err := s.retainApacheCCArchiveUnderLock(ctx, lock, id, entry.Retained.SnapshotSHA, nil)
			if err != nil || !reflect.DeepEqual(entry, again) || !reflect.DeepEqual(prior, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("explicit retention replay repeated writes", err)
			}
			if _, err := s.archiveApacheCCLogAt(ctx, id, nil); err == nil || !reflect.DeepEqual(prior, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("retention allowed original archive replay", err)
			}
		})
	}
}

func TestApacheCCArchiveInterruptedRetentionKeepsIntentBeforeSealingAndNeverReplays(t *testing.T) {
	for _, faultAt := range []string{"retention-intent-durable", "original-data-sealed", "retained-receipt-durable", "partial-retention-receipt"} {
		t.Run(faultAt, func(t *testing.T) {
			s, live, _, _ := apacheCCArchiveFixture(t, []byte("original\n"))
			ctx := context.Background()
			lock, err := s.lockWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			id := core.ID()
			if _, err := s.archiveApacheCCLogAt(ctx, id, func(stage string) error {
				if stage == "names-exchanged" {
					return errors.New("owned archive loss")
				}
				return nil
			}); err == nil {
				t.Fatal("archive fault not reached")
			}
			original, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			inputSHA := apacheCCArchiveSnapshotSHA(original)
			stopAt := faultAt
			if faultAt == "partial-retention-receipt" {
				stopAt = "retained-receipt-durable"
			}
			if _, err := s.retainApacheCCArchiveUnderLock(ctx, lock, id, inputSHA, func(stage string) error {
				if stage == stopAt {
					return errors.New("owned retention loss")
				}
				return nil
			}); err == nil {
				t.Fatal("retention fault not reached")
			}
			if faultAt == "partial-retention-receipt" {
				files, err := os.ReadDir(filepath.Join(s.apacheCCArchiveDirectory(), id))
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range files {
					if apacheCCArchiveRetentionName(f.Name()) {
						if err := os.WriteFile(filepath.Join(s.apacheCCArchiveDirectory(), id, f.Name()), []byte("{\"format\":"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			row, err := s.readApacheCCArchive(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if faultAt == "retained-receipt-durable" {
				if row.State != "retained-unknown" {
					t.Fatal("durable original receipt not observed")
				}
				return
			}
			if row.State != "unknown" {
				t.Fatal("interrupted retention treated as resolved", row)
			}
			next, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(next.Files) <= len(original.Files) {
				t.Fatal("original retention intent or partial receipt removed")
			}
			prior := programQueueTree(t, s.Config.SystemRoot)
			if _, err := s.retainApacheCCArchiveUnderLock(ctx, lock, id, inputSHA, nil); err == nil || !reflect.DeepEqual(prior, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("old snapshot authority silently resumed the interrupted operation", err)
			}
			result, err := s.retainApacheCCArchiveUnderLock(ctx, lock, id, apacheCCArchiveSnapshotSHA(next), nil)
			if err != nil || result.State != "retained-unknown" {
				t.Fatal("fresh explicit evidence retention failed", result, err)
			}
			if raw, _ := os.ReadFile(live); len(raw) != 0 {
				t.Fatal("retention wrote to empty new current log")
			}
		})
	}
}

func TestApacheCCArchiveRecoveryRejectsChangedDigestForeignRecordAndLostActiveLog(t *testing.T) {
	for _, kind := range []string{"foreign-digest", "foreign-file", "missing-current", "changed-original-after-retention"} {
		t.Run(kind, func(t *testing.T) {
			s, live, _, _ := apacheCCArchiveFixture(t, []byte("original\n"))
			ctx := context.Background()
			lock, err := s.lockWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			id := core.ID()
			if _, err := s.archiveApacheCCLogAt(ctx, id, func(stage string) error {
				if stage == "prepared-durable" {
					return errors.New("owned archive loss")
				}
				return nil
			}); err == nil {
				t.Fatal("archive fault not reached")
			}
			snapshot, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			digest := apacheCCArchiveSnapshotSHA(snapshot)
			switch kind {
			case "foreign-digest":
				digest = strings.Repeat("0", 64)
			case "foreign-file":
				if err := os.WriteFile(filepath.Join(s.apacheCCArchiveDirectory(), id, "unowned"), []byte("original unknown file"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-current":
				if err := os.Rename(live, live+".owned-retained"); err != nil {
					t.Fatal(err)
				}
			case "changed-original-after-retention":
				if _, err := s.retainApacheCCArchiveUnderLock(ctx, lock, id, digest, nil); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(s.apacheCCArchiveDirectory(), id, "intent.json"), []byte("changed evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := programQueueTree(t, s.Config.SystemRoot)
			if _, err := s.retainApacheCCArchiveUnderLock(ctx, lock, id, digest, nil); err == nil {
				t.Fatal("unsafe recovery adopted", kind)
			}
			if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
				t.Fatal("recovery refusal repaired or changed original evidence")
			}
		})
	}
}
