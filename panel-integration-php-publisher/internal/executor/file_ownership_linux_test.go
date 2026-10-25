//go:build linux

package executor

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteAndDeletedBackupRestoreKeepActualUIDGID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual root Linux ownership fixture required")
	}
	path := filepath.Join(t.TempDir(), "owned.conf")
	if err := os.WriteFile(path, []byte("original"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := backupFile(path)
	if err != nil || b.owner == nil || b.owner.UID != 0 || b.owner.GID != 1 || b.mode != 0600 {
		t.Fatal("atomic replacement lost original owner", b, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := restoreFiles([]fileBackup{b}); err != nil {
		t.Fatal(err)
	}
	after, err := backupFile(path)
	if err != nil || after.owner == nil || *after.owner != *b.owner || after.mode != b.mode || !bytes.Equal(after.data, b.data) {
		t.Fatal("deleted backup owner not restored", after, err)
	}
}

func TestWAFTransactionOwnerDriftStopsBeforeWritesAndRecoveryRestoresGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual root Linux ownership fixture required")
	}
	s, cfg, id := wafBodyPlanFixture(t)
	path := filepath.Join(s.Config.ConfDir, id+".conf")
	if err := os.Chown(path, 0, 1); err != nil {
		t.Fatal(err)
	}
	plan, err := s.planWAFConfiguration(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.startWAFTransaction(plan); err == nil {
		t.Fatal("owner drift admitted")
	}
	if _, err := os.Lstat(s.wafPendingPath()); !os.IsNotExist(err) {
		t.Fatal("owner drift created pending transaction", err)
	}
	if err := os.Chown(path, 0, 1); err != nil {
		t.Fatal(err)
	}
	tx, err := s.startWAFTransaction(plan)
	if err != nil || tx.Format != 2 {
		t.Fatal("new transaction not bound to owners", err)
	}
	for _, change := range tx.Changes {
		if err := wafApplyChange(change, true); err != nil {
			t.Fatal(err)
		}
	}
	current, err := backupFile(path)
	if err != nil || current.owner == nil || current.owner.GID != 1 {
		t.Fatal("apply changed site group", err)
	}
	if changed, err := New(s.Config).recoverWAFTransaction(); err != nil || !changed {
		t.Fatal("fresh owner-aware recovery failed", err)
	}
	for _, change := range tx.Changes {
		if matches, err := s.wafCurrentMatches(change, false); err != nil || !matches {
			t.Fatal("original owner/bytes/mode not restored", change.Path, err)
		}
	}
}

func TestWAFLegacyUnfinishedTransactionNeverGuessesOriginalUIDGID(t *testing.T) {
	s, cfg, _ := wafBodyPlanFixture(t)
	plan, err := s.planWAFConfiguration(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.startWAFTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range tx.Changes {
		if err := wafApplyChange(change, true); err != nil {
			t.Fatal(err)
		}
	}
	tx.Format = 1
	for i := range tx.Changes {
		tx.Changes[i].OldOwner = nil
		tx.Changes[i].NextOwner = nil
	}
	if err := wafWriteTransaction(s.wafPendingPath(), tx); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.wafPendingPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(s.Config).recoverWAFTransaction(); err == nil {
		t.Fatal("legacy missing owners fabricated full restoration")
	}
	after, err := os.ReadFile(s.wafPendingPath())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("legacy evidence overwritten", err)
	}
	for _, change := range plan {
		if matches, err := s.wafCurrentMatches(change, true); err != nil || !matches {
			t.Fatal("legacy refusal changed configuration", err)
		}
	}
}
