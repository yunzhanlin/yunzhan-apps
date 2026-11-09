//go:build linux

package executor

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestHardeningJournalExclusivePrepareKeepsCompleteOriginalAuthority(t *testing.T) {
	f, p := hardeningJournalFixturePlan(t, "", "baseline")
	lock, err := f.s.hardeningMutationLock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	raw, err := f.s.hardeningJournalPrepare(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.s.Config.SecurityDir, hardeningPendingName)
	before, err := os.Lstat(path)
	if err != nil || before.Mode().Perm() != 0600 {
		t.Fatal("pending identity", err)
	}
	got, again, err := f.s.hardeningJournalPending()
	if err != nil || got.ID != p.ID || !bytes.Equal(raw, again) {
		t.Fatal("original plan not retained", err)
	}
	if _, err = f.s.hardeningJournalPrepare(p); err == nil {
		t.Fatal("second prepare replaced pending identity")
	}
	after, _ := os.Lstat(path)
	now, _ := os.ReadFile(path)
	if !os.SameFile(before, after) || !bytes.Equal(raw, now) || f.writes != 0 {
		t.Fatal("prepare replay mutated original authority/kernel")
	}
}

func TestHardeningJournalUnappliedPlanCannotPublishCommittedSuccess(t *testing.T) {
	f, p := hardeningJournalFixturePlan(t, "", "baseline")
	raw, err := f.s.hardeningJournalPrepare(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.hardeningJournalPublishTerminal(p, raw, "committed", ""); err == nil {
		t.Fatal("unapplied plan became committed success")
	}
	inventory, err := f.s.hardeningJournalInventoryRead()
	if err != nil || len(inventory.Records) != 0 {
		t.Fatal("false terminal source", err)
	}
	_, again, err := f.s.hardeningJournalPending()
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("failed publication lost pending", err)
	}
}

func TestHardeningJournalRolledBackArchivePreservesOriginalPlanAndBlocksIDReuse(t *testing.T) {
	f, p := hardeningJournalFixturePlan(t, "", "baseline")
	raw, err := f.s.hardeningJournalPrepare(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.hardeningJournalPublishTerminal(p, raw, "rolled_back", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.s.hardeningJournalPending(); !os.IsNotExist(err) {
		t.Fatal("closed pending remained", err)
	}
	inventory, err := f.s.hardeningJournalInventoryRead()
	if err != nil {
		t.Fatal(err)
	}
	record := inventory.Records[p.ID]
	if record.State != "rolled_back" || record.PlanSHA256 != hardeningJournalDigest(raw) {
		t.Fatal("original terminal identity/digest lost")
	}
	path := filepath.Join(f.s.Config.SecurityDir, hardeningJournalDirectory, p.ID+".json")
	before, _ := os.Lstat(path)
	data, _ := os.ReadFile(path)
	if _, err = f.s.hardeningJournalPrepare(p); err == nil {
		t.Fatal("terminal original ID reused")
	}
	after, _ := os.Lstat(path)
	again, _ := os.ReadFile(path)
	if !os.SameFile(before, after) || !bytes.Equal(data, again) {
		t.Fatal("terminal record rewritten")
	}
}

func TestHardeningJournalPartialOrLinkedPrimaryRefusesWithoutRepair(t *testing.T) {
	for _, mode := range []string{"partial", "symlink", "public", "directory"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := hardeningJournalFixturePlan(t, "", "baseline")
			path := filepath.Join(f.s.Config.SecurityDir, hardeningPendingName)
			switch mode {
			case "partial":
				if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(f.s.Config.SystemRoot, "foreign.json")
				if err := os.WriteFile(target, []byte("private unchanged\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.Lstat(path)
			if err := f.s.hardeningJournalRequireClosed(); err == nil {
				t.Fatal("unsafe primary became absent/closed")
			}
			after, _ := os.Lstat(path)
			if !os.SameFile(before, after) || before.Mode() != after.Mode() || f.writes != 0 {
				t.Fatal("unsafe primary or kernel repaired")
			}
		})
	}
}

func TestHardeningJournalIncompleteAtomicTemporaryIsNotSuccessAndNotDeleted(t *testing.T) {
	f, _ := hardeningJournalFixturePlan(t, "", "baseline")
	root, err := f.s.hardeningJournalArchiveRoot(true)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	path := filepath.Join(f.s.Config.SecurityDir, hardeningJournalDirectory, ".panel-write-12345")
	if err = os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Lstat(path)
	got, err := f.s.hardeningJournalInventoryRead()
	if err != nil || len(got.Records) != 0 || got.TemporaryFiles != 1 {
		t.Fatal("temporary promoted/lost", got, err)
	}
	after, _ := os.Lstat(path)
	if !os.SameFile(before, after) {
		t.Fatal("temporary evidence removed")
	}
}

func TestHardeningJournalUnknownArchiveEntryBlocksNewAuthorityWithoutDeletion(t *testing.T) {
	f, p := hardeningJournalFixturePlan(t, "", "baseline")
	root, err := f.s.hardeningJournalArchiveRoot(true)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	path := filepath.Join(f.s.Config.SecurityDir, hardeningJournalDirectory, "unknown.json")
	if err = os.WriteFile(path, []byte("foreign original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Lstat(path)
	if _, err = f.s.hardeningJournalPrepare(p); err == nil {
		t.Fatal("unknown inventory ignored")
	}
	after, _ := os.Lstat(path)
	raw, _ := os.ReadFile(path)
	if !os.SameFile(before, after) || string(raw) != "foreign original\n" || f.writes != 0 {
		t.Fatal("unknown inventory changed")
	}
	if _, err = os.Lstat(filepath.Join(f.s.Config.SecurityDir, hardeningPendingName)); !os.IsNotExist(err) {
		t.Fatal("new pending despite unknown inventory", err)
	}
}
