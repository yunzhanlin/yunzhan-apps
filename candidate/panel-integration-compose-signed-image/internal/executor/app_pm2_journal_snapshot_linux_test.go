//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"local/panel/internal/core"
)

func TestPM2JournalSnapshotMissingReadDoesNotCreateOrRewrite(t *testing.T) {
	s, _, appPath := pm2StateAppFixture(t)
	before, err := os.ReadFile(appPath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.snapshotPM2ConfigurationJournal()
	if err != nil || snapshot.Exists || snapshot.eligible() || snapshot.Records != 0 {
		t.Fatalf("missing journal observation: %#v %v", snapshot, err)
	}
	if _, err := os.Lstat(filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions")); !os.IsNotExist(err) {
		t.Fatal("read created a journal directory")
	}
	if _, err := os.Lstat(filepath.Join(s.moduleDir("pm2-manager"), pm2ConfigurationJournalLock)); !os.IsNotExist(err) {
		t.Fatal("read created a lock")
	}
	after, err := os.ReadFile(appPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read rewrote encrypted app configuration")
	}
}

func TestPM2JournalSnapshotPinsOriginalBytesAndTerminalEligibility(t *testing.T) {
	s, _, _, record := pm2ConfigFixtureIntent(t)
	first, err := s.snapshotPM2ConfigurationJournal()
	if err != nil || first.eligible() || first.Records != 1 || !reflect.DeepEqual(first.Pending, []string{record.Intent.ID}) {
		t.Fatalf("pending original was not retained: %#v %v", first, err)
	}
	d, err := s.openPM2ConfigStore(false)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	intentPath := filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions", record.Intent.ID+".intent.json")
	original, err := os.Lstat(intentPath)
	if err != nil {
		t.Fatal(err)
	}
	raw := record.Raw
	pin := first.Files[record.Intent.ID+".intent.json"]
	if pin.SHA256 != pm2ConfigHash(raw) || pin.Identity.Inode == 0 {
		t.Fatal("original intent bytes were not pinned")
	}
	receipt := pm2ConfigReceipt{Format: 1, ID: record.Intent.ID, IntentSHA: record.SHA, State: "rolled_back", ManifestSHA: record.Intent.BeforeSHA, FinishedAt: core.Now()}
	// Deliberately retain noncanonical whitespace. Archival must preserve the
	// original file bytes instead of regenerating a parsed receipt.
	receiptRaw, err := json.MarshalIndent(receipt, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	receiptRaw = append(receiptRaw, '\n')
	if err := pm2ConfigCreate(d.modulePrivateDirectory, record.Intent.ID+".result.json", receiptRaw); err != nil {
		t.Fatal(err)
	}
	terminal, err := s.snapshotPM2ConfigurationJournal()
	if err != nil || !terminal.eligible() || terminal.Records != 1 || len(terminal.Pending) != 0 {
		t.Fatalf("completed original not eligible: %#v %v", terminal, err)
	}
	if terminal.Files[record.Intent.ID+".result.json"].SHA256 != pm2ConfigHash(receiptRaw) || terminal.Files[record.Intent.ID+".intent.json"] != pin {
		t.Fatal("inventory did not retain exact original intent and receipt")
	}
	again, err := s.snapshotPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	a, err := terminal.sha256()
	if err != nil {
		t.Fatal(err)
	}
	b, err := again.sha256()
	if err != nil || a != b {
		t.Fatal("observation invalidated its own stable inventory")
	}
	after, err := os.Lstat(intentPath)
	if err != nil || !programQueueSame(original, after) {
		t.Fatal("inventory changed original intent metadata")
	}
	current, err := os.ReadFile(intentPath)
	if err != nil || !bytes.Equal(current, raw) {
		t.Fatal("inventory rewrote original intent")
	}
}

func TestPM2JournalSnapshotRefusesUnknownLinkedOrIncompleteEvidence(t *testing.T) {
	for _, kind := range []string{"unknown", "symlink", "hardlink", "orphan-receipt"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _, record := pm2ConfigFixtureIntent(t)
			dir := filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions")
			target := filepath.Join(t.TempDir(), "retained-original")
			if err := os.WriteFile(target, []byte("retained independent original"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "unknown":
				if err := os.WriteFile(filepath.Join(dir, "unknown.json"), []byte("retain damaged record"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(target, filepath.Join(dir, core.ID()+".intent.json")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(target, filepath.Join(dir, core.ID()+".intent.json")); err != nil {
					t.Fatal(err)
				}
			case "orphan-receipt":
				if err := os.Rename(filepath.Join(dir, record.Intent.ID+".intent.json"), filepath.Join(dir, record.Intent.ID+".result.json")); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot, err := s.snapshotPM2ConfigurationJournal(); err == nil || snapshot.eligible() {
				t.Fatal("unverifiable evidence was presented as complete or empty")
			}
			after, err := os.ReadDir(dir)
			if err != nil || len(before) != len(after) {
				t.Fatal("rejected evidence was removed")
			}
			raw, err := os.ReadFile(target)
			if err != nil || string(raw) != "retained independent original" {
				t.Fatal("rejected evidence changed the independent original")
			}
		})
	}
}

func TestPM2JournalSnapshotDetachedMissingNamespaceIsUnknown(t *testing.T) {
	s, _, appPath := pm2StateAppFixture(t)
	original, err := os.ReadFile(appPath)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	parent := s.moduleDir("pm2-manager")
	if err := os.Rename(parent, parent+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	err = pm2ConfigChild(d, "configuration-transactions", false)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing child of detached original namespace was presented as empty")
	}
	retained := filepath.Join(parent+"-retained", "apps", filepath.Base(appPath))
	after, err := os.ReadFile(retained)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("detached original app data was changed")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("read repaired the replacement namespace")
	}
}
