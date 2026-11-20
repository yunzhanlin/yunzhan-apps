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

func pm2ArchiveStoreFixture(t *testing.T) (*Service, *modulePrivateDirectory, string) {
	t.Helper()
	s, _, _ := pm2StateAppFixture(t)
	parent, err := s.openPM2ArchivePath("requests", "", true)
	if err != nil {
		t.Fatal(err)
	}
	id := core.ID()
	if err := parent.Mkdir(id, 0700); err != nil {
		t.Fatal(err)
	}
	if err := pm2ConfigSync(parent); err != nil {
		t.Fatal(err)
	}
	parent.Close()
	d, err := s.openPM2ArchivePath("requests", id, false)
	if err != nil {
		t.Fatal(err)
	}
	return s, d, id
}
func TestPM2JournalArchiveStorePublishesLargeMetadataWithoutWideningOldReader(t *testing.T) {
	_, d, _ := pm2ArchiveStoreFixture(t)
	defer d.Close()
	raw := bytes.Repeat([]byte("original metadata\n"), 20000)
	if len(raw) <= pm2ConfigRecordLimit || len(raw) > pm2ConfigurationArchiveIntentLimit {
		t.Fatal("invalid large metadata fixture")
	}
	if err := pm2ArchivePublish(d, "intent.json", raw); err != nil {
		t.Fatal(err)
	}
	got, err := pm2ArchiveRead(d, "intent.json")
	if err != nil || !bytes.Equal(raw, got) {
		t.Fatal("complete published bytes changed")
	}
	if _, err := pm2ConfigRead(d, "intent.json"); err == nil {
		t.Fatal("original 128KiB configuration reader limit was widened")
	}
	names, err := pm2ArchiveNames(d, 64)
	if err != nil || !reflect.DeepEqual(names, []string{"intent.json"}) {
		t.Fatalf("publication left an acknowledged partial record: %v %v", names, err)
	}
}
func TestPM2JournalArchiveStoreCollisionRetainsFinalAndCandidate(t *testing.T) {
	_, d, _ := pm2ArchiveStoreFixture(t)
	defer d.Close()
	original := []byte("retained original final")
	if err := pm2ArchivePublish(d, "outcome.json", original); err != nil {
		t.Fatal(err)
	}
	before, err := d.Lstat("outcome.json")
	if err != nil {
		t.Fatal(err)
	}
	candidate := []byte("retained conflicting candidate")
	if err := pm2ArchivePublish(d, "outcome.json", candidate); err == nil {
		t.Fatal("existing final outcome was replaced")
	}
	after, err := d.Lstat("outcome.json")
	if err != nil || !programQueueSame(before, after) {
		t.Fatal("collision modified original final metadata")
	}
	got, err := pm2ArchiveRead(d, "outcome.json")
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("collision changed original final bytes")
	}
	names, err := pm2ArchiveNames(d, 64)
	if err != nil {
		t.Fatal(err)
	}
	retained := 0
	for _, name := range names {
		if pm2ArchivePartName.MatchString(name) {
			raw, err := pm2ArchiveRead(d, name)
			if err != nil || !bytes.Equal(raw, candidate) {
				t.Fatal("conflicting candidate was not retained")
			}
			retained++
		}
	}
	if retained != 1 {
		t.Fatal("collision evidence was lost")
	}
}
func TestPM2JournalArchiveStoreEmptyFragmentIsNotAnAcceptedFinal(t *testing.T) {
	_, d, _ := pm2ArchiveStoreFixture(t)
	defer d.Close()
	fragment := "intent." + core.ID() + ".part"
	f, err := d.OpenFile(fragment, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pm2ConfigWriteDurable(f, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := pm2ArchiveRead(d, fragment)
	if err != nil || len(raw) != 0 {
		t.Fatal("original empty partial fragment was not observable")
	}
	f, err = d.OpenFile("intent.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pm2ConfigWriteDurable(f, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := pm2ArchiveRead(d, "intent.json"); err == nil {
		t.Fatal("empty final record was acknowledged")
	}
	if names, err := pm2ArchiveNames(d, 64); err != nil || len(names) != 2 {
		t.Fatal("invalid original evidence was deleted")
	}
}
func TestPM2JournalArchiveStoreRejectsLinkedRecordsAndDetachedAbsence(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "detached-missing"} {
		t.Run(kind, func(t *testing.T) {
			s, d, id := pm2ArchiveStoreFixture(t)
			defer d.Close()
			target := filepath.Join(t.TempDir(), "original")
			if err := os.WriteFile(target, []byte("retained independent original"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.moduleDir("pm2-manager"), "configuration-archives", "requests", id)
			switch kind {
			case "symlink":
				if err := os.Symlink(target, filepath.Join(path, "intent.json")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(target, filepath.Join(path, "intent.json")); err != nil {
					t.Fatal(err)
				}
			case "detached-missing":
				if err := os.Rename(path, path+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := pm2ArchiveRead(d, "intent.json"); err == nil || kind == "detached-missing" && errors.Is(err, os.ErrNotExist) {
				t.Fatal("linked or detached original record was accepted or presented as absent")
			}
			raw, err := os.ReadFile(target)
			if err != nil || string(raw) != "retained independent original" {
				t.Fatal("independent original was changed")
			}
		})
	}
}
func TestPM2JournalArchiveStoreWholeDirectoryNoReplacePreservesOriginals(t *testing.T) {
	s, _, _, record := pm2ConfigFixtureIntent(t)
	active, err := s.openPM2ConfigStore(false)
	if err != nil {
		t.Fatal(err)
	}
	receipt := pm2ConfigReceipt{Format: 1, ID: record.Intent.ID, IntentSHA: record.SHA, State: "rolled_back", ManifestSHA: record.Intent.BeforeSHA, FinishedAt: core.Now()}
	raw, err := json.MarshalIndent(receipt, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := pm2ConfigCreate(active.modulePrivateDirectory, record.Intent.ID+".result.json", raw); err != nil {
		t.Fatal(err)
	}
	before, err := active.snapshot()
	if err != nil || !before.eligible() {
		t.Fatalf("original terminal journal: %v", err)
	}
	active.Close()
	module, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		t.Fatal(err)
	}
	defer module.Close()
	generations, err := s.openPM2ArchivePath("generations", "", true)
	if err != nil {
		t.Fatal(err)
	}
	defer generations.Close()
	foreign := core.ID()
	if err := generations.Mkdir(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	if err := pm2ArchiveRenameNoReplace(module, "configuration-transactions", generations, foreign); err == nil {
		t.Fatal("existing foreign destination was replaced")
	}
	id := core.ID()
	if err := pm2ArchiveRenameNoReplace(module, "configuration-transactions", generations, id); err != nil {
		t.Fatal(err)
	}
	moved, err := s.openPM2ArchivePath("generations", id, false)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := (&pm2ConfigStore{modulePrivateDirectory: moved}).snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !pm2JournalSameMovedDirectory(before.Directory, observed.Directory) || !reflect.DeepEqual(before.Files, observed.Files) || before.Records != observed.Records {
		t.Fatal("whole-directory archival changed original bytes or inode/group witnesses")
	}
	moved.Close()
	if err := pm2ArchiveRenameNoReplace(generations, id, module, "configuration-transactions"); err != nil {
		t.Fatal(err)
	}
	restored, err := s.snapshotPM2ConfigurationJournal()
	if err != nil || !pm2JournalSameMovedDirectory(before.Directory, restored.Directory) || !reflect.DeepEqual(before.Files, restored.Files) {
		t.Fatal("explicit no-replace reverse move changed original evidence")
	}
	if info, err := generations.Lstat(foreign); err != nil || !info.IsDir() {
		t.Fatal("foreign destination was not retained")
	}
}
