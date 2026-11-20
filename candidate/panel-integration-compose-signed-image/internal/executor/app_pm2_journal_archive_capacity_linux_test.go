//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"local/panel/internal/core"
)

// Seed valid terminal cancellation records only to exercise the real512-file
// storage boundary. These are model records, not512 claimed business requests.
func TestPM2JournalArchiveFullCapacityRetainsAllOriginalsAndAllowsNewSave(t *testing.T) {
	s, input := pm2ArchiveActiveFixture(t)
	d, err := s.openPM2ConfigStore(false)
	if err != nil {
		t.Fatal(err)
	}
	originalIDs := []string{input.PM2OperationID}
	for i := 1; i < pm2ConfigIntentLimit; i++ {
		id := core.ID()
		originalIDs = append(originalIDs, id)
		c := pm2ConfigCancellation{Format: 1, ID: id, AppID: input.ResourceID, CreatedAt: core.Now(), CancelledBeforePublication: true}
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := pm2ConfigCreate(d.modulePrivateDirectory, id+".cancel.json", append(raw, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := s.snapshotPM2ConfigurationJournal()
	if err != nil || before.Records != 512 || len(before.Files) != 513 || !before.eligible() {
		t.Fatalf("full boundary not established: %v", err)
	}
	next := input
	next.PM2OperationID = core.ID()
	next.ExpectedRevision++
	next.MemoryMB = 256
	if _, err := s.modulePM2(context.Background(), "update", next); err == nil {
		t.Fatal("513th configuration bypassed retained capacity")
	}
	current, err := s.snapshotPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	originalSHA, _ := before.sha256()
	currentSHA, _ := current.sha256()
	if currentSHA != originalSHA {
		t.Fatal("capacity refusal changed original journal")
	}
	in := core.AppModuleInput{PM2OperationID: core.ID(), ExpectedSHA: originalSHA, Confirm: "ARCHIVE PM2 CONFIGURATIONS " + originalSHA}
	if _, err := s.archivePM2Configurations(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	observed, err := s.readPM2ArchiveRequest(in.PM2OperationID)
	if err != nil || observed.Intent == nil || observed.Outcome == nil || observed.Outcome.State != "archived" || observed.Intent.Inventory.Records != 512 {
		t.Fatalf("complete capacity archive failed: %v", err)
	}
	directory, err := s.openPM2ArchivePath("generations", in.PM2OperationID, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.pm2MovedJournalSnapshot(in.PM2OperationID, before)
	if err != nil || len(raw.Files) != len(before.Files) {
		t.Fatal("original512 records were not retained")
	}
	for name, pin := range before.Files {
		data, err := pm2ConfigRead(directory, name)
		if err != nil || pm2ConfigHash(data) != pin.SHA256 {
			t.Fatal("archived original changed", name, err)
		}
	}
	directory.Close()
	if _, err := s.modulePM2(context.Background(), "update", next); err != nil {
		t.Fatal("new save after full archive failed", err)
	}
	// Check both the real committed request and the last seeded consumed nonce.
	for _, id := range []string{originalIDs[0], originalIDs[len(originalIDs)-1]} {
		record, found, err := s.pm2ArchivedConfigurationRecord(id)
		if err != nil || !found || record.Receipt == nil && record.Cancellation == nil {
			t.Fatal("consumed operation was lost", err)
		}
	}
	next.PM2OperationID = originalIDs[len(originalIDs)-1]
	next.ExpectedRevision++
	if _, err := s.modulePM2(context.Background(), "update", next); err == nil {
		t.Fatal("archived cancelled nonce became a new update")
	}
	active, err := s.snapshotPM2ConfigurationJournal()
	if err != nil || active.Records != 1 {
		t.Fatal("old cancelled request created a fresh intent")
	}
}

func TestPM2JournalArchiveRequestCapacityRefusesWithoutDiscardingEvidence(t *testing.T) {
	s, _ := pm2ArchiveActiveFixture(t)
	requests, err := s.openPM2ArchivePath("requests", "", true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < pm2ConfigurationArchiveGenerations; i++ {
		if err := requests.Mkdir(fmt.Sprintf("%032x", i+1), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := pm2ConfigSync(requests); err != nil {
		t.Fatal(err)
	}
	requests.Close()
	before, err := s.snapshotPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	sha, err := before.sha256()
	if err != nil {
		t.Fatal(err)
	}
	in := core.AppModuleInput{PM2OperationID: core.ID(), ExpectedSHA: sha, Confirm: "ARCHIVE PM2 CONFIGURATIONS " + sha}
	if _, err := s.archivePM2Configurations(context.Background(), in); err == nil {
		t.Fatal("513th request discarded or bypassed retained archive capacity")
	}
	after, err := s.snapshotPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	afterSHA, _ := after.sha256()
	if sha != afterSHA {
		t.Fatal("archive capacity refusal changed active records")
	}
	page, err := s.pm2ConfigurationArchiveReport(core.AppModuleInput{Limit: 32, Offset: 500})
	if err != nil {
		t.Fatal(err)
	}
	view := page.(map[string]any)
	if view["archive_eligible"] != false || view["total"] != 512 || len(view["configuration_archives"].([]any)) != 12 || view["page_complete"] != true {
		t.Fatal("bounded complete512 request inventory was misreported")
	}
	rows, err := s.pm2ArchiveCatalogue()
	if err != nil || len(rows) != 512 {
		t.Fatal("retained requests were deleted")
	}
}

func TestPM2JournalArchiveCompletedBackupUsesOriginalBytesAndRecordedGroup(t *testing.T) {
	s, id, input := pm2ArchiveReadCompleteFixture(t)
	root := filepath.Join(s.moduleDir("pm2-manager"), "configuration-archives", "generations", id)
	names, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		p := filepath.Join(root, name.Name())
		original, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		old, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := pm2JournalIdentityOf(old)
		if err != nil {
			t.Fatal(err)
		}
		temporary := filepath.Join(root, ".owned-restore-"+core.ID())
		if err := os.WriteFile(temporary, original, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(temporary, int(identity.UID), int(identity.GID)); err != nil {
			t.Fatal(err)
		}
		fresh, err := os.Lstat(temporary)
		if err != nil || os.SameFile(old, fresh) {
			t.Fatal("backup fixture did not use a new inode")
		}
		if err := os.Rename(temporary, p); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatal("backup fixture changed original bytes")
		}
	}
	record, found, err := s.pm2ArchivedConfigurationRecord(input.PM2OperationID)
	if err != nil || !found || record.Receipt == nil || record.Receipt.State != "committed" {
		t.Fatal("legitimate completed backup was tied to old inode", err)
	}
}
