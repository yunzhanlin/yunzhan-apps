//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"local/panel/internal/core"
)

func pm2ArchivePhaseFixture(t *testing.T, phase string) (*Service, string, string, pm2JournalSnapshot) {
	t.Helper()
	s, _ := pm2ArchiveActiveFixture(t)
	before, err := s.snapshotPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	id, sha := pm2ArchivePreparedRequestFixture(t, s)
	module, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		t.Fatal(err)
	}
	defer module.Close()
	generations, err := s.openPM2ArchivePath("generations", "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer generations.Close()
	request, err := s.openPM2ArchivePath("requests", id, false)
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	if phase != "before-first" {
		if err := pm2ArchiveRenameNoReplace(module, "configuration-transactions", generations, id); err != nil {
			t.Fatal(err)
		}
	}
	if phase == "after-second" {
		if err := pm2ArchiveRenameNoReplace(request, "prepared-new", module, "configuration-transactions"); err != nil {
			t.Fatal(err)
		}
	}
	return s, id, sha, before
}
func TestPM2JournalArchiveRestoreRetainsOriginalsAtEachFilesystemPhase(t *testing.T) {
	for _, phase := range []string{"before-first", "after-first", "after-second"} {
		t.Run(phase, func(t *testing.T) {
			s, id, sha, before := pm2ArchivePhaseFixture(t, phase)
			calls := 0
			s.Config.Run = func(context.Context, string, ...string) (string, error) { calls++; return "", nil }
			in := core.AppModuleInput{PM2OperationID: id, ExpectedSHA: sha, Confirm: "RESTORE PM2 CONFIG ARCHIVE " + id}
			out, err := s.restorePM2ConfigurationArchive(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			state := "restored_for_review"
			if phase == "before-first" {
				state = "not_moved"
			}
			if out.(map[string]any)["archive"].(map[string]any)["state"] != state || out.(map[string]any)["already_terminal"] != false {
				t.Fatal("reverse recovery completion was misreported")
			}
			active, err := s.snapshotPM2ConfigurationJournal()
			if err != nil || !pm2JournalSameMovedDirectory(before.Directory, active.Directory) || !reflect.DeepEqual(before.Files, active.Files) || calls != 0 {
				t.Fatal("reverse recovery changed original data, metadata or service")
			}
			if generation, err := s.pm2ArchiveGenerationInfo(id); err != nil || generation != nil {
				t.Fatal("original generation was duplicated or left detached")
			}
			again, err := s.restorePM2ConfigurationArchive(context.Background(), in)
			if err != nil || again.(map[string]any)["already_terminal"] != true {
				t.Fatal("terminal reverse recovery replayed directory operations")
			}
			if rows, err := s.pm2ArchiveCatalogue(); err != nil || len(rows) != 1 || rows[0].Restore == nil {
				t.Fatal("explicit reverse choice was lost")
			}
		})
	}
}
func TestPM2JournalArchiveRestoreDirectionCannotBecomeForwardReplay(t *testing.T) {
	s, id, sha, _ := pm2ArchivePhaseFixture(t, "after-second")
	request, err := s.openPM2ArchivePath("requests", id, false)
	if err != nil {
		t.Fatal(err)
	}
	choice := pm2ConfigurationArchiveRestore{Format: 1, ID: id, IntentSHA: sha, Mode: "restore_for_review", RequestedAt: core.Now(), StartedAfterMove: true}
	raw, err := json.Marshal(choice)
	if err != nil {
		t.Fatal(err)
	}
	if err := pm2ArchivePublish(request, "restore.json", raw); err != nil {
		t.Fatal(err)
	}
	request.Close()
	before, err := s.pm2ArchiveActiveDirectoryInfo()
	if err != nil || before == nil {
		t.Fatal(err)
	}
	if _, err := s.recoverPM2ConfigurationArchive(context.Background(), core.AppModuleInput{PM2OperationID: id, ExpectedSHA: sha, Confirm: "RECOVER PM2 CONFIG ARCHIVE " + id}); err == nil {
		t.Fatal("explicit restore choice became a forward retry")
	}
	after, err := s.pm2ArchiveActiveDirectoryInfo()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("refused forward replay changed directory")
	}
	out, err := s.restorePM2ConfigurationArchive(context.Background(), core.AppModuleInput{PM2OperationID: id, ExpectedSHA: sha, Confirm: "RESTORE PM2 CONFIG ARCHIVE " + id})
	if err != nil || out.(map[string]any)["archive"].(map[string]any)["state"] != "restored_for_review" {
		t.Fatal("explicit reverse choice could not resume")
	}
}
func TestPM2JournalArchiveRestorePreservesUnknownOriginalFileContents(t *testing.T) {
	s, id, sha, _ := pm2ArchivePhaseFixture(t, "after-first")
	path := filepath.Join(s.moduleDir("pm2-manager"), "configuration-archives", "generations", id, "retain-original-unknown.json")
	original := []byte("retained original data requiring review")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := s.restorePM2ConfigurationArchive(context.Background(), core.AppModuleInput{PM2OperationID: id, ExpectedSHA: sha, Confirm: "RESTORE PM2 CONFIG ARCHIVE " + id})
	if err != nil || out.(map[string]any)["archive"].(map[string]any)["state"] != "restored_for_review" {
		t.Fatal("original directory was not restored for review")
	}
	restored := filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions", "retain-original-unknown.json")
	got, err := os.ReadFile(restored)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("unknown original evidence was changed or removed")
	}
	if _, err := s.snapshotPM2ConfigurationJournal(); err == nil {
		t.Fatal("restored unknown original was falsely presented as a valid journal")
	}
}
func TestPM2JournalArchiveRestoreNeverOverwritesForeignActiveDirectory(t *testing.T) {
	s, id, sha, _ := pm2ArchivePhaseFixture(t, "after-first")
	path := filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(path, "original-foreign")
	if err := os.WriteFile(sentinel, []byte("retain foreign directory"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.restorePM2ConfigurationArchive(context.Background(), core.AppModuleInput{PM2OperationID: id, ExpectedSHA: sha, Confirm: "RESTORE PM2 CONFIG ARCHIVE " + id}); err == nil {
		t.Fatal("foreign directory was adopted")
	}
	after, err := os.Lstat(path)
	if err != nil || !programQueueSame(before, after) {
		t.Fatal("foreign directory metadata was changed")
	}
	raw, err := os.ReadFile(sentinel)
	if err != nil || string(raw) != "retain foreign directory" {
		t.Fatal("foreign original data was changed")
	}
	if generation, err := s.pm2ArchiveGenerationInfo(id); err != nil || generation == nil {
		t.Fatal("original generation was lost")
	}
}
