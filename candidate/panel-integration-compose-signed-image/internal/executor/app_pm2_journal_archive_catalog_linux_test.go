//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"local/panel/internal/core"
)

func TestPM2JournalArchiveConsumedNonceRemainsOriginalObservation(t *testing.T) {
	s, id, input := pm2ArchiveReadCompleteFixture(t)
	path := filepath.Join(s.moduleDir("pm2-manager"), "apps", input.ResourceID+".json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		calls++
		t.Error("archived nonce attempted service observation or mutation")
		return "", nil
	}
	out, err := s.modulePM2(context.Background(), "update", input)
	if err != nil {
		t.Fatal(err)
	}
	reply, ok := out.(map[string]any)
	if !ok || reply["duplicate_observation"] != true || reply["original_durable_commit"] != true {
		t.Fatal("old successful request was not an original duplicate observation")
	}
	record, found, err := s.pm2ArchivedConfigurationRecord(input.PM2OperationID)
	if err != nil || !found || record.Receipt == nil || record.Receipt.State != "committed" {
		t.Fatal("original committed operation was lost")
	}
	report, err := s.pm2ConfigurationReport(core.AppModuleInput{ResourceID: input.ResourceID, PM2OperationID: input.PM2OperationID})
	if err != nil || report.(map[string]any)["archived_original"] != true {
		t.Fatal("selected original operation was presented as absent")
	}
	cancelled, err := s.modulePM2(context.Background(), "cancel-configuration-request", core.AppModuleInput{ResourceID: input.ResourceID, PM2OperationID: input.PM2OperationID, Confirm: "CANCEL PM2 " + input.PM2OperationID})
	if err != nil || cancelled.(map[string]any)["original_operation_retained"] != true || cancelled.(map[string]any)["request_cancelled"] != false {
		t.Fatal("completed old request was converted into a new cancellation")
	}
	recovered, err := s.modulePM2(context.Background(), "recover-configuration", core.AppModuleInput{ResourceID: input.ResourceID, PM2OperationID: input.PM2OperationID, ExpectedSHA: record.SHA, Confirm: "RECOVER PM2 " + input.PM2OperationID})
	if err != nil || recovered.(map[string]any)["already_terminal"] != true {
		t.Fatal("completed old request was replayed as recovery")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("archived request changed current encrypted manifest")
	}
	current, err := os.Lstat(path)
	if err != nil || !programQueueSame(info, current) || calls != 0 {
		t.Fatal("archived request touched current manifest or service")
	}
	active, err := s.snapshotPM2ConfigurationJournal()
	if err != nil || active.Records != 0 {
		t.Fatal("old request created a fresh active intent")
	}
	rows, err := s.pm2ArchiveCatalogue()
	if err != nil || len(rows) != 1 || rows[0].ID != id {
		t.Fatal("original archive catalogue changed")
	}
}
func TestPM2JournalArchiveNewNonceCanSaveAfterArchivedHistory(t *testing.T) {
	s, _, input := pm2ArchiveReadCompleteFixture(t)
	next := input
	next.PM2OperationID = core.ID()
	next.ExpectedRevision++
	next.MemoryMB = 256
	if _, err := s.modulePM2(context.Background(), "update", next); err != nil {
		t.Fatal(err)
	}
	active, err := s.snapshotPM2ConfigurationJournal()
	if err != nil || active.Records != 1 || !active.eligible() {
		t.Fatal("new configuration could not use the fresh journal")
	}
	old, found, err := s.pm2ArchivedConfigurationRecord(input.PM2OperationID)
	if err != nil || !found || old.Receipt == nil || old.Receipt.State != "committed" {
		t.Fatal("new save discarded old operation evidence")
	}
	again, err := s.modulePM2(context.Background(), "update", input)
	if err != nil || again.(map[string]any)["duplicate_observation"] != true {
		t.Fatal("later revision made old nonce fresh again")
	}
}
func TestPM2JournalArchiveDamagedOriginalNeverBecomesMissingOrFresh(t *testing.T) {
	s, id, input := pm2ArchiveReadCompleteFixture(t)
	path := filepath.Join(s.moduleDir("pm2-manager"), "apps", input.ResourceID+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(s.moduleDir("pm2-manager"), "configuration-archives", "generations", id, input.PM2OperationID+".intent.json")
	damaged := []byte("retain damaged original archive evidence")
	if err := os.WriteFile(original, damaged, 0600); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.pm2ArchivedConfigurationRecord(input.PM2OperationID); !found || err == nil {
		t.Fatal("damaged known operation was presented as absent")
	}
	if _, err := s.modulePM2(context.Background(), "update", input); err == nil {
		t.Fatal("damaged archived operation was replayed")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("damaged history changed current manifest")
	}
	retained, err := os.ReadFile(original)
	if err != nil || !bytes.Equal(retained, damaged) {
		t.Fatal("damaged original was repaired or deleted")
	}
}
func TestPM2JournalArchivePendingMetadataBlocksNewConfigurationWithoutReplay(t *testing.T) {
	s, id, input := pm2ArchiveReadCompleteFixture(t)
	request := filepath.Join(s.moduleDir("pm2-manager"), "configuration-archives", "requests", id)
	retained := filepath.Join(t.TempDir(), "retained-original-outcome.json")
	if err := os.Rename(filepath.Join(request, "outcome.json"), retained); err != nil {
		t.Fatal(err)
	}
	if err := s.pm2NoPendingConfigurationArchives(); err == nil {
		t.Fatal("interrupted archive was treated as terminal")
	}
	path := filepath.Join(s.moduleDir("pm2-manager"), "apps", input.ResourceID+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.Config.Run = func(context.Context, string, ...string) (string, error) { calls++; return "", nil }
	next := input
	next.PM2OperationID = core.ID()
	next.ExpectedRevision++
	next.MemoryMB = 256
	if _, err := s.modulePM2(context.Background(), "update", next); err == nil {
		t.Fatal("new config accepted while original archive required explicit recovery")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || calls != 0 {
		t.Fatal("interrupted archive guard changed current service/config")
	}
	if _, err := os.Stat(retained); err != nil {
		t.Fatal("original outcome evidence was lost")
	}
}
func TestPM2JournalArchiveOrphanGenerationIsNotAnEmptyCatalogue(t *testing.T) {
	s, _, _ := pm2ArchiveReadCompleteFixture(t)
	parent, err := s.openPM2ArchivePath("generations", "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	orphan := core.ID()
	if err := parent.Mkdir(orphan, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pm2ArchiveCatalogue(); err == nil {
		t.Fatal("unknown original generation was silently omitted")
	}
	if _, err := parent.Lstat(orphan); err != nil {
		t.Fatal("unknown original generation was deleted")
	}
}
