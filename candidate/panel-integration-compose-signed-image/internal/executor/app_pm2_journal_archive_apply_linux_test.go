//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"local/panel/internal/core"
)

func pm2ArchiveActiveFixture(t *testing.T) (*Service, core.AppModuleInput) {
	t.Helper()
	s, app, _ := pm2StateAppFixture(t)
	s.Config.Run = func(_ context.Context, command string, args ...string) (string, error) {
		if command != "/usr/bin/systemctl" || len(args) != 3 || args[0] != "show" {
			t.Fatalf("fixture attempted service mutation: %s %v", command, args)
		}
		return pm2TestStateText(pm2TestState("inactive", "disabled")), nil
	}
	in := core.AppModuleInput{ResourceID: app.ID, ExpectedRevision: app.Revision, PM2OperationID: core.ID(), MemoryMB: 192}
	if _, err := s.modulePM2(context.Background(), "update", in); err != nil {
		t.Fatal(err)
	}
	return s, in
}
func pm2ArchivePreparedRequestFixture(t *testing.T, s *Service) (string, string) {
	t.Helper()
	snapshot, err := s.snapshotPM2ConfigurationJournal()
	if err != nil || !snapshot.eligible() {
		t.Fatalf("active fixture: %v", err)
	}
	requests, err := s.openPM2ArchivePath("requests", "", true)
	if err != nil {
		t.Fatal(err)
	}
	id := core.ID()
	if err := requests.Mkdir(id, 0700); err != nil {
		t.Fatal(err)
	}
	if err := pm2ConfigSync(requests); err != nil {
		t.Fatal(err)
	}
	requests.Close()
	generations, err := s.openPM2ArchivePath("generations", "", true)
	if err != nil {
		t.Fatal(err)
	}
	generations.Close()
	request, err := s.openPM2ArchivePath("requests", id, false)
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	if err := request.Mkdir("prepared-new", 0700); err != nil {
		t.Fatal(err)
	}
	if err := pm2ConfigSync(request); err != nil {
		t.Fatal(err)
	}
	prepared, err := s.openPM2ArchivePrepared(id)
	if err != nil {
		t.Fatal(err)
	}
	info, err := prepared.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := pm2JournalIdentityOf(info)
	if err != nil {
		t.Fatal(err)
	}
	prepared.Close()
	digest, err := snapshot.sha256()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := currentModuleApplyOwner()
	if err != nil {
		t.Fatal(err)
	}
	boot, err := currentPM2ConfigBoot()
	if err != nil {
		t.Fatal(err)
	}
	intent := pm2ConfigurationArchiveIntent{Format: 1, ID: id, CreatedAt: core.Now(), BootID: boot, Owner: owner, RequestSHA: core.Hash("owned interrupted request"), Inventory: snapshot, InventorySHA: digest, PreparedDirectory: identity}
	if err := validatePM2ConfigurationArchiveIntent(intent); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := pm2ArchivePublish(request, "intent.json", raw); err != nil {
		t.Fatal(err)
	}
	return id, pm2ConfigHash(raw)
}
func TestPM2JournalArchiveApplyPreservesManifestServicesAndOriginalNonce(t *testing.T) {
	s, originalInput := pm2ArchiveActiveFixture(t)
	path := filepath.Join(s.moduleDir("pm2-manager"), "apps", originalInput.ResourceID+".json")
	before, err := os.ReadFile(path)
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
		t.Error("archive tried to change a service")
		return "", nil
	}
	report, err := s.pm2ConfigurationArchiveReport(core.AppModuleInput{})
	if err != nil {
		t.Fatal(err)
	}
	preview := report.(map[string]any)
	if preview["archive_eligible"] != true || preview["active_record_count"] != 1 {
		t.Fatal("complete active journal was not available for explicit archive")
	}
	digest := preview["inventory_sha256"].(string)
	in := core.AppModuleInput{PM2OperationID: core.ID(), ExpectedSHA: digest, Confirm: "ARCHIVE PM2 CONFIGURATIONS " + digest}
	out, err := s.archivePM2Configurations(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	reply := out.(map[string]any)
	if reply["already_terminal"] != false || reply["archive"].(map[string]any)["state"] != "archived" {
		t.Fatal("new archive completion was not acknowledged accurately")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("archive changed encrypted manifest")
	}
	now, err := os.Lstat(path)
	if err != nil || !programQueueSame(info, now) || calls != 0 {
		t.Fatal("archive changed service or original manifest metadata")
	}
	active, err := s.snapshotPM2ConfigurationJournal()
	if err != nil || !active.Exists || active.Records != 0 {
		t.Fatal("new active private journal not established")
	}
	old, found, err := s.pm2ArchivedConfigurationRecord(originalInput.PM2OperationID)
	if err != nil || !found || old.Receipt == nil || old.Receipt.State != "committed" {
		t.Fatal("original consumed configuration operation was lost")
	}
	again, err := s.archivePM2Configurations(context.Background(), in)
	if err != nil || again.(map[string]any)["duplicate_observation"] != true {
		t.Fatal("duplicate archive request was replayed")
	}
	rows, err := s.pm2ArchiveCatalogue()
	if err != nil || len(rows) != 1 {
		t.Fatal("duplicate archive reserved another generation")
	}
}
func TestPM2JournalArchiveApplyRefusesStalePendingOrUnexpectedInputs(t *testing.T) {
	for _, kind := range []string{"stale", "pending", "extra-fields", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			var s *Service
			if kind == "pending" {
				s, _, _, _ = pm2ConfigFixtureIntent(t)
			} else {
				s, _ = pm2ArchiveActiveFixture(t)
			}
			snapshot, err := s.snapshotPM2ConfigurationJournal()
			if err != nil {
				t.Fatal(err)
			}
			digest, err := snapshot.sha256()
			if err != nil {
				t.Fatal(err)
			}
			if kind == "stale" {
				digest = core.Hash("different original inventory")
			}
			in := core.AppModuleInput{PM2OperationID: core.ID(), ExpectedSHA: digest, Confirm: "ARCHIVE PM2 CONFIGURATIONS " + digest}
			if kind == "extra-fields" {
				in.ResourceID = "other-project"
			}
			ctx := context.Background()
			if kind == "cancelled" {
				next, cancel := context.WithCancel(ctx)
				cancel()
				ctx = next
			}
			if _, err := s.archivePM2Configurations(ctx, in); err == nil {
				t.Fatal("invalid archive request accepted")
			}
			after, err := s.snapshotPM2ConfigurationJournal()
			if err != nil {
				t.Fatal(err)
			}
			afterSHA, err := after.sha256()
			if err != nil {
				t.Fatal(err)
			}
			beforeSHA, err := snapshot.sha256()
			if err != nil || beforeSHA != afterSHA {
				t.Fatal("refusal changed original journal")
			}
			if _, err := os.Lstat(filepath.Join(s.moduleDir("pm2-manager"), "configuration-archives")); !os.IsNotExist(err) {
				t.Fatal("refusal reserved an archive namespace")
			}
		})
	}
}
func TestPM2JournalArchiveRecoveryFinishesEachBoundFilesystemPhase(t *testing.T) {
	for _, phase := range []string{"before-first", "after-first", "after-second"} {
		t.Run(phase, func(t *testing.T) {
			s, input := pm2ArchiveActiveFixture(t)
			id, sha := pm2ArchivePreparedRequestFixture(t, s)
			module, err := s.moduleRecordDirectory("pm2-manager")
			if err != nil {
				t.Fatal(err)
			}
			generations, err := s.openPM2ArchivePath("generations", "", false)
			if err != nil {
				t.Fatal(err)
			}
			request, err := s.openPM2ArchivePath("requests", id, false)
			if err != nil {
				t.Fatal(err)
			}
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
			request.Close()
			generations.Close()
			module.Close()
			path := filepath.Join(s.moduleDir("pm2-manager"), "apps", input.ResourceID+".json")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			s.Config.Run = func(context.Context, string, ...string) (string, error) { calls++; return "", nil }
			in := core.AppModuleInput{PM2OperationID: id, ExpectedSHA: sha, Confirm: "RECOVER PM2 CONFIG ARCHIVE " + id}
			out, err := s.recoverPM2ConfigurationArchive(context.Background(), in)
			if err != nil || out.(map[string]any)["archive"].(map[string]any)["state"] != "archived" {
				t.Fatalf("explicit recovery did not finish phase: %v", err)
			}
			again, err := s.recoverPM2ConfigurationArchive(context.Background(), in)
			if err != nil || again.(map[string]any)["already_terminal"] != true {
				t.Fatal("terminal recovery replayed relocation")
			}
			current, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, current) || calls != 0 {
				t.Fatal("recovery changed manifest or service")
			}
			old, found, err := s.pm2ArchivedConfigurationRecord(input.PM2OperationID)
			if err != nil || !found || old.Receipt == nil {
				t.Fatal("recovery lost original config operation")
			}
		})
	}
}
func TestPM2JournalArchiveRecoveryNeverAdoptsForeignActiveDirectory(t *testing.T) {
	s, _ := pm2ArchiveActiveFixture(t)
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
	if err := pm2ArchiveRenameNoReplace(module, "configuration-transactions", generations, id); err != nil {
		t.Fatal(err)
	}
	if err := module.Mkdir("configuration-transactions", 0700); err != nil {
		t.Fatal(err)
	}
	foreign, err := module.Lstat("configuration-transactions")
	if err != nil {
		t.Fatal(err)
	}
	in := core.AppModuleInput{PM2OperationID: id, ExpectedSHA: sha, Confirm: "RECOVER PM2 CONFIG ARCHIVE " + id}
	if _, err := s.recoverPM2ConfigurationArchive(context.Background(), in); err == nil {
		t.Fatal("foreign empty active directory was adopted")
	}
	after, err := module.Lstat("configuration-transactions")
	if err != nil || !programQueueSame(foreign, after) {
		t.Fatal("foreign directory was replaced")
	}
	if _, err := s.pm2ArchiveGenerationInfo(id); err != nil {
		t.Fatal("original generation was removed")
	}
	prepared, err := s.openPM2ArchivePrepared(id)
	if err != nil {
		t.Fatal("original prepared directory was removed")
	}
	prepared.Close()
}
func TestPM2JournalArchiveReservedUnacceptedIDNeverReplays(t *testing.T) {
	s, _ := pm2ArchiveActiveFixture(t)
	requests, err := s.openPM2ArchivePath("requests", "", true)
	if err != nil {
		t.Fatal(err)
	}
	id := core.ID()
	if err := requests.Mkdir(id, 0700); err != nil {
		t.Fatal(err)
	}
	requests.Close()
	snapshot, err := s.snapshotPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	sha, err := snapshot.sha256()
	if err != nil {
		t.Fatal(err)
	}
	in := core.AppModuleInput{PM2OperationID: id, ExpectedSHA: sha, Confirm: "ARCHIVE PM2 CONFIGURATIONS " + sha}
	out, err := s.archivePM2Configurations(context.Background(), in)
	if err != nil || out.(map[string]any)["duplicate_observation"] != true || out.(map[string]any)["archive"].(map[string]any)["state"] != "not_started" {
		t.Fatal("unaccepted reserved request was replayed")
	}
	active, err := s.snapshotPM2ConfigurationJournal()
	if err != nil || active.Records != snapshot.Records {
		t.Fatal("unaccepted duplicate moved original data")
	}
}
