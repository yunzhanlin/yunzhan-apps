//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"local/panel/internal/core"
)

func TestPM2JournalArchiveReadRetainsUnacceptedEmptyFragment(t *testing.T) {
	s, d, id := pm2ArchiveStoreFixture(t)
	name := "intent." + core.ID() + ".part"
	f, err := d.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pm2ConfigWriteDurable(f, nil); err != nil {
		t.Fatal(err)
	}
	d.Close()
	observed, err := s.readPM2ArchiveRequest(id)
	if err != nil || observed.Intent != nil || observed.Outcome != nil || len(observed.Fragments) != 1 {
		t.Fatalf("unaccepted evidence observation: %#v %v", observed, err)
	}
	pin := observed.Fragments[name]
	if pin.Identity.Size != 0 || pin.SHA256 != pm2ConfigHash(nil) {
		t.Fatal("empty original fragment was not retained and bound")
	}
}

func pm2ArchiveReadCompleteFixture(t *testing.T) (*Service, string, core.AppModuleInput) {
	t.Helper()
	s, app, _ := pm2StateAppFixture(t)
	s.Config.Run = func(_ context.Context, command string, args ...string) (string, error) {
		if command != "/usr/bin/systemctl" || len(args) != 3 || args[0] != "show" {
			t.Fatalf("archive fixture attempted a service change: %s %v", command, args)
		}
		return pm2TestStateText(pm2TestState("inactive", "disabled")), nil
	}
	input := core.AppModuleInput{ResourceID: app.ID, ExpectedRevision: app.Revision, PM2OperationID: core.ID(), MemoryMB: 192}
	if _, err := s.modulePM2(context.Background(), "update", input); err != nil {
		t.Fatal(err)
	}
	active, err := s.openPM2ConfigStore(false)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := active.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	active.Close()
	parent, err := s.openPM2ArchivePath("requests", "", true)
	if err != nil {
		t.Fatal(err)
	}
	id := core.ID()
	if err := parent.Mkdir(id, 0700); err != nil {
		t.Fatal(err)
	}
	parent.Close()
	d, err := s.openPM2ArchivePath("requests", id, false)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Mkdir("prepared-new", 0700); err != nil {
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
	preparedIdentity, err := pm2JournalIdentityOf(info)
	if err != nil {
		t.Fatal(err)
	}
	prepared.Close()
	inventorySHA, err := inventory.sha256()
	if err != nil {
		t.Fatal(err)
	}
	boot, err := currentPM2ConfigBoot()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := currentModuleApplyOwner()
	if err != nil {
		t.Fatal(err)
	}
	intent := pm2ConfigurationArchiveIntent{Format: 1, ID: id, CreatedAt: core.Now(), BootID: boot, Owner: owner, RequestSHA: core.Hash("owned explicit archive request"), Inventory: inventory, InventorySHA: inventorySHA, PreparedDirectory: preparedIdentity}
	if err := validatePM2ConfigurationArchiveIntent(intent); err != nil {
		t.Fatal(err)
	}
	intentRaw, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	intentRaw = append(intentRaw, '\n')
	if err := pm2ArchivePublish(d, "intent.json", intentRaw); err != nil {
		t.Fatal(err)
	}
	before, err := s.readPM2ArchiveRequest(id)
	if err != nil || before.IntentSHA != pm2ConfigHash(intentRaw) || before.Prepared == nil || !before.PreparedEmpty || before.Outcome != nil {
		t.Fatalf("original preparation not observed: %#v %v", before, err)
	}
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
	if err := pm2ArchiveRenameNoReplace(module, "configuration-transactions", generations, id); err != nil {
		t.Fatal(err)
	}
	if err := pm2ArchiveRenameNoReplace(d, "prepared-new", module, "configuration-transactions"); err != nil {
		t.Fatal(err)
	}
	generation, err := s.pm2ArchiveGenerationInfo(id)
	if err != nil || generation == nil {
		t.Fatal("original generation was not retained")
	}
	newActive, err := s.snapshotPM2ConfigurationJournal()
	if err != nil || newActive.Records != 0 || !newActive.Exists {
		t.Fatal("prepared empty journal was not published")
	}
	outcome := pm2ConfigurationArchiveOutcome{Format: 1, ID: id, IntentSHA: pm2ConfigHash(intentRaw), State: "archived", FinishedAt: core.Now(), OriginalDirectory: *generation, ActiveDirectory: newActive.Directory}
	if err := validatePM2ConfigurationArchiveOutcome(outcome, intent, outcome.IntentSHA); err != nil {
		t.Fatal(err)
	}
	outcomeRaw, err := json.MarshalIndent(outcome, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	outcomeRaw = append(outcomeRaw, '\n')
	if err := pm2ArchivePublish(d, "outcome.json", outcomeRaw); err != nil {
		t.Fatal(err)
	}
	observed, err := s.readPM2ArchiveRequest(id)
	if err != nil || observed.Outcome == nil || observed.Outcome.State != "archived" || observed.Prepared != nil || observed.IntentSHA != pm2ConfigHash(intentRaw) || observed.OutcomeSHA != pm2ConfigHash(outcomeRaw) {
		t.Fatalf("original archive outcome not durably observed: %#v %v", observed, err)
	}
	return s, id, input
}

func TestPM2JournalArchiveReadActualPrivateWholeGenerationAndOutcome(t *testing.T) {
	pm2ArchiveReadCompleteFixture(t)
}

func TestPM2JournalArchiveReadUnknownFinalEvidenceIsNeverEmpty(t *testing.T) {
	for _, kind := range []string{"unknown", "malformed-intent", "orphan-outcome"} {
		t.Run(kind, func(t *testing.T) {
			s, d, id := pm2ArchiveStoreFixture(t)
			switch kind {
			case "unknown":
				f, err := d.OpenFile("retain-unknown.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if err := pm2ConfigWriteDurable(f, []byte("original evidence")); err != nil {
					t.Fatal(err)
				}
			case "malformed-intent":
				if err := pm2ArchivePublish(d, "intent.json", []byte("original malformed intent")); err != nil {
					t.Fatal(err)
				}
			case "orphan-outcome":
				raw, err := json.Marshal(pm2ConfigurationArchiveOutcome{Format: 1, ID: id, IntentSHA: core.Hash("missing original"), State: "archived", FinishedAt: core.Now()})
				if err != nil {
					t.Fatal(err)
				}
				if err := pm2ArchivePublish(d, "outcome.json", raw); err != nil {
					t.Fatal(err)
				}
			}
			before, err := pm2ArchiveNames(d, 64)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.readPM2ArchiveRequest(id); err == nil {
				t.Fatal("unverifiable original evidence was presented as an empty/valid request")
			}
			after, err := pm2ArchiveNames(d, 64)
			if err != nil || len(before) != len(after) {
				t.Fatal("read removed original evidence")
			}
			d.Close()
		})
	}
}
