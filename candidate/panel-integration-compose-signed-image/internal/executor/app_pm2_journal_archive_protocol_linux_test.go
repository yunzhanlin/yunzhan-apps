//go:build linux

package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"local/panel/internal/core"
)

func pm2ArchiveProtocolFixture(t *testing.T) pm2ConfigurationArchiveIntent {
	t.Helper()
	s, _, _, record := pm2ConfigFixtureIntent(t)
	d, err := s.openPM2ConfigStore(false)
	if err != nil {
		t.Fatal(err)
	}
	receipt := pm2ConfigReceipt{Format: 1, ID: record.Intent.ID, IntentSHA: record.SHA, State: "rolled_back", ManifestSHA: record.Intent.BeforeSHA, FinishedAt: core.Now()}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := pm2ConfigCreate(d.modulePrivateDirectory, record.Intent.ID+".result.json", raw); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.snapshotPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	sha, err := snapshot.sha256()
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(s.moduleDir("pm2-manager"), "archive-protocol-prepared")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(stage)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := pm2JournalIdentityOf(info)
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
	v := pm2ConfigurationArchiveIntent{Format: 1, ID: core.ID(), CreatedAt: core.Now(), BootID: boot, Owner: owner, RequestSHA: core.Hash("original archive request"), Inventory: snapshot, InventorySHA: sha, PreparedDirectory: identity}
	if err := validatePM2ConfigurationArchiveIntent(v); err != nil {
		t.Fatal(err)
	}
	return v
}
func pm2ArchiveProtocolClone(t *testing.T, v pm2ConfigurationArchiveIntent) pm2ConfigurationArchiveIntent {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var next pm2ConfigurationArchiveIntent
	if err := json.Unmarshal(raw, &next); err != nil {
		t.Fatal(err)
	}
	return next
}
func pm2ArchiveProtocolSHA(t *testing.T, v pm2ConfigurationArchiveIntent) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return pm2ConfigHash(raw)
}
func TestPM2JournalArchiveProtocolRejectsUnfinishedOrReboundInventories(t *testing.T) {
	original := pm2ArchiveProtocolFixture(t)
	cases := map[string]func(*pm2ConfigurationArchiveIntent){
		"pending": func(v *pm2ConfigurationArchiveIntent) { v.Inventory.Pending = []string{core.ID()} },
		"missing-receipt": func(v *pm2ConfigurationArchiveIntent) {
			for name := range v.Inventory.Files {
				if filepath.Ext(name) == ".json" && name[len(name)-12:] == ".result.json" {
					delete(v.Inventory.Files, name)
				}
			}
		},
		"wrong-count": func(v *pm2ConfigurationArchiveIntent) { v.Inventory.Records++ },
		"aliased-originals": func(v *pm2ConfigurationArchiveIntent) {
			var first *pm2JournalFilePin
			for name, pin := range v.Inventory.Files {
				if first == nil {
					copy := pin
					first = &copy
					continue
				}
				pin.Identity = first.Identity
				v.Inventory.Files[name] = pin
			}
		},
		"wrong-owner": func(v *pm2ConfigurationArchiveIntent) {
			for name, pin := range v.Inventory.Files {
				pin.Identity.UID++
				v.Inventory.Files[name] = pin
				break
			}
		},
		"public-record": func(v *pm2ConfigurationArchiveIntent) {
			for name, pin := range v.Inventory.Files {
				pin.Identity.Mode = 0100644
				v.Inventory.Files[name] = pin
				break
			}
		},
		"linked-record": func(v *pm2ConfigurationArchiveIntent) {
			for name, pin := range v.Inventory.Files {
				pin.Identity.Links = 2
				v.Inventory.Files[name] = pin
				break
			}
		},
		"damaged-pin": func(v *pm2ConfigurationArchiveIntent) {
			for name, pin := range v.Inventory.Files {
				pin.SHA256 = "damaged"
				v.Inventory.Files[name] = pin
				break
			}
		},
		"source-as-prepared": func(v *pm2ConfigurationArchiveIntent) {
			v.PreparedDirectory = v.Inventory.Directory
			v.PreparedDirectory.GID++
		},
		"cross-device-prepared": func(v *pm2ConfigurationArchiveIntent) { v.PreparedDirectory.Device ^= 1 },
		"missing-owner-time":    func(v *pm2ConfigurationArchiveIntent) { v.Owner.StartTime = 0 },
		"unknown-format":        func(v *pm2ConfigurationArchiveIntent) { v.Format++ },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			v := pm2ArchiveProtocolClone(t, original)
			alter(&v)
			sha, err := v.Inventory.sha256()
			if err != nil {
				t.Fatal(err)
			}
			v.InventorySHA = sha
			if err := validatePM2ConfigurationArchiveIntent(v); err == nil {
				t.Fatal("unverifiable or unfinished archive intent accepted")
			}
		})
	}
	stale := pm2ArchiveProtocolClone(t, original)
	stale.Inventory.Directory.ChangedNS++
	if err := validatePM2ConfigurationArchiveIntent(stale); err == nil {
		t.Fatal("stale complete inventory digest was accepted")
	}
}
func TestPM2JournalArchiveProtocolRetainsRecordedGroupAndRenameWitnesses(t *testing.T) {
	intent := pm2ArchiveProtocolFixture(t)
	// Recorded groups are witnesses. They may differ from this reader's group.
	recordedGroup := uint32(987)
	if recordedGroup == uint32(os.Getegid()) {
		recordedGroup++
	}
	intent.Inventory.Directory.GID = recordedGroup
	intent.PreparedDirectory.GID = recordedGroup + 1
	sha, err := intent.Inventory.sha256()
	if err != nil {
		t.Fatal(err)
	}
	intent.InventorySHA = sha
	original := intent.Inventory.Directory
	original.ChangedNS++
	active := intent.PreparedDirectory
	active.ChangedNS++
	outcome := pm2ConfigurationArchiveOutcome{Format: 1, ID: intent.ID, IntentSHA: pm2ArchiveProtocolSHA(t, intent), State: "archived", FinishedAt: core.Now(), OriginalDirectory: original, ActiveDirectory: active}
	if err := validatePM2ConfigurationArchiveOutcome(outcome, intent, outcome.IntentSHA); err != nil {
		t.Fatal(err)
	}
	wrongGroup := outcome
	wrongGroup.OriginalDirectory.GID = uint32(os.Getegid())
	if err := validatePM2ConfigurationArchiveOutcome(wrongGroup, intent, outcome.IntentSHA); err == nil {
		t.Fatal("reader group substituted for recorded original group")
	}
	wrongInode := outcome
	wrongInode.ActiveDirectory.Inode++
	if err := validatePM2ConfigurationArchiveOutcome(wrongInode, intent, outcome.IntentSHA); err == nil {
		t.Fatal("unbound new active directory adopted")
	}
	if err := validatePM2ConfigurationArchiveOutcome(outcome, intent, core.Hash("different original header")); err == nil {
		t.Fatal("receipt for a different original intent accepted")
	}
	for _, state := range []string{"not_moved", "restored_for_review"} {
		retained := outcome
		retained.State = state
		retained.ActiveDirectory = original
		if err := validatePM2ConfigurationArchiveOutcome(retained, intent, outcome.IntentSHA); err != nil {
			t.Fatal(err)
		}
	}
}
