//go:build linux

package executor

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
)

const pm2ConfigurationArchiveGenerations = 512
const pm2ConfigurationArchiveIntentLimit = 1 << 20

// The request identity is reserved before publication. Its prepared empty
// directory is recorded before either no-replace rename. Both crash boundaries
// can consequently be distinguished without adopting an unknown active path.
type pm2ConfigurationArchiveIntent struct {
	Format            int                `json:"format"`
	ID                string             `json:"id"`
	CreatedAt         string             `json:"created_at"`
	BootID            string             `json:"boot_id"`
	Owner             *moduleApplyOwner  `json:"owner"`
	RequestSHA        string             `json:"request_sha256"`
	Inventory         pm2JournalSnapshot `json:"inventory"`
	InventorySHA      string             `json:"inventory_sha256"`
	PreparedDirectory pm2JournalIdentity `json:"prepared_directory"`
}

type pm2ConfigurationArchiveOutcome struct {
	Format            int                `json:"format"`
	ID                string             `json:"id"`
	IntentSHA         string             `json:"intent_sha256"`
	State             string             `json:"state"`
	FinishedAt        string             `json:"finished_at"`
	OriginalDirectory pm2JournalIdentity `json:"original_directory"`
	ActiveDirectory   pm2JournalIdentity `json:"active_directory"`
}

func pm2JournalPrivateDirectoryIdentity(v pm2JournalIdentity) bool {
	return v.UID == uint32(os.Geteuid()) && v.Mode == syscall.S_IFDIR|0700 && v.Inode != 0 && v.Links > 0 && v.Size >= 0
}
func pm2JournalSameDirectoryObject(a, b pm2JournalIdentity) bool {
	return a.Device == b.Device && a.Inode == b.Inode && a.UID == b.UID && a.GID == b.GID && a.Mode == b.Mode && pm2JournalPrivateDirectoryIdentity(a) && pm2JournalPrivateDirectoryIdentity(b)
}

// A directory rename changes its ctime. Retain every other recorded field,
// including its original group; never replace it with the reader's own GID.
// This witness is for an unfinished relocation. Completed archive data will
// be read through fresh no-follow identities and original content/owner pins,
// so an old device/inode is not treated as a permanent server identifier.
func pm2JournalSameMovedDirectory(a, b pm2JournalIdentity) bool {
	return pm2JournalSameDirectoryObject(a, b) && a.Links == b.Links && a.Size == b.Size && a.ModifiedNS == b.ModifiedNS
}
func validatePM2ArchiveSnapshot(v pm2JournalSnapshot) error {
	if v.Format != 1 || !v.eligible() || v.Records > pm2ConfigIntentLimit || !pm2JournalPrivateDirectoryIdentity(v.Directory) || len(v.Files) > 2*pm2ConfigIntentLimit {
		return errors.New("PM2 archive requires a complete nonempty terminal journal")
	}
	kinds := map[string]map[string]bool{}
	type key struct{ device, inode uint64 }
	identities := map[key]bool{}
	var total int64
	for name, pin := range v.Files {
		id, kind := "", ""
		for _, suffix := range []string{".intent.json", ".result.json", ".cancel.json"} {
			if original, ok := strings.CutSuffix(name, suffix); ok {
				id, kind = original, suffix
				break
			}
		}
		p := pin.Identity
		if !core.ValidID(id) || kind == "" || !coreSHA.MatchString(pin.SHA256) || p.UID != uint32(os.Geteuid()) || p.Mode != syscall.S_IFREG|0600 || p.Links != 1 || p.Inode == 0 || p.Size < 1 || p.Size > pm2ConfigRecordLimit {
			return errors.New("PM2 archive original file binding is invalid")
		}
		inode := key{p.Device, p.Inode}
		if identities[inode] {
			return errors.New("PM2 archive original file identities are aliased")
		}
		identities[inode] = true
		total += p.Size
		if total > 64<<20 {
			return errors.New("PM2 archive original journal exceeds its byte budget")
		}
		if kinds[id] == nil {
			kinds[id] = map[string]bool{}
		}
		kinds[id][kind] = true
	}
	if len(kinds) != v.Records {
		return errors.New("PM2 archive complete record count does not match its original files")
	}
	for _, parts := range kinds {
		if parts[".cancel.json"] {
			if len(parts) != 1 {
				return errors.New("PM2 archive cancellation conflicts with an original intent")
			}
		} else if len(parts) != 2 || !parts[".intent.json"] || !parts[".result.json"] {
			return errors.New("PM2 archive contains an unfinished original configuration")
		}
	}
	return nil
}
func validatePM2ConfigurationArchiveIntent(v pm2ConfigurationArchiveIntent) error {
	_, timeErr := time.Parse(time.RFC3339, v.CreatedAt)
	if v.Format != 1 || !core.ValidID(v.ID) || timeErr != nil || !moduleBootID.MatchString(v.BootID) || v.Owner == nil || v.Owner.PID <= 1 || v.Owner.StartTime == 0 || !coreSHA.MatchString(v.RequestSHA) || !coreSHA.MatchString(v.InventorySHA) {
		return errors.New("PM2 archive intent identity is invalid")
	}
	if err := validatePM2ArchiveSnapshot(v.Inventory); err != nil {
		return err
	}
	sha, err := v.Inventory.sha256()
	if err != nil || sha != v.InventorySHA {
		return errors.New("PM2 archive intent does not bind the complete original inventory")
	}
	if !pm2JournalPrivateDirectoryIdentity(v.PreparedDirectory) || v.PreparedDirectory.Device != v.Inventory.Directory.Device || (v.Inventory.Directory.Device == v.PreparedDirectory.Device && v.Inventory.Directory.Inode == v.PreparedDirectory.Inode) {
		return errors.New("PM2 archive prepared directory cannot be distinguished from the original")
	}
	return nil
}
func validatePM2ConfigurationArchiveOutcome(v pm2ConfigurationArchiveOutcome, intent pm2ConfigurationArchiveIntent, intentSHA string) error {
	if err := validatePM2ConfigurationArchiveIntent(intent); err != nil {
		return err
	}
	_, timeErr := time.Parse(time.RFC3339, v.FinishedAt)
	if v.Format != 1 || v.ID != intent.ID || !coreSHA.MatchString(intentSHA) || v.IntentSHA != intentSHA || timeErr != nil {
		return errors.New("PM2 archive outcome does not match its original intent")
	}
	switch v.State {
	case "archived":
		if !pm2JournalSameMovedDirectory(intent.Inventory.Directory, v.OriginalDirectory) || !pm2JournalSameMovedDirectory(intent.PreparedDirectory, v.ActiveDirectory) {
			return errors.New("PM2 archive completion directory bindings are invalid")
		}
	case "not_moved", "restored_for_review":
		if !pm2JournalSameDirectoryObject(intent.Inventory.Directory, v.ActiveDirectory) {
			return errors.New("PM2 archive original active directory was not retained")
		}
	default:
		return errors.New("PM2 archive outcome state is unknown")
	}
	return nil
}

// A reverse recovery is a durable explicit choice before either reverse
// rename. A later read or forward retry must never silently reverse it.
type pm2ConfigurationArchiveRestore struct {
	StartedAfterMove bool   `json:"started_after_move"`
	Format           int    `json:"format"`
	ID               string `json:"id"`
	IntentSHA        string `json:"intent_sha256"`
	Mode             string `json:"mode"`
	RequestedAt      string `json:"requested_at"`
}

func validatePM2ConfigurationArchiveRestore(v pm2ConfigurationArchiveRestore, id, intentSHA string) error {
	_, err := time.Parse(time.RFC3339, v.RequestedAt)
	if v.Format != 1 || !core.ValidID(v.ID) || v.ID != id || !coreSHA.MatchString(intentSHA) || v.IntentSHA != intentSHA || v.Mode != "restore_for_review" || err != nil {
		return errors.New("PM2 archive explicit restore choice cannot be verified")
	}
	return nil
}
