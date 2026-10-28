package diskjob

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"local/panel/internal/diskusage"
)

const InventoryBytesMax = 8 << 20

type InventoryRequest struct {
	Format         int    `json:"format"`
	ActorID        string `json:"actor_id"`
	AccessRevision string `json:"access_revision"`
}

func DecodeInventoryRequest(raw []byte) (InventoryRequest, error) {
	var in InventoryRequest
	if decodeReceipt(raw, &in, 1024) != nil || in.Format != 1 || !ValidID(in.ActorID) || !CanonicalInteger(in.AccessRevision, true) {
		return InventoryRequest{}, ErrSelection
	}
	return in, nil
}

type HostState struct {
	Format         int        `json:"format"`
	Installed      bool       `json:"installed"`
	AppVersion     string     `json:"app_version"`
	InstallationID string     `json:"installation_id"`
	AppSHA         string     `json:"app_manifest_sha256"`
	Inventory      *Inventory `json:"inventory"`
}

func DecodeInventory(raw []byte) (Inventory, error) {
	var out Inventory
	if decodeReceipt(raw, &out, InventoryBytesMax) != nil || ValidateInventory(out) != nil {
		return Inventory{}, ErrSelection
	}
	return out, nil
}

func EncodeInventory(in Inventory) ([]byte, error) {
	if ValidateInventory(in) != nil {
		return nil, ErrSelection
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > InventoryBytesMax {
		return nil, ErrSelection
	}
	return raw, nil
}

func ValidateInventory(in Inventory) error {
	i := in.Mounts
	if ValidateHost(in.Host) != nil || i.Format != 1 || !i.MountListComplete || i.SnapshotConsistent || !ValidSHA(i.BindingSHA) || len(i.Mounts) == 0 || len(i.Mounts) > diskusage.MountCountMax {
		return ErrSelection
	}
	seen := map[string]bool{}
	for _, m := range i.Mounts {
		if !CanonicalInteger(m.ID, true) || !CanonicalInteger(m.ParentID, true) || seen[m.ID] || !ValidSHA(m.BindingSHA) || len(m.Point) < 1 || len(m.Root) < 1 || len(m.Point) > 12288 || len(m.Root) > 12288 || !utf8.ValidString(m.Point) || !utf8.ValidString(m.Root) || !strings.HasPrefix(m.Point, "/") || len(m.Filesystem) < 1 || len(m.Filesystem) > 64 {
			return ErrSelection
		}
		seen[m.ID] = true
		switch m.Class {
		case "local", "kernel_virtual", "remote_or_userspace", "unknown":
		default:
			return ErrSelection
		}
		if m.Actionable && (!diskusage.ValidHostPath(m.Point) || !diskusage.ValidHostPath(m.Root)) {
			return ErrSelection
		}
	}
	return nil
}

func ValidateHostState(s HostState) error {
	if s.Format != 1 {
		return ErrSelection
	}
	if !s.Installed {
		if s.AppVersion != "" || s.InstallationID != "" || s.AppSHA != "" || s.Inventory != nil {
			return ErrSelection
		}
		return nil
	}
	if !HostAppVersionSupported(s.AppVersion) {
		if s.InstallationID != "" || s.AppSHA != "" || s.Inventory != nil {
			return ErrSelection
		}
		return nil
	}
	if !ValidID(s.InstallationID) || !ValidSHA(s.AppSHA) || s.Inventory == nil || ValidateInventory(*s.Inventory) != nil {
		return ErrSelection
	}
	return nil
}

type DispatchAck struct {
	Format      int    `json:"format"`
	JobID       string `json:"job_id"`
	RequestSHA  string `json:"request_sha256"`
	ObserveOnly bool   `json:"observe_only"`
}

type CancelAck struct {
	Format          int    `json:"format"`
	JobID           string `json:"job_id"`
	RequestSHA      string `json:"request_sha256"`
	SignalRequested bool   `json:"signal_requested"`
}

func ValidateCancelAck(a CancelAck, in Request) error {
	return ValidateDispatchAck(DispatchAck{Format: a.Format, JobID: a.JobID, RequestSHA: a.RequestSHA}, in)
}

func ValidateDispatchAck(a DispatchAck, in Request) error {
	if ValidateRequest(in) != nil || a.Format != 1 || a.JobID != in.JobID || a.RequestSHA != RequestSHA(in) {
		return ErrReceipt
	}
	return nil
}
