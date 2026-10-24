package core

import (
	"bytes"
	"encoding/json"
	"errors"

	"local/panel/internal/appcatalog"
)

// This independent immutable event format is evidence, not an official
// signature, live Core grant, account ownership proof, or Docker capability.
// Interrupted intents are never inferred to have succeeded or silently replayed.
const MemcachedUnixInstallEvents = 12
const MaxMemcachedUnixInstallRecordBytes = 128 << 10

type MemcachedUnixInstallRecord struct {
	Format           int                  `json:"format"`
	Sequence         int                  `json:"sequence"`
	Operation        DockerProjectRequest `json:"operation"`
	Binding          MemcachedUnixBinding `json:"binding"`
	SubmissionSHA256 string               `json:"submission_sha256"`
	CatalogSHA256    string               `json:"catalog_sha256"`
	Phase            string               `json:"phase"`
	UID              uint32               `json:"uid"`
	GID              uint32               `json:"gid"`
	ImageID          string               `json:"image_id"`
	ComposeSHA256    string               `json:"compose_sha256"`
	ContainerID      string               `json:"container_id"`
	Fault            string               `json:"fault"`
}

var errMemcachedUnixInstallRecord = errors.New("Memcached Socket 原安装事件或连续性绑定无效，保留原证据，不重发")

var memcachedUnixInstallPhases = [...]string{
	"prepared", "account-intent", "account-verified", "pull-intent", "image-verified",
	"project-intent", "project-written", "start-intent", "runtime-verified", "committed",
}

func memcachedUnixInstallPhaseIndex(phase string) int {
	for i, value := range memcachedUnixInstallPhases {
		if value == phase {
			return i
		}
	}
	return -1
}

func NewMemcachedUnixInstallRecord(submission MemcachedUnixInstallSubmission) (MemcachedUnixInstallRecord, error) {
	raw, err := json.Marshal(submission)
	if err != nil {
		return MemcachedUnixInstallRecord{}, errMemcachedUnixInstallRecord
	}
	in, err := DecodeMemcachedUnixInstallSubmission(raw)
	if err != nil {
		return MemcachedUnixInstallRecord{}, errMemcachedUnixInstallRecord
	}
	out := MemcachedUnixInstallRecord{Format: 1, Operation: in.Operation, Binding: in.Binding,
		SubmissionSHA256: Hash(string(raw)), CatalogSHA256: Hash(string(in.Envelope.Catalog)), Phase: "prepared"}
	if ValidateMemcachedUnixInstallRecord(out) != nil {
		return MemcachedUnixInstallRecord{}, errMemcachedUnixInstallRecord
	}
	return out, nil
}

func ValidateMemcachedUnixInstallRecord(v MemcachedUnixInstallRecord) error {
	if v.Format != 1 || v.Sequence < 0 || v.Sequence >= MemcachedUnixInstallEvents ||
		v.Operation.Action != "create" || v.Operation.TemplateProfile != MemcachedUnixProfile ||
		ValidateDockerProject(v.Operation) != nil || v.Binding.Version != appcatalog.MemcachedUnixVersion ||
		!dockerRequestDigestPattern.MatchString(v.Binding.ManifestSHA256) ||
		!dockerRequestDigestPattern.MatchString(v.SubmissionSHA256) || !dockerRequestDigestPattern.MatchString(v.CatalogSHA256) ||
		v.UID > 0x7fffffff || v.GID > 0x7fffffff || (v.UID == 0) != (v.GID == 0) {
		return errMemcachedUnixInstallRecord
	}
	index := memcachedUnixInstallPhaseIndex(v.Phase)
	if index >= 0 {
		if v.Sequence != index || v.Fault != "" ||
			(index >= 2) != (v.UID != 0) || (index >= 4) != (v.ImageID != "") ||
			(index >= 5) != (v.ComposeSHA256 != "") || (index >= 8) != (v.ContainerID != "") {
			return errMemcachedUnixInstallRecord
		}
	} else {
		switch v.Phase {
		case "refused":
			if v.Sequence != 1 || v.UID != 0 || v.ImageID != "" || v.ComposeSHA256 != "" || v.ContainerID != "" {
				return errMemcachedUnixInstallRecord
			}
		case "needs-attention":
			// A failed intent carries only its previously observed identities.
			// The preceding immutable event is still needed to interpret it.
			if v.Sequence < 1 || v.Sequence > 9 {
				return errMemcachedUnixInstallRecord
			}
		default:
			return errMemcachedUnixInstallRecord
		}
		switch v.Fault {
		case "authority-unavailable", "account-unverified", "image-unverified", "project-unverified", "runtime-unverified", "interrupted":
		default:
			return errMemcachedUnixInstallRecord
		}
	}
	if v.ImageID != "" && (len(v.ImageID) != 71 || v.ImageID[:7] != "sha256:" || !dockerRequestDigestPattern.MatchString(v.ImageID[7:])) ||
		v.ComposeSHA256 != "" && !dockerRequestDigestPattern.MatchString(v.ComposeSHA256) ||
		v.ContainerID != "" && !dockerRequestDigestPattern.MatchString(v.ContainerID) ||
		v.ImageID != "" && v.UID == 0 || v.ComposeSHA256 != "" && v.ImageID == "" || v.ContainerID != "" && v.ComposeSHA256 == "" {
		return errMemcachedUnixInstallRecord
	}
	body, err := json.Marshal(v)
	if err != nil || len(body) > MaxMemcachedUnixInstallRecordBytes {
		return errMemcachedUnixInstallRecord
	}
	return nil
}

func DecodeMemcachedUnixInstallRecord(raw []byte) (MemcachedUnixInstallRecord, error) {
	var out MemcachedUnixInstallRecord
	if len(raw) == 0 || len(raw) > MaxMemcachedUnixInstallRecordBytes || json.Unmarshal(raw, &out) != nil {
		return MemcachedUnixInstallRecord{}, errMemcachedUnixInstallRecord
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) || ValidateMemcachedUnixInstallRecord(out) != nil {
		return MemcachedUnixInstallRecord{}, errMemcachedUnixInstallRecord
	}
	return out, nil
}

// A successful next event adds exactly its newly verified identity. An intent
// failure preserves all already observed identities; it does not synthesize a
// rollback, safe shutdown, account deletion or a committed store receipt.
func ValidateMemcachedUnixInstallTransition(before, after MemcachedUnixInstallRecord) error {
	if ValidateMemcachedUnixInstallRecord(before) != nil || ValidateMemcachedUnixInstallRecord(after) != nil ||
		before.Sequence+1 != after.Sequence || before.Operation != after.Operation || before.Binding != after.Binding ||
		before.SubmissionSHA256 != after.SubmissionSHA256 || before.CatalogSHA256 != after.CatalogSHA256 {
		return errMemcachedUnixInstallRecord
	}
	index := memcachedUnixInstallPhaseIndex(before.Phase)
	if index < 0 || before.Phase == "committed" {
		return errMemcachedUnixInstallRecord
	}
	previous := before
	previous.Sequence, previous.Phase, previous.Fault = after.Sequence, after.Phase, after.Fault
	if after.Phase == "refused" || after.Phase == "needs-attention" {
		if after.Phase == "refused" && before.Phase != "prepared" || previous != after {
			return errMemcachedUnixInstallRecord
		}
		return nil
	}
	if index+1 >= len(memcachedUnixInstallPhases) || after.Phase != memcachedUnixInstallPhases[index+1] {
		return errMemcachedUnixInstallRecord
	}
	switch after.Phase {
	case "account-verified":
		previous.UID, previous.GID = after.UID, after.GID
	case "image-verified":
		previous.ImageID = after.ImageID
	case "project-intent":
		previous.ComposeSHA256 = after.ComposeSHA256
	case "runtime-verified":
		previous.ContainerID = after.ContainerID
	}
	if previous != after {
		return errMemcachedUnixInstallRecord
	}
	return nil
}
