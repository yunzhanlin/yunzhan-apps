// Package diskjob defines closed, installation/actor/host-bound disk jobs.
// Queue acceptance is not proof of native execution or commercial acceptance.
package diskjob

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"

	"local/panel/internal/diskusage"
)

const HostAppVersion = "1.4.0" // Fixed host capability; never proof of an installed signed app.
const HostFeature = "disk-host-jobs-v1"
const ActiveJobsMax = 128

var ErrSelection = errors.New("全盘任务的宿主视图、范围或安装身份无效")
var identifier = regexp.MustCompile(`^[a-f0-9]{32}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var boot = regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)

type Host struct {
	BootID      string `json:"boot_id"`
	NamespaceID string `json:"mount_namespace_id"`
}

type Inventory struct {
	Host   Host                `json:"host"`
	Mounts diskusage.Inventory `json:"inventory"`
}

type Selection struct {
	BootID         string `json:"boot_id"`
	NamespaceID    string `json:"mount_namespace_id"`
	MountID        string `json:"mount_id"`
	MountSHA       string `json:"mount_binding_sha256"`
	Directory      string `json:"relative_directory"`
	AppVersion     string `json:"app_version"`
	InstallationID string `json:"installation_id"`
	AppSHA         string `json:"app_manifest_sha256"`
}

// Actor is added by Core from its current authenticated full administrator.
// It must never be decoded from the public Selection object or expanded by
// a menu grant. Current authority is checked again at dispatch and worker use.
type Request struct {
	Format         int       `json:"format"`
	JobID          string    `json:"job_id"`
	ActorID        string    `json:"actor_id"`
	AccessRevision string    `json:"access_revision"`
	Selection      Selection `json:"selection"`
}

func ValidID(id string) bool   { return identifier.MatchString(id) }
func ValidSHA(sha string) bool { return digest.MatchString(sha) }
func CanonicalInteger(value string, nonzero bool) bool {
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && (!nonzero || n > 0) && strconv.FormatUint(n, 10) == value
}

func ValidateHost(h Host) error {
	d, inode, ok := strings.Cut(h.NamespaceID, ":")
	if !boot.MatchString(h.BootID) || !ok || !CanonicalInteger(d, false) || !CanonicalInteger(inode, true) {
		return ErrSelection
	}
	return nil
}

func RelativeDirectory(value string) bool {
	if value == "" {
		return true
	}
	return !strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "." && value != ".." && diskusage.ValidHostPath("/"+value)
}

func ValidateSelection(in Selection) error {
	if ValidateHost(Host{in.BootID, in.NamespaceID}) != nil || !CanonicalInteger(in.MountID, true) || !ValidSHA(in.MountSHA) || !RelativeDirectory(in.Directory) || in.AppVersion != HostAppVersion || !ValidID(in.InstallationID) || !ValidSHA(in.AppSHA) {
		return ErrSelection
	}
	return nil
}

func ValidateRequest(in Request) error {
	if in.Format != 1 || !ValidID(in.JobID) || !ValidID(in.ActorID) || !CanonicalInteger(in.AccessRevision, true) || ValidateSelection(in.Selection) != nil {
		return ErrSelection
	}
	return nil
}

// All selection fields are exact strings, including the empty root directory.
// Reject Go JSON's case-insensitive aliases, duplicates, nulls and trailing data.
func DecodeSelection(raw []byte) (Selection, error) {
	var in Selection
	if len(raw) < 2 || len(raw) > 8192 {
		return in, ErrSelection
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if first, err := d.Token(); err != nil || first != json.Delim('{') {
		return in, ErrSelection
	}
	allowed := map[string]bool{"boot_id": true, "mount_namespace_id": true, "mount_id": true, "mount_binding_sha256": true, "relative_directory": true, "app_version": true, "installation_id": true, "app_manifest_sha256": true}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return in, ErrSelection
		}
		seen[name] = true
		value, err := d.Token()
		if _, ok := value.(string); err != nil || !ok {
			return in, ErrSelection
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') || len(seen) != len(allowed) {
		return in, ErrSelection
	}
	if _, err := d.Token(); err != io.EOF || json.Unmarshal(raw, &in) != nil {
		return in, ErrSelection
	}
	return in, ValidateSelection(in)
}

func DecodeRequest(raw []byte) (Request, error) {
	var in Request
	if len(raw) < 2 || len(raw) > 12288 {
		return in, ErrSelection
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if first, err := d.Token(); err != nil || first != json.Delim('{') {
		return in, ErrSelection
	}
	allowed := map[string]bool{"format": true, "job_id": true, "actor_id": true, "access_revision": true, "selection": true}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return in, ErrSelection
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return in, ErrSelection
		}
		if name == "selection" {
			if _, err := DecodeSelection(value); err != nil {
				return in, err
			}
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') || len(seen) != len(allowed) {
		return in, ErrSelection
	}
	if _, err := d.Token(); err != io.EOF || json.Unmarshal(raw, &in) != nil {
		return in, ErrSelection
	}
	return in, ValidateRequest(in)
}
