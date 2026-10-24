//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

const memcachedUnixProjectMarker = "memcached-unix-install.json"

// Independent socket-only metadata decoder. Do NOT relax compat2's required
// published port/closed seven-field template in decodeComposeUpdateMetadata.
func decodeMemcachedUnixMetadata(raw []byte, id string) (composeMetadata, error) {
	var m composeMetadata
	if len(raw) == 0 || len(raw) > 16<<10 || json.Unmarshal(raw, &m) != nil {
		return m, errMemcachedUnixJournal
	}
	canonical, err := json.Marshal(m)
	if err != nil || !bytes.Equal(raw, canonical) || !core.ValidID(id) || m.ID != id || m.Engine != "panel_"+id[:12] || m.TemplateID != "memcached-cache" || m.HostPort != 0 || m.Services != 1 || !dockerResourceNamePattern.MatchString(m.Name) {
		return composeMetadata{}, errMemcachedUnixJournal
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return composeMetadata{}, errMemcachedUnixJournal
	}
	return m, nil
}

func memcachedUnixProjectLeafLimit(name string) int64 {
	switch name {
	case "compose.yaml":
		return 48 << 10
	case "metadata.json":
		return 16 << 10
	case memcachedUnixProjectMarker:
		return core.MaxMemcachedUnixInstallRecordBytes
	}
	return 0
}

func readMemcachedUnixProjectMarker(d *composeUpdateDirectory) ([]byte, error) {
	if d == nil || !d.current() {
		return nil, errMemcachedUnixJournal
	}
	raw, info, err := geoStoreReadIdentity(d.root, memcachedUnixProjectMarker, core.MaxMemcachedUnixInstallRecordBytes)
	if err != nil || !memcachedUnixJournalFileInfo(info, core.MaxMemcachedUnixInstallRecordBytes, false) || !d.current() {
		return nil, errMemcachedUnixJournal
	}
	return raw, nil
}

func memcachedUnixProjectWrite(d *composeUpdateDirectory, name string, raw []byte) error {
	limit := memcachedUnixProjectLeafLimit(name)
	if d == nil || !d.current() || limit == 0 || len(raw) == 0 || int64(len(raw)) > limit {
		return errMemcachedUnixJournal
	}
	file, err := d.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if file.Chown(0, 0) != nil || file.Chmod(0600) != nil {
		return errMemcachedUnixJournal
	}
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		return errMemcachedUnixJournal
	}
	if file.Sync() != nil || ruleFeedStoreSync(d.root) != nil || !d.current() {
		return errMemcachedUnixJournal
	}
	opened, e1 := file.Stat()
	visible, e2 := d.root.Lstat(name)
	if e1 != nil || e2 != nil || !memcachedUnixJournalFileInfo(opened, limit, false) || !geoStoreStableInfo(opened, visible) {
		return errMemcachedUnixJournal
	}
	return nil
}

// Caller holds independently verified original run + global engine leases.
// Never rename over/adopt an existing project, repair ownership, or remove a
// partial directory. Marker FIRST: even a partial attempt cannot subsequently
// enter an unbound legacy Compose start/recovery/delete path.
func createMemcachedUnixProjectAt(base string, head core.MemcachedUnixInstallRecord) (*composeUpdateDirectory, error) {
	if core.ValidateMemcachedUnixInstallRecord(head) != nil || head.Phase != "project-intent" {
		return nil, errMemcachedUnixJournal
	}
	compose, err := core.MemcachedUnixRuntimeCompose(head.Operation.ProjectID, head.Operation.SiteID, head.UID, head.GID)
	if err != nil || core.Hash(compose) != head.ComposeSHA256 {
		return nil, errMemcachedUnixJournal
	}
	anchor, err := memcachedUnixBaseAt(base, 0700)
	if err != nil {
		return nil, err
	}
	defer anchor.Close()
	directory, err := anchor.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := directory.ReadDir(4097)
	directory.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 4096 {
		return nil, errMemcachedUnixJournal
	}
	for _, entry := range entries {
		// No abbreviated engine-name collision, including stopped projects.
		if core.ValidID(entry.Name()) && entry.Name()[:12] == head.Operation.ProjectID[:12] {
			return nil, errMemcachedUnixJournal
		}
	}
	if err := anchor.Mkdir(head.Operation.ProjectID, 0700); err != nil {
		return nil, err
	}
	child, err := anchor.OpenRoot(head.Operation.ProjectID)
	if err != nil {
		return nil, err
	}
	file, err := child.Open(".")
	if err != nil {
		child.Close()
		return nil, err
	}
	err = file.Chown(0, 0)
	if err == nil {
		err = file.Chmod(0700)
	}
	if err == nil {
		err = file.Sync()
	}
	file.Close()
	child.Close()
	if err != nil || ruleFeedStoreSync(anchor) != nil {
		return nil, errMemcachedUnixJournal
	}
	d, err := openComposeUpdateDirectory(base, head.Operation.ProjectID)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*composeUpdateDirectory, error) { d.Close(); return nil, e }
	marker := head
	marker.Sequence, marker.Phase = 6, "project-written"
	raw, err := coreEncodeMemcachedUnixInstallRecord(marker)
	if err != nil {
		return fail(err)
	}
	if err = memcachedUnixProjectWrite(d, memcachedUnixProjectMarker, raw); err != nil {
		return fail(err)
	}
	metadata := composeMetadata{ID: head.Operation.ProjectID, Name: head.Operation.Name, Engine: "panel_" + head.Operation.ProjectID[:12], TemplateID: "memcached-cache", Services: 1, CreatedAt: core.Now()}
	meta, err := json.Marshal(metadata)
	if err != nil {
		return fail(err)
	}
	if err = memcachedUnixProjectWrite(d, "metadata.json", meta); err != nil {
		return fail(err)
	}
	if err = memcachedUnixProjectWrite(d, "compose.yaml", []byte(compose)); err != nil {
		return fail(err)
	}
	return d, nil
}

func readMemcachedUnixProject(d *composeUpdateDirectory, head core.MemcachedUnixInstallRecord) (composeMetadata, error) {
	var empty composeMetadata
	if d == nil || !d.current() || core.ValidateMemcachedUnixInstallRecord(head) != nil || head.ComposeSHA256 == "" {
		return empty, errMemcachedUnixJournal
	}
	dir, err := d.root.Open(".")
	if err != nil {
		return empty, err
	}
	entries, err := dir.ReadDir(4)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) != 3 {
		return empty, errMemcachedUnixJournal
	}
	for _, entry := range entries {
		limit := memcachedUnixProjectLeafLimit(entry.Name())
		info, err := d.root.Lstat(entry.Name())
		if limit == 0 || err != nil || !memcachedUnixJournalFileInfo(info, limit, false) {
			return empty, errMemcachedUnixJournal
		}
	}
	marker, err := readMemcachedUnixProjectMarker(d)
	if err != nil {
		return empty, err
	}
	actual, err := core.DecodeMemcachedUnixInstallRecord(marker)
	expected := head
	expected.Sequence, expected.Phase, expected.ContainerID, expected.Fault = 6, "project-written", "", ""
	if err != nil || actual != expected {
		return empty, errMemcachedUnixJournal
	}
	compose, _, err := d.read("compose.yaml", 48<<10)
	want, templateErr := core.MemcachedUnixRuntimeCompose(head.Operation.ProjectID, head.Operation.SiteID, head.UID, head.GID)
	if err != nil || templateErr != nil || !bytes.Equal(compose, []byte(want)) || core.Hash(string(compose)) != head.ComposeSHA256 {
		return empty, errMemcachedUnixJournal
	}
	meta, _, err := d.read("metadata.json", 16<<10)
	if err != nil {
		return empty, err
	}
	m, err := decodeMemcachedUnixMetadata(meta, head.Operation.ProjectID)
	if err != nil || m.Name != head.Operation.Name || m.Engine != "panel_"+m.ID[:12] || m.TemplateID != "memcached-cache" || m.HostPort != 0 || m.Services != 1 || !d.current() {
		return empty, errMemcachedUnixJournal
	}
	return m, nil
}

func memcachedUnixEmptyEngine(ctx context.Context, project string, read composeUpdateDockerRead) error {
	if ctx == nil || ctx.Err() != nil || !core.ValidID(project) || read == nil {
		return errMemcachedUnixJournal
	}
	filters, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=panel_" + project[:12]}})
	query := "filters=" + url.QueryEscape(string(filters))
	var containers, networks []json.RawMessage
	var volumes struct{ Volumes []json.RawMessage }
	if read(ctx, "/containers/json?all=1&"+query, &containers) != nil || len(containers) != 0 || read(ctx, "/networks?"+query, &networks) != nil || len(networks) != 0 || read(ctx, "/volumes?"+query, &volumes) != nil || len(volumes.Volumes) != 0 || ctx.Err() != nil {
		return errMemcachedUnixJournal
	}
	return nil
}

func memcachedUnixRejectLegacyProject(dir string) error {
	_, err := os.Lstat(filepath.Join(dir, memcachedUnixProjectMarker))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errMemcachedUnixJournal
}
