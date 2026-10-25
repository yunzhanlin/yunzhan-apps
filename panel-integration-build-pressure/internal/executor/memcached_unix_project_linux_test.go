//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func memcachedUnixProjectFixture(t *testing.T) (string, core.MemcachedUnixInstallRecord) {
	t.Helper()
	store, _, head := memcachedUnixJournalFixture(t)
	head.Sequence, head.Phase, head.UID, head.GID = 5, "project-intent", 65534, 65534
	head.ImageID = "sha256:" + strings.Repeat("d", 64)
	compose, err := core.MemcachedUnixRuntimeCompose(head.Operation.ProjectID, head.Operation.SiteID, head.UID, head.GID)
	if err != nil {
		t.Fatal(err)
	}
	head.ComposeSHA256 = core.Hash(compose)
	if core.ValidateMemcachedUnixInstallRecord(head) != nil {
		t.Fatal("fixture framing")
	}
	return filepath.Join(filepath.Dir(store.base), "projects"), head
}

func TestMemcachedUnixProjectExclusiveMarkerSourceAndNoLegacyMetadataWidening(t *testing.T) {
	base, head := memcachedUnixProjectFixture(t)
	d, err := createMemcachedUnixProjectAt(base, head)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, _, err := d.read(memcachedUnixProjectMarker, core.MaxMemcachedUnixInstallRecordBytes); err == nil {
		t.Fatal("new marker widened the old two-leaf/48KiB reader")
	}
	metadata, err := readMemcachedUnixProject(d, head)
	if err != nil || metadata.HostPort != 0 || metadata.Services != 1 {
		t.Fatal("own exact private project", err)
	}
	raw, _, err := d.read("metadata.json", 16<<10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeComposeUpdateMetadata(raw, metadata.ID); err == nil {
		t.Fatal("new metadata widened legacy TCP decoder")
	}
	if memcachedUnixRejectLegacyProject(filepath.Join(base, head.Operation.ProjectID)) == nil {
		t.Fatal("new marker entered generic start/recovery/delete")
	}
	if _, err := createMemcachedUnixProjectAt(base, head); err == nil {
		t.Fatal("existing project adopted/overwritten")
	}
	committed := head
	committed.Sequence, committed.Phase, committed.ContainerID = 9, "committed", strings.Repeat("f", 64)
	if _, err := readMemcachedUnixProject(d, committed); err != nil {
		t.Fatal("original marker lost after later commit", err)
	}
	bad := head
	bad.Operation.Name = "foreign"
	if _, err := readMemcachedUnixProject(d, bad); err == nil {
		t.Fatal("different original identity borrowed project")
	}
}

func TestMemcachedUnixProjectRetainsMarkerAndRejectsForeignFilesSourceAndAliases(t *testing.T) {
	for _, change := range []string{"foreign-file", "public-config", "source-drift", "alias-metadata", "foreign-marker", "same-engine-prefix"} {
		t.Run(change, func(t *testing.T) {
			base, head := memcachedUnixProjectFixture(t)
			if change == "same-engine-prefix" {
				anchor, err := memcachedUnixBaseAt(base, 0700)
				if err != nil {
					t.Fatal(err)
				}
				if err := anchor.Mkdir(head.Operation.ProjectID[:12]+strings.Repeat("e", 20), 0700); err != nil {
					t.Fatal(err)
				}
				anchor.Close()
				if _, err := createMemcachedUnixProjectAt(base, head); err == nil {
					t.Fatal("abbreviated engine namespace collision adopted")
				}
				return
			}
			d, err := createMemcachedUnixProjectAt(base, head)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			root := filepath.Join(base, head.Operation.ProjectID)
			before, err := os.ReadFile(filepath.Join(root, memcachedUnixProjectMarker))
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "foreign-file":
				err = os.WriteFile(filepath.Join(root, "foreign"), []byte("retain"), 0600)
			case "public-config":
				err = os.Chmod(filepath.Join(root, "compose.yaml"), 0644)
			case "source-drift":
				err = os.WriteFile(filepath.Join(root, "compose.yaml"), []byte("foreign"), 0600)
			case "alias-metadata":
				raw, e := os.ReadFile(filepath.Join(root, "metadata.json"))
				if e != nil {
					t.Fatal(e)
				}
				err = os.WriteFile(filepath.Join(root, "metadata.json"), bytes.Replace(raw, []byte(`"id"`), []byte(`"ID"`), 1), 0600)
			case "foreign-marker":
				row := head
				row.Sequence, row.Phase = 6, "project-written"
				row.Binding.ManifestSHA256 = strings.Repeat("e", 64)
				raw, _ := json.Marshal(row)
				err = os.WriteFile(filepath.Join(root, memcachedUnixProjectMarker), raw, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := readMemcachedUnixProject(d, head); err == nil {
				t.Fatal("foreign/partial project trusted", change)
			}
			if memcachedUnixRejectLegacyProject(root) == nil {
				t.Fatal("unsafe/partial project became legacy controllable")
			}
			if change != "foreign-marker" {
				after, e := os.ReadFile(filepath.Join(root, memcachedUnixProjectMarker))
				if e != nil || !bytes.Equal(before, after) {
					t.Fatal("read refusal rewrote original marker")
				}
			}
		})
	}
}

func TestMemcachedUnixEmptyEngineChecksAllLabelNamespacesAndClosedInputs(t *testing.T) {
	for _, kind := range []string{"empty", "container", "network", "volume", "unreadable"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			err := memcachedUnixEmptyEngine(context.Background(), strings.Repeat("a", 32), func(_ context.Context, path string, out any) error {
				calls++
				body := "[]"
				if strings.HasPrefix(path, "/volumes?") {
					body = `{"Volumes":[]}`
				}
				if kind == "container" && strings.HasPrefix(path, "/containers/") || kind == "network" && strings.HasPrefix(path, "/networks?") {
					body = `[{"Id":"foreign"}]`
				}
				if kind == "volume" && strings.HasPrefix(path, "/volumes?") {
					body = `{"Volumes":[{"Name":"foreign"}]}`
				}
				if kind == "unreadable" {
					return os.ErrPermission
				}
				return json.Unmarshal([]byte(body), out)
			})
			if (err == nil) != (kind == "empty") || kind == "empty" && calls != 3 {
				t.Fatal(kind, err, calls)
			}
		})
	}
	if memcachedUnixEmptyEngine(nil, strings.Repeat("a", 32), nil) == nil {
		t.Fatal("nil native authority accepted")
	}
}
