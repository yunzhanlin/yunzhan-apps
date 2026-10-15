//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// Root-private filesystem fixtures only, not provider/installed-panel proof.
func geoArchiveRootFixture(t *testing.T) (statisticsGeoJobArchiveStore, string, core.StatisticsGeoArchiveInput, map[string][]byte) {
	t.Helper()
	f := geoStoreRootFixture(t)
	parent := filepath.Dir(f.store.base)
	store := statisticsGeoJobArchiveStore{active: filepath.Join(parent, "job-active"), archive: filepath.Join(parent, "job-archive")}
	if err := os.Mkdir(store.active, 0700); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	dir := filepath.Join(store.active, id)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	selection := core.StatisticsGeoSelection{Action: "rollback", AppVersion: "2.6.0", AppManifestSHA: strings.Repeat("b", 64), InstallationID: strings.Repeat("c", 32), Release: "2026-10", DataManifestSHA: strings.Repeat("d", 64)}
	request := statisticsGeoRequest{Format: 1, JobID: id, Selection: selection, EnvelopeSHA: core.Hash("{}")}
	raw, _ := json.Marshal(request)
	result, _ := json.Marshal(core.StatisticsGeoOperation{JobID: id, Selection: selection, State: "succeeded", Steps: []core.Step{{Time: core.Now(), Message: "synthetic terminal fixture"}}})
	files := map[string][]byte{"request.json": raw, "envelope.json": []byte("{}"), "started.json": raw, "result.json": result, "install.lock": {}}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := store.inventory()
	if err != nil || len(inv.Entries) != 1 {
		t.Fatal(inv, err)
	}
	in := core.StatisticsGeoArchiveInput{JobID: id, SHA: inv.Entries[0].SHA, Confirm: "ARCHIVE GEODATA JOB " + id}
	return store, id, in, files
}
func TestStatisticsGeoJobArchivePreservesInodesBytesAndOriginalRead(t *testing.T) {
	store, id, in, files := geoArchiveRootFixture(t)
	before := map[string]os.FileInfo{}
	for name := range files {
		info, err := os.Lstat(filepath.Join(store.active, id, name))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = info
	}
	out, err := store.archiveJob(context.Background(), in)
	if err != nil || out.Replayed || !out.Record.Archived || out.Record.SHA != in.SHA {
		t.Fatal(out, err)
	}
	if _, err = os.Lstat(filepath.Join(store.active, id)); !os.IsNotExist(err) {
		t.Fatal("active evidence not moved", err)
	}
	for name, want := range files {
		path := filepath.Join(store.archive, id, name)
		got, err := os.ReadFile(path)
		after, e := os.Lstat(path)
		if err != nil || e != nil || !bytes.Equal(got, want) || !os.SameFile(before[name], after) || !geoStoreStableInfo(before[name], after) {
			t.Fatal("original file changed", name, err, e)
		}
	}
	replay, err := store.archiveJob(context.Background(), in)
	if err != nil || !replay.Replayed || replay.Record != out.Record {
		t.Fatal("lost reply changed original", replay, err)
	}
	request, envelope, base, root, err := readStatisticsGeoJobAt(store, id)
	if err != nil || request.JobID != id || string(envelope) != "{}" {
		t.Fatal("archived original status no longer readable", err)
	}
	root.Close()
	base.Close()
	inv, err := store.inventory()
	if err != nil || len(inv.Entries) != 1 || inv.Entries[0] != out.Record {
		t.Fatal(inv, err)
	}
}
func TestStatisticsGeoJobArchiveRejectsPartialChangedLockedOrForeign(t *testing.T) {
	for _, mode := range []string{"pending", "changed", "locked", "hardlink", "symlink", "foreign", "unknown", "duplicate", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			store, id, in, files := geoArchiveRootFixture(t)
			dir := filepath.Join(store.active, id)
			ctx := context.Background()
			var lock *os.File
			switch mode {
			case "pending":
				if err := os.Remove(filepath.Join(dir, "result.json")); err != nil {
					t.Fatal(err)
				}
			case "changed":
				if err := os.WriteFile(filepath.Join(dir, "result.json"), append(files["result.json"], ' '), 0600); err != nil {
					t.Fatal(err)
				}
			case "locked":
				var err error
				lock, err = os.OpenFile(filepath.Join(dir, "install.lock"), os.O_RDONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				if err = unix.Flock(int(lock.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(dir, "envelope.json"), filepath.Join(filepath.Dir(store.active), "extra-link")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(filepath.Join(dir, "envelope.json")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("request.json", filepath.Join(dir, "envelope.json")); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				if err := os.Chown(filepath.Join(dir, "result.json"), 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(filepath.Join(dir, "unexpected.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				if err := os.Mkdir(store.archive, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(store.archive, id), 0700); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := store.archiveJob(ctx, in); err == nil {
				t.Fatal("unsafe task archived", mode)
			}
			if _, err := os.Lstat(dir); err != nil {
				t.Fatal("original directory lost", err)
			}
		})
	}
}
func TestStatisticsGeoJobArchiveDoesNotRelaxProgramUpgradeReceipts(t *testing.T) {
	store, id, in, _ := geoArchiveRootFixture(t)
	if _, err := store.archiveJob(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(filepath.Join(store.archive, id))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	r := &programQueueReader{ctx: context.Background(), root: "/"}
	// The same closed receipt validator covers the new archive tree. A retained
	// terminal cannot bypass the original worker/envelope validation on upgrade.
	relative := strings.TrimPrefix(filepath.Join(store.archive, id), "/")
	if err = r.statisticsGeoJob(relative, id, root); err != nil {
		t.Fatal(err)
	}
	if len(r.snapshots) == 0 {
		t.Fatal("archive omitted from upgrade snapshots")
	}
	before := append([]programQueueSnapshot(nil), r.snapshots...)
	if err = os.WriteFile(filepath.Join(store.archive, id, "result.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = r.statisticsGeoJob(relative, id, root); err == nil {
		t.Fatal("corrupt archive accepted for upgrade")
	}
	if reflect.DeepEqual(before, r.snapshots) {
		t.Log("prior immutable snapshot evidence retained")
	}
}
func TestStatisticsGeoJobArchiveLostAcknowledgementAndFileIdentity(t *testing.T) {
	for _, point := range []string{"before-rename", "after-rename", "after-sync", "same-bytes-replacement"} {
		t.Run(point, func(t *testing.T) {
			store, id, in, files := geoArchiveRootFixture(t)
			store.fault = func(at string) error {
				if point == "same-bytes-replacement" && at == "before-rename" {
					path := filepath.Join(store.active, id, "result.json")
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, files["result.json"], 0600); err != nil {
						t.Fatal(err)
					}
					return nil
				}
				if at == point {
					return errors.New("synthetic acknowledgement fault")
				}
				return nil
			}
			if _, err := store.archiveJob(context.Background(), in); err == nil {
				t.Fatal("injected interruption/identity replacement accepted")
			}
			moved := point == "after-rename" || point == "after-sync"
			_, activeErr := os.Lstat(filepath.Join(store.active, id))
			if moved != os.IsNotExist(activeErr) {
				t.Fatal("wrong interruption location", point, activeErr)
			}
			store.fault = nil
			out, err := store.archiveJob(context.Background(), in)
			if err != nil || out.Replayed != moved || out.Record.SHA != in.SHA {
				t.Fatal("original recovery mismatch", out, err)
			}
		})
	}
}
func TestStatisticsGeoJobArchiveCapacityNeverDeletesOldEvidence(t *testing.T) {
	store, id, in, files := geoArchiveRootFixture(t)
	if err := os.Mkdir(store.archive, 0700); err != nil {
		t.Fatal(err)
	}
	var template statisticsGeoRequest
	_ = json.Unmarshal(files["request.json"], &template)
	for i := 0; i < 512; i++ {
		key := fmt.Sprintf("%032x", i+1)
		dir := filepath.Join(store.archive, key)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		request := template
		request.JobID = key
		requestRaw, _ := json.Marshal(request)
		resultRaw, _ := json.Marshal(core.StatisticsGeoOperation{JobID: key, Selection: request.Selection, State: "failed", Error: "synthetic capacity fixture", Steps: []core.Step{}})
		for name, raw := range map[string][]byte{"request.json": requestRaw, "envelope.json": files["envelope.json"], "started.json": requestRaw, "result.json": resultRaw, "install.lock": {}} {
			if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	inv, err := store.inventory()
	if err != nil || len(inv.Entries) != 513 {
		t.Fatal("full private inventory", len(inv.Entries), err)
	}
	if _, err = store.archiveJob(context.Background(), in); err == nil {
		t.Fatal("archive capacity bypassed")
	}
	if _, err = os.Lstat(filepath.Join(store.active, id)); err != nil {
		t.Fatal("full archive deleted active evidence", err)
	}
	if after, err := store.inventory(); err != nil || !reflect.DeepEqual(inv, after) {
		t.Fatal("capacity refusal changed prior evidence", err)
	}
}
