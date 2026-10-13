//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"local/panel/internal/core"
	"local/panel/internal/geodata"
)

// Synthetic signed months under trusted/root-private /var. These tests are
// transaction/permission evidence, not real provider or installed UI proof.
func geoRetentionFixture(t *testing.T) (*geoStoreFixture, string, string, string) {
	t.Helper()
	f := geoStoreRootFixture(t)
	old := f.install(t, "2026-08")
	previous := f.install(t, "2026-09")
	current := f.install(t, "2026-10")
	return f, geoStoreName(old), geoStoreName(previous), geoStoreName(current)
}
func geoRetentionSelector(t *testing.T, f *geoStoreFixture) ([]byte, os.FileInfo) {
	t.Helper()
	path := filepath.Join(f.store.base, "selected.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw, info
}
func geoRetentionRows(t *testing.T, f *geoStoreFixture) []core.StatisticsGeoStored {
	t.Helper()
	root, err := f.store.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	selected, _, _, err := f.store.selector(root.Root)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.store.storedRows(root, selected)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}
func geoRetentionWriteFixture(t *testing.T, f *geoStoreFixture, base, month string) string {
	t.Helper()
	in := f.envelope(t, month)
	a, err := f.store.trust.VerifyGeoDataEnvelope(in, "2.6.0", f.sha, f.store.now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	name := geoStoreName(a)
	dir := filepath.Join(base, name)
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(in)
	for leaf, data := range map[string][]byte{"envelope.json": raw, "database.mmdb.gz": f.payloads[a.Data().Manifest().Source], "NOTICE.txt": statisticsGeoNotice(a)} {
		if err = os.WriteFile(filepath.Join(dir, leaf), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return name
}
func TestStatisticsGeoRetentionProtectsCurrentPreviousAndHighWater(t *testing.T) {
	f, old, previous, current := geoRetentionFixture(t)
	before, identity := geoRetentionSelector(t, f)
	downloads := f.downloads
	for _, name := range []string{previous, current} {
		if err := f.store.maintain(context.Background(), "archive", name); err == nil {
			t.Fatal("protected original archived", name)
		}
	}
	archivePath := f.store.archiveStore().base
	if _, err := os.Lstat(archivePath); !os.IsNotExist(err) {
		t.Fatal("refusal created archive", err)
	}
	root, err := f.store.open(false)
	if err != nil {
		t.Fatal(err)
	}
	original, err := geoDatasetFiles(root.Root, old)
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.maintain(context.Background(), "archive", old); err != nil {
		t.Fatal(err)
	}
	rows := geoRetentionRows(t, f)
	if len(rows) != 3 || !rows[0].Archived || !rows[1].Previous || !rows[2].Selected || !rows[2].HighWater {
		t.Fatal("protected inventory", rows)
	}
	archive, _, err := f.store.archivedInventory()
	if err != nil {
		t.Fatal(err)
	}
	moved, err := geoDatasetFiles(archive.Root, old)
	archive.Close()
	if err != nil || !geoDatasetSameFiles(original, moved) {
		t.Fatal("archive changed bytes/inodes/timestamps", err)
	}
	if err = f.store.maintain(context.Background(), "archive", old); err != nil {
		t.Fatal("same archive identity cannot reconcile", err)
	}
	if err = f.store.maintain(context.Background(), "restore", old); err != nil {
		t.Fatal(err)
	}
	after, afterIdentity := geoRetentionSelector(t, f)
	if !bytes.Equal(before, after) || !geoStoreStableInfo(identity, afterIdentity) || f.downloads != downloads {
		t.Fatal("maintenance selected data, downloaded or changed selector identity")
	}
	if err = f.store.maintain(context.Background(), "restore", old); err != nil {
		t.Fatal("same restore identity cannot reconcile", err)
	}
	rolled, err := f.store.rollback(context.Background(), old)
	if err != nil {
		t.Fatal(err)
	}
	defer rolled.Close()
	rows = geoRetentionRows(t, f)
	if !rows[0].Selected || !rows[2].HighWater || !rows[2].Previous {
		t.Fatal("rollback lost latest signed anchor", rows)
	}
	if err = f.store.maintain(context.Background(), "archive", current); err == nil {
		t.Fatal("high-water anchor archived after rollback")
	}
	if _, s, err := f.store.install(context.Background(), f.envelope(t, "2026-09"), f.sha); err == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("maintenance/rollback lowered install high-water mark")
	}
}
func TestStatisticsGeoRetentionRejectsCorruptForeignAliasesAndChangedIdentity(t *testing.T) {
	for _, mode := range []string{"corrupt-gzip", "hardlink", "symlink", "foreign", "unknown", "collision", "same-bytes-replacement", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f, old, _, _ := geoRetentionFixture(t)
			selector, _ := geoRetentionSelector(t, f)
			dir := filepath.Join(f.store.base, old)
			ctx := context.Background()
			switch mode {
			case "corrupt-gzip":
				path := filepath.Join(dir, "database.mmdb.gz")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)/2] ^= 1
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(dir, "database.mmdb.gz"), filepath.Join(filepath.Dir(f.store.base), "extra")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				path := filepath.Join(dir, "NOTICE.txt")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("envelope.json", path); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				if err := os.Chown(filepath.Join(dir, "NOTICE.txt"), 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(filepath.Join(dir, "extra.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "collision":
				base := f.store.archiveStore().base
				if err := os.Mkdir(base, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(base, old), 0700); err != nil {
					t.Fatal(err)
				}
			case "same-bytes-replacement":
				f.store.fault = func(point string) error {
					if point == "dataset-before-rename" {
						path := filepath.Join(dir, "NOTICE.txt")
						data, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						if err = os.Remove(path); err != nil {
							t.Fatal(err)
						}
						if err = os.WriteFile(path, data, 0600); err != nil {
							t.Fatal(err)
						}
					}
					return nil
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := f.store.maintain(ctx, "archive", old); err == nil {
				t.Fatal("unsafe old dataset archived", mode)
			}
			if _, err := os.Lstat(dir); err != nil {
				t.Fatal("refusal lost original", err)
			}
			after, _ := geoRetentionSelector(t, f)
			if !bytes.Equal(selector, after) {
				t.Fatal("refusal changed selection")
			}
		})
	}
}
func TestStatisticsGeoRetentionLostAcknowledgementReconcilesOriginalCopy(t *testing.T) {
	for _, action := range []string{"archive", "restore"} {
		for _, point := range []string{"dataset-before-rename", "dataset-after-rename", "dataset-after-sync"} {
			t.Run(action+"/"+point, func(t *testing.T) {
				f, old, _, _ := geoRetentionFixture(t)
				if action == "restore" {
					if err := f.store.maintain(context.Background(), "archive", old); err != nil {
						t.Fatal(err)
					}
				}
				selector, identity := geoRetentionSelector(t, f)
				f.store.fault = func(at string) error {
					if at == point {
						return errors.New("synthetic acknowledgement loss")
					}
					return nil
				}
				if err := f.store.maintain(context.Background(), action, old); err == nil {
					t.Fatal("lost acknowledgement claimed success")
				}
				f.store.fault = nil
				if err := f.store.maintain(context.Background(), action, old); err != nil {
					t.Fatal("original copy reconciliation", err)
				}
				after, afterIdentity := geoRetentionSelector(t, f)
				if !bytes.Equal(selector, after) || !geoStoreStableInfo(identity, afterIdentity) {
					t.Fatal("reconciliation switched data")
				}
				rows := geoRetentionRows(t, f)
				if rows[0].Archived != (action == "archive") {
					t.Fatal("wrong final location", rows[0])
				}
			})
		}
	}
}
func TestStatisticsGeoRetentionActiveEightAndArchiveTwentyFourAreHardLogicalBounds(t *testing.T) {
	f, old, _, _ := geoRetentionFixture(t)
	for _, month := range []string{"2026-03", "2026-04", "2026-05", "2026-06", "2026-07"} {
		geoRetentionWriteFixture(t, f, f.store.base, month)
	}
	if len(geoRetentionRows(t, f)) != 8 {
		t.Fatal("active fixture size")
	}
	if err := f.store.maintain(context.Background(), "archive", old); err != nil {
		t.Fatal(err)
	}
	geoRetentionWriteFixture(t, f, f.store.base, "2026-02")
	before := geoRetentionRows(t, f)
	if err := f.store.maintain(context.Background(), "restore", old); err == nil {
		t.Fatal("active8 capacity bypassed")
	}
	if !reflect.DeepEqual(before, geoRetentionRows(t, f)) {
		t.Fatal("capacity refusal modified inventory")
	}
	archiveStore := f.store.archiveStore()
	for i := 0; i < 23; i++ {
		geoRetentionWriteFixture(t, f, archiveStore.base, fmt.Sprintf("%04d-%02d", 2024+i/12, 1+i%12))
	}
	before = geoRetentionRows(t, f)
	if len(before) != 32 {
		t.Fatal("archive24 fixture size", len(before))
	}
	var eligible core.StatisticsGeoStored
	for _, row := range before {
		if !row.Archived && !row.Selected && !row.Previous && !row.HighWater {
			eligible = row
			break
		}
	}
	name := geodata.Channel + "-" + eligible.Release + "-" + eligible.ManifestSHA
	if err := f.store.maintain(context.Background(), "archive", name); err == nil {
		t.Fatal("archive24 capacity bypassed")
	}
	if !reflect.DeepEqual(before, geoRetentionRows(t, f)) {
		t.Fatal("full archive erased original evidence")
	}
}
func TestStatisticsGeoFailureTextRemainsValidUTF8WithinReceiptBound(t *testing.T) {
	for _, text := range []string{strings.Repeat("网络断开", 500), strings.Repeat("x", 1023) + "断", strings.Repeat("\xff", 1000)} {
		out := statisticsGeoBoundedError(errors.New(text))
		if len(out) > 1024 || !utf8.ValidString(out) || out == "" {
			t.Fatal("failure receipt exceeds bound after JSON repair", len(out))
		}
		wire, _ := json.Marshal(out)
		var decoded string
		json.Unmarshal(wire, &decoded)
		if len(decoded) > 1024 {
			t.Fatal("JSON expanded invalid truncated failure")
		}
	}
}
func TestStatisticsGeoRetentionNativeNamespaceChild(t *testing.T) {
	parent := os.Getenv("PANEL_GEO_RETENTION_NATIVE_PARENT")
	if parent == "" {
		t.Skip("dedicated native systemd child fixture only")
	}
	if os.Geteuid() != 0 || !strings.HasPrefix(parent, "/var/lib/panel-executor/statistics-geodata-test24beqg-") || filepath.Clean(parent) != parent || statisticsGeoParents(parent) != nil || ruleFeedStoreOwned(parent, true, 0700) != nil {
		t.Fatal("native namespace fixture parent is not the approved private root scope")
	}
	f := geoStoreRootFixtureIn(t, parent)
	old := f.install(t, "2026-08")
	f.install(t, "2026-09")
	f.install(t, "2026-10")
	before, identity := geoRetentionSelector(t, f)
	if err := f.store.maintain(context.Background(), "archive", geoStoreName(old)); err != nil {
		t.Fatal("archive within hardened writable bind mount", err)
	}
	if err := f.store.maintain(context.Background(), "restore", geoStoreName(old)); err != nil {
		t.Fatal("restore within hardened writable bind mount", err)
	}
	after, current := geoRetentionSelector(t, f)
	if !bytes.Equal(before, after) || !geoStoreStableInfo(identity, current) {
		t.Fatal("hardened namespace changed selection")
	}
}
func TestStatisticsGeoRetentionActualHardenedSystemdBindMount(t *testing.T) {
	if os.Getenv("PANEL_GEODATA_NATIVE_RETENTION_TEST") != "1" {
		t.Skip("explicit owned QA systemd fixture acceptance required; not generic CI/provider proof")
	}
	parent := geoStoreRootFixture(t)
	scope := filepath.Dir(parent.store.base)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := []string{"--unit=panel-own-geodata-retention-" + core.ID(), "--wait", "--collect", "--pipe", "--property=User=root", "--property=Group=root", "--property=ProtectSystem=strict", "--property=ProtectHome=true", "--property=PrivateTmp=true", "--property=PrivateDevices=true", "--property=NoNewPrivileges=true", "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=", "--property=ReadWritePaths=" + scope, "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "--property=MemoryMax=1G", "--property=MemoryHigh=768M", "--property=MemorySwapMax=0", "--property=TasksMax=32", "--property=CPUQuota=70%", "--property=RuntimeMaxSec=55s", "--setenv=PANEL_GEO_RETENTION_NATIVE_PARENT=" + scope, binary, "-test.run=^TestStatisticsGeoRetentionNativeNamespaceChild$", "-test.v", "-test.count=1"}
	out, err := exec.CommandContext(ctx, "/usr/bin/systemd-run", args...).CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("--- PASS: TestStatisticsGeoRetentionNativeNamespaceChild")) {
		t.Fatalf("actual hardened native namespace fixture failed: %v\n%s", err, out)
	}
	t.Log("actual hardened systemd bind-mount archive/restore passed with synthetic signed fixtures, not original-provider/installed-app acceptance")
}
