//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
)

func wafBackupArchiveFixture(t *testing.T) (*Service, string, core.WAFBackupArchiveInput) {
	t.Helper()
	s, dir := wafInventoryFixture(t)
	if err := s.writeSoftwareManifest(softwareManifest{ID: "nginx-waf", Version: core.WAFVersion, Settings: core.WAFSettings(core.DefaultWAFConfig()), InstalledAt: core.Now()}); err != nil {
		t.Fatal(err)
	}
	row, err := s.readWAFBackupSnapshot(context.Background(), filepath.Base(dir))
	if err != nil {
		t.Fatal(err)
	}
	return s, dir, core.WAFBackupArchiveInput{ID: row.ID, SHA: row.SHA, Confirm: "ARCHIVE NGINX CONFIG " + row.ID}
}

func TestWAFBackupArchivePreservesOriginalIdentityAndOnlyReplaysOriginalSnapshot(t *testing.T) {
	s, dir, in := wafBackupArchiveFixture(t)
	before, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(s.Config.SecurityDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	files, err := wafArchiveSnapshotIdentity(root, "waf-backups/"+in.ID)
	if err != nil {
		t.Fatal(err)
	}
	configBefore, err := os.ReadFile(s.Config.NginxConf)
	if err != nil {
		t.Fatal(err)
	}
	manifestBefore, err := os.ReadFile(s.softwareManifestPath("nginx-waf"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.archiveWAFBackup(context.Background(), in)
	if err != nil || out["archived"] != true || out["replayed"] != false || out["records_retained"] != true || out["configuration_changed"] != false {
		t.Fatal("no-overwrite archive", out, err)
	}
	after, err := os.Lstat(filepath.Join(s.Config.SecurityDir, "waf-backup-archive", in.ID))
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		t.Fatal("directory inode not preserved", err)
	}
	actual, err := wafArchiveSnapshotIdentity(root, "waf-backup-archive/"+in.ID)
	if err != nil || !reflect.DeepEqual(files, actual) {
		t.Fatal("file inode, bytes length, mode or UID/GID changed", err)
	}
	if _, err = os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("original activity slot not released", err)
	}
	beforeReplay := wafInventoryTree(t, s.Config.SystemRoot)
	out, err = s.archiveWAFBackup(context.Background(), in)
	if err != nil || out["replayed"] != true || !reflect.DeepEqual(beforeReplay, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("original ID+SHA replay changed evidence", out, err)
	}
	configAfter, err := os.ReadFile(s.Config.NginxConf)
	if err != nil || string(configBefore) != string(configAfter) {
		t.Fatal("archival applied an old website config", err)
	}
	manifestAfter, err := os.ReadFile(s.softwareManifestPath("nginx-waf"))
	if err != nil || string(manifestBefore) != string(manifestAfter) {
		t.Fatal("archival replaced installation or policy", err)
	}
	if _, err = s.backupWAFConfiguration(); err != nil {
		t.Fatal("new activity backup cannot use released slot", err)
	}
}

func TestWAFBackupArchiveRefusesStaleMissingInstallPendingAndCanceledWithoutWrites(t *testing.T) {
	for _, name := range []string{"stale", "missing-install", "old-version", "pending", "html-pending", "canceled", "unsafe-archive", "missing-id"} {
		t.Run(name, func(t *testing.T) {
			s, _, in := wafBackupArchiveFixture(t)
			ctx := context.Background()
			switch name {
			case "stale":
				in.SHA = strings.Repeat("0", 64)
			case "missing-install":
				if err := os.Rename(s.softwareManifestPath("nginx-waf"), s.softwareManifestPath("nginx-waf")+".retained"); err != nil {
					t.Fatal(err)
				}
			case "old-version":
				if err := s.writeSoftwareManifest(softwareManifest{ID: "nginx-waf", Version: "2.4.0", Settings: core.WAFSettings(core.DefaultWAFConfig()), InstalledAt: core.Now()}); err != nil {
					t.Fatal(err)
				}
			case "pending", "html-pending":
				path := s.wafPendingPath()
				if name == "html-pending" {
					path = s.analyticsHTMLTransactionService().wafPendingPath()
				}
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("original pending retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unsafe-archive":
				path := filepath.Join(s.Config.SecurityDir, "waf-backup-archive")
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				// The native diagnostic runner uses umask 0077. Set the actual
				// forbidden mode, rather than hoping Mkdir bypasses that mask.
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "missing-id":
				in.ID = core.ID()
				in.Confirm = "ARCHIVE NGINX CONFIG " + in.ID
			}
			before := wafInventoryTree(t, s.Config.SystemRoot)
			if out, err := s.archiveWAFBackup(ctx, in); err == nil || out != nil {
				t.Fatal("unsafe maintenance accepted", out, err)
			}
			if !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
				t.Fatal("refused preflight changed evidence")
			}
		})
	}
}

func TestWAFBackupArchiveLargeActiveScanOverflowStillSupportsVerifiedSingleSnapshot(t *testing.T) {
	s, _, _ := wafBackupArchiveFixture(t)
	manifest, err := os.ReadFile(s.softwareManifestPath("nginx-waf"))
	if err != nil {
		t.Fatal(err)
	}
	// Fill the real producer's complete 8 MiB source budget, including
	// the existing installation manifest. Index bytes make 16 rows >128 MiB.
	if err := os.WriteFile(s.Config.NginxConf, []byte(strings.Repeat("x", (8<<20)-len(manifest))), 0644); err != nil {
		t.Fatal(err)
	}
	var dir string
	for i := 0; i < 16; i++ {
		var err error
		dir, err = s.backupWAFConfiguration()
		if err != nil {
			t.Fatal(err)
		}
	}
	if out, err := s.readWAFBackupInventory(context.Background()); err == nil || out.Available {
		t.Fatal("oversized full inventory claimed complete")
	}
	row, err := s.readWAFBackupSnapshot(context.Background(), filepath.Base(dir))
	if err != nil {
		t.Fatal(err)
	}
	in := core.WAFBackupArchiveInput{ID: row.ID, SHA: row.SHA, Confirm: "ARCHIVE NGINX CONFIG " + row.ID}
	if _, err = s.archiveWAFBackup(context.Background(), in); err != nil {
		t.Fatal("safe selected archive depended on complete full scan", err)
	}
	out, err := s.readWAFBackupInventory(context.Background())
	if err != nil || !out.Available || len(out.Entries) != 16 {
		t.Fatal("after one selected handoff full active scan remains unavailable", out, err)
	}
}

func TestWAFBackupArchiveCountCapacityDoesNotDeleteOrOverwriteEitherNamespace(t *testing.T) {
	s, first, in := wafBackupArchiveFixture(t)
	archive := filepath.Join(s.Config.SecurityDir, "waf-backup-archive")
	if err := os.Mkdir(archive, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		dir := first
		if i != 0 {
			var err error
			dir, err = s.backupWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Rename(dir, filepath.Join(archive, filepath.Base(dir))); err != nil {
			t.Fatal(err)
		}
	}
	// Genuine same-identity replay remains possible at the full count, because
	// it does not allocate a new slot or copy an original byte.
	if out, err := s.archiveWAFBackup(context.Background(), in); err != nil || out["replayed"] != true {
		t.Fatal(out, err)
	}
	dir, err := s.backupWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	row, err := s.readWAFBackupSnapshot(context.Background(), filepath.Base(dir))
	if err != nil {
		t.Fatal(err)
	}
	in = core.WAFBackupArchiveInput{ID: row.ID, SHA: row.SHA, Confirm: "ARCHIVE NGINX CONFIG " + row.ID}
	before := wafInventoryTree(t, s.Config.SystemRoot)
	if out, err := s.archiveWAFBackup(context.Background(), in); err == nil || out != nil {
		t.Fatal("full archive accepted a new snapshot", out, err)
	}
	if !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("count refusal changed original evidence")
	}
}

func TestWAFBackupArchiveByteCapacityRefusesNewSlotAndRetainsAllRecords(t *testing.T) {
	s, _, _ := wafBackupArchiveFixture(t)
	manifest, err := os.ReadFile(s.softwareManifestPath("nginx-waf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Config.NginxConf, []byte(strings.Repeat("x", (8<<20)-len(manifest))), 0644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(s.Config.SecurityDir, "waf-backup-archive")
	if err := os.Mkdir(archive, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 15; i++ {
		dir, err := s.backupWAFConfiguration()
		if err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(dir, filepath.Join(archive, filepath.Base(dir))); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := s.backupWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	row, err := s.readWAFBackupSnapshot(context.Background(), filepath.Base(dir))
	if err != nil {
		t.Fatal(err)
	}
	in := core.WAFBackupArchiveInput{ID: row.ID, SHA: row.SHA, Confirm: "ARCHIVE NGINX CONFIG " + row.ID}
	lock, _, err := s.openExistingWAFBackupLock(context.Background(), syscall.LOCK_SH)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.scanWAFBackupSelection(context.Background(), "waf-backup-archive", "")
	lock.Close()
	if err != nil || !out.Available || len(out.Entries) != 15 || out.Bytes+row.Bytes <= wafBackupInventoryBytes {
		t.Fatal("byte-capacity fixture not at true projected limit", out.Bytes, row.Bytes, err)
	}
	before := wafInventoryTree(t, s.Config.SystemRoot)
	if out, err := s.archiveWAFBackup(context.Background(), in); err == nil || out != nil {
		t.Fatal("byte-capacity accepted", out, err)
	}
	if !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("byte-capacity refusal altered evidence")
	}
}

func TestWAFBackupArchiveCollisionAndDamagedArchiveNeverRepairEvidence(t *testing.T) {
	for _, kind := range []string{"collision", "broken-index", "hardlink", "symlink", "unsafe-leaf", "missing-lock", "busy-lock"} {
		t.Run(kind, func(t *testing.T) {
			s, first, in := wafBackupArchiveFixture(t)
			archive := filepath.Join(s.Config.SecurityDir, "waf-backup-archive")
			if err := os.Mkdir(archive, 0700); err != nil {
				t.Fatal(err)
			}
			dir, err := s.backupWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(archive, filepath.Base(dir))
			if kind == "collision" {
				target = filepath.Join(archive, in.ID)
			}
			if err = os.Rename(dir, target); err != nil {
				t.Fatal(err)
			}
			var lock *os.File
			switch kind {
			case "broken-index":
				err = os.WriteFile(filepath.Join(target, "index.json"), []byte("original broken archive retained"), 0600)
			case "hardlink":
				err = os.Link(filepath.Join(target, "000.conf"), filepath.Join(s.Config.SystemRoot, "original-link-retained"))
			case "symlink":
				err = os.Symlink(first, filepath.Join(target, "extra-link"))
			case "unsafe-leaf":
				err = os.Chmod(target, 0750)
			case "missing-lock":
				err = os.Rename(filepath.Join(s.Config.SecurityDir, "waf-configuration.lock"), filepath.Join(s.Config.SecurityDir, "original-lock-retained"))
			case "busy-lock":
				lock, err = s.lockWAFConfiguration()
				if lock != nil {
					defer lock.Close()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before := wafInventoryTree(t, s.Config.SystemRoot)
			if out, err := s.archiveWAFBackup(context.Background(), in); err == nil || out != nil {
				t.Fatal("ambiguous maintenance accepted", out, err)
			}
			if !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
				t.Fatal("invalid archive was repaired, unlinked, overwritten or modified")
			}
		})
	}
}

func TestWAFBackupArchiveNativeDisconnectAndFsyncFailureRetainOriginalReplayIdentity(t *testing.T) {
	for _, kind := range []string{"after-rename-cancel", "after-rename-fsync", "rename-refused"} {
		t.Run(kind, func(t *testing.T) {
			s, dir, in := wafBackupArchiveFixture(t)
			root, err := os.OpenRoot(s.Config.SecurityDir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			original, err := os.Lstat(dir)
			if err != nil {
				t.Fatal(err)
			}
			files, err := wafArchiveSnapshotIdentity(root, "waf-backups/"+in.ID)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			moved := false
			afterSync := 0
			operation := wafBackupArchiveIO{
				rename: func(a int, b string, c int, d string, e uint) error {
					if e != unix.RENAME_NOREPLACE || b != in.ID || d != in.ID {
						t.Fatal("unbound rename")
					}
					if kind == "rename-refused" {
						return unix.EXDEV
					}
					err := unix.Renameat2(a, b, c, d, e)
					if err == nil {
						moved = true
						if kind == "after-rename-cancel" {
							cancel()
						}
					}
					return err
				},
				syncDirectory: func(f *os.File) error {
					if moved {
						afterSync++
						if kind == "after-rename-fsync" && afterSync == 1 {
							return unix.EIO
						}
					}
					return f.Sync()
				},
			}
			out, err := s.archiveWAFBackupWithIO(ctx, in, operation)
			location := "waf-backup-archive/" + in.ID
			if kind == "rename-refused" {
				if err == nil || out != nil || moved {
					t.Fatal("cross-device fallback occurred", out, err)
				}
				location = "waf-backups/" + in.ID
			}
			if kind == "after-rename-cancel" {
				if err != nil || out["archived"] != true || !errors.Is(ctx.Err(), context.Canceled) || afterSync != 3 {
					t.Fatal("disconnect abandoned persistence", out, err, afterSync)
				}
			}
			if kind == "after-rename-fsync" {
				if err == nil || out != nil || !moved || !strings.Contains(err.Error(), "可能已交接") {
					t.Fatal("fsync failure claimed success or unchanged source", out, err)
				}
			}
			after, err := root.Lstat(location)
			if err != nil || !os.SameFile(original, after) {
				t.Fatal("fault changed original directory identity", err)
			}
			actual, err := wafArchiveSnapshotIdentity(root, location)
			if err != nil || !reflect.DeepEqual(files, actual) {
				t.Fatal("fault changed private bytes/file identity", err)
			}
			// Real syscalls, not the fault seam, verify the retained original on retry.
			out, err = s.archiveWAFBackup(context.Background(), in)
			if err != nil || out["replayed"] != moved {
				t.Fatal("original identity replay", out, err)
			}
		})
	}
}

func TestWAFBackupArchiveHTTPClosedInputNoOverwriteAndMetadataOnlyReads(t *testing.T) {
	s, _, in := wafBackupArchiveFixture(t)
	m := http.NewServeMux()
	s.wafBackupInventoryRoutes(m)
	raw, _ := json.Marshal(in)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		return w
	}
	base := "/v1/software/nginx-waf/"
	for _, bad := range []struct{ path, body string }{
		{base + "archive-config-backup?", string(raw)}, {base + "archive-config-backup?path=/private", string(raw)},
		{base + "archive-config-backup", strings.Replace(string(raw), `"confirm":`, `"source":"/private","confirm":`, 1)},
		{base + "archive-config-backup", strings.Repeat(" ", 4097)},
	} {
		before := wafInventoryTree(t, s.Config.SystemRoot)
		w := request("POST", bad.path, bad.body)
		if w.Code != 400 || !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
			t.Fatal("unsafe route input changed evidence", w.Code)
		}
	}
	w := request("POST", base+"archive-config-backup", string(raw))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("archive route", w.Code, w.Body.String())
	}
	out, err := core.DecodeWAFBackupArchiveResult(w.Body.Bytes(), in)
	if err != nil || out.Replayed {
		t.Fatal(out, err)
	}
	before := wafInventoryTree(t, s.Config.SystemRoot)
	for _, path := range []string{base + "config-backup-archive", base + "config-backup-archive/" + in.ID} {
		w := request("GET", path, "")
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "source") || strings.Contains(w.Body.String(), s.Config.SystemRoot) || strings.Contains(w.Body.String(), "events {}") {
			t.Fatal("private archive metadata escaped", w.Code)
		}
		if strings.HasSuffix(path, in.ID) {
			if _, err := core.DecodeWAFBackupSnapshot(w.Body.Bytes()); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := core.DecodeWAFBackupInventory(w.Body.Bytes()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("archive GET mutated evidence")
	}
	w = request("POST", base+"archive-config-backup", string(raw))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	out, err = core.DecodeWAFBackupArchiveResult(w.Body.Bytes(), in)
	if err != nil || !out.Replayed || !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("HTTP original replay mutated evidence", out, err)
	}
	for _, path := range []string{base + "config-backup-archive?", base + "config-backup-archive/BAD", base + "config-backup-archive/" + in.ID + "?"} {
		if w := request("GET", path, ""); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
}
