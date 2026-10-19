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

	"local/panel/internal/core"
)

func wafInventoryFixture(t *testing.T) (*Service, string) {
	t.Helper()
	s := wafPolicyFixture(t)
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("read-only inventory executed a command")
		return "", nil
	}
	f, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	dir, err := s.backupWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

// Ignore access time only: a legitimate read may update it. Preserve inode,
// ownership, mode, links, sizes, mtime/ctime, and full ordinary-file bytes.
func wafInventoryTree(t *testing.T, root string) map[string]any {
	t.Helper()
	out := map[string]any{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		value := []any{info.Mode(), st.Uid, st.Gid, st.Ino, st.Nlink, info.Size(), st.Mtim, st.Ctim}
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value = append(value, core.Hash(string(raw)))
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			value = append(value, target)
		}
		out[path] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWAFBackupInventoryReadsGenuineCompleteSnapshotWithoutWrites(t *testing.T) {
	s, dir := wafInventoryFixture(t)
	before := wafInventoryTree(t, s.Config.SystemRoot)
	out, err := s.readWAFBackupInventory(context.Background())
	if err != nil || !out.Available || !out.ReadOnly || out.CountMax != 100 || out.ScanMax != 128<<20 || len(out.Entries) != 1 || out.Entries[0].ID != filepath.Base(dir) || out.Entries[0].Files != 5 || out.Bytes != out.Entries[0].Bytes || len(out.Entries[0].SHA) != 64 {
		t.Fatal("genuine snapshot not verified", out, err)
	}
	data, _ := json.Marshal(out)
	if strings.Contains(string(data), s.Config.SystemRoot) || strings.Contains(string(data), "events {}") || strings.Contains(string(data), "source") || strings.Contains(string(data), "owner") {
		t.Fatal("private config metadata escaped")
	}
	if _, err := core.DecodeWAFBackupInventory(data); err != nil {
		t.Fatal("executor/Core closed DTO mismatch", err)
	}
	if !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("read modified the original tree")
	}
}

func TestWAFBackupInventoryAbsenceBusyAndCancellationAreNotMutations(t *testing.T) {
	s := wafPolicyFixture(t)
	before := wafInventoryTree(t, s.Config.SystemRoot)
	out, err := s.readWAFBackupInventory(context.Background())
	if err != nil || out.Available || len(out.Entries) != 0 || !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("absence created or claimed inventory", out, err)
	}
	f, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	before = wafInventoryTree(t, s.Config.SystemRoot)
	if _, err = s.readWAFBackupInventory(context.Background()); !errors.Is(err, errWAFConfigurationBusy) {
		t.Fatal("exclusive apply lock was ignored", err)
	}
	f.Close()
	out, err = s.readWAFBackupInventory(context.Background())
	if err != nil || !out.Available || len(out.Entries) != 0 || !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("empty locked observation changed tree", out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err = s.readWAFBackupInventory(ctx); !errors.Is(err, context.Canceled) || out.Available || len(out.Entries) != 0 {
		t.Fatal("canceled observation", out, err)
	}
}

func TestWAFBackupInventoryRejectsAmbiguousAndIncompletePrivateIndex(t *testing.T) {
	changes := map[string]func([]byte) []byte{
		"duplicate-root": func(raw []byte) []byte { return append([]byte(`{"files":[],`), raw[1:]...) },
		"escaped-duplicate": func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), `"existed": true`, `"existed": true, "exis\u0074ed": true`, 1))
		},
		"case-folded-key": func(raw []byte) []byte { return []byte(strings.Replace(string(raw), `"source"`, `"Source"`, 1)) },
		"unknown-field": func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), `"source":`, `"extra": 1, "source":`, 1))
		},
		"null-existed": func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), `"existed": true`, `"existed": null`, 1))
		},
		"null-mode": func(raw []byte) []byte { return []byte(strings.Replace(string(raw), `"mode": 420`, `"mode": null`, 1)) },
		"null-uid":  func(raw []byte) []byte { return []byte(strings.Replace(string(raw), `"uid": 0`, `"uid": null`, 1)) },
		"trailing":  func(raw []byte) []byte { return append(raw, []byte(` {}`)...) },
		"missing-fixed": func(raw []byte) []byte {
			var idx wafBackupIndex
			json.Unmarshal(raw, &idx)
			idx.Files = idx.Files[:1]
			out, _ := json.Marshal(idx)
			return out
		},
		"wrong-fixed": func(raw []byte) []byte {
			var idx wafBackupIndex
			json.Unmarshal(raw, &idx)
			idx.Files[1].Source = idx.Files[2].Source
			out, _ := json.Marshal(idx)
			return out
		},
		"path-escape": func(raw []byte) []byte {
			var idx wafBackupIndex
			json.Unmarshal(raw, &idx)
			idx.Files[0].File = "../escaped.conf"
			out, _ := json.Marshal(idx)
			return out
		},
		"stale-sha": func(raw []byte) []byte {
			var idx wafBackupIndex
			json.Unmarshal(raw, &idx)
			idx.Files[0].SHA = strings.Repeat("0", 64)
			out, _ := json.Marshal(idx)
			return out
		},
		"missing-owner": func(raw []byte) []byte {
			var idx wafBackupIndex
			json.Unmarshal(raw, &idx)
			idx.Files[0].Owner = nil
			out, _ := json.Marshal(idx)
			return out
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s, dir := wafInventoryFixture(t)
			path := filepath.Join(dir, "index.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// UID is the fixture runner's actual UID, not assumed root.
			if name == "null-uid" {
				var v map[string]any
				json.Unmarshal(raw, &v)
				files := v["files"].([]any)
				files[0].(map[string]any)["owner"].(map[string]any)["uid"] = nil
				raw, _ = json.Marshal(v)
			} else {
				next := change(raw)
				if string(next) == string(raw) {
					t.Fatal("negative fixture did not mutate source")
				}
				raw = next
			}
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			before := wafInventoryTree(t, s.Config.SystemRoot)
			out, err := s.readWAFBackupInventory(context.Background())
			if err == nil || out.Available || len(out.Entries) != 0 || out.Bytes != 0 {
				t.Fatal("invalid index accepted or partial inventory published", out, err)
			}
			if !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
				t.Fatal("invalid evidence changed")
			}
		})
	}
}

func TestWAFBackupInventoryRefusesUnsafeLeafDirectoryAndLock(t *testing.T) {
	cases := map[string]func(*testing.T, *Service, string){
		"extra-file": func(t *testing.T, s *Service, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "extra"), []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"missing-content": func(t *testing.T, s *Service, dir string) {
			if err := os.Rename(filepath.Join(dir, "000.conf"), filepath.Join(s.Config.SystemRoot, "retained-original")); err != nil {
				t.Fatal(err)
			}
		},
		"symlink-content": func(t *testing.T, s *Service, dir string) {
			p := filepath.Join(dir, "000.conf")
			if err := os.Rename(p, p+".keep"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".keep", p); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink-content": func(t *testing.T, s *Service, dir string) {
			if err := os.Link(filepath.Join(dir, "000.conf"), filepath.Join(s.Config.SystemRoot, "link")); err != nil {
				t.Fatal(err)
			}
		},
		"public-content": func(t *testing.T, s *Service, dir string) {
			if err := os.Chmod(filepath.Join(dir, "000.conf"), 0644); err != nil {
				t.Fatal(err)
			}
		},
		"public-index": func(t *testing.T, s *Service, dir string) {
			if err := os.Chmod(filepath.Join(dir, "index.json"), 0644); err != nil {
				t.Fatal(err)
			}
		},
		"public-directory": func(t *testing.T, s *Service, dir string) {
			if err := os.Chmod(dir, 0750); err != nil {
				t.Fatal(err)
			}
		},
		"public-parent": func(t *testing.T, s *Service, dir string) {
			if err := os.Chmod(filepath.Dir(dir), 0755); err != nil {
				t.Fatal(err)
			}
		},
		"extra-directory": func(t *testing.T, s *Service, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "extra"), 0700); err != nil {
				t.Fatal(err)
			}
		},
		"nonempty-lock": func(t *testing.T, s *Service, dir string) {
			if err := os.WriteFile(filepath.Join(s.Config.SecurityDir, "waf-configuration.lock"), []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"public-lock": func(t *testing.T, s *Service, dir string) {
			if err := os.Chmod(filepath.Join(s.Config.SecurityDir, "waf-configuration.lock"), 0644); err != nil {
				t.Fatal(err)
			}
		},
		"oversized-index": func(t *testing.T, s *Service, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(strings.Repeat(" ", (1<<20)+1)), 0600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, dir := wafInventoryFixture(t)
			change(t, s, dir)
			before := wafInventoryTree(t, s.Config.SystemRoot)
			out, err := s.readWAFBackupInventory(context.Background())
			if err == nil || out.Available || len(out.Entries) != 0 || out.Bytes != 0 {
				t.Fatal("unsafe evidence accepted", out, err)
			}
			if !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
				t.Fatal("unsafe evidence changed")
			}
		})
	}
}

func TestWAFBackupInventoryCountBoundaryKeepsAllEvidence(t *testing.T) {
	s, _ := wafInventoryFixture(t)
	for i := 1; i < 100; i++ {
		if _, err := s.backupWAFConfiguration(); err != nil {
			t.Fatal(err)
		}
	}
	out, err := s.readWAFBackupInventory(context.Background())
	if err != nil || len(out.Entries) != 100 {
		t.Fatal("exact count rejected", err)
	}
	base := filepath.Join(s.Config.SecurityDir, "waf-backups")
	if err = os.Mkdir(filepath.Join(base, core.ID()), 0700); err != nil {
		t.Fatal(err)
	}
	before := wafInventoryTree(t, s.Config.SystemRoot)
	out, err = s.readWAFBackupInventory(context.Background())
	if err == nil || out.Available || len(out.Entries) != 0 || !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("count overflow deleted or claimed partial inventory", out, err)
	}
}

func TestWAFBackupInventoryAPIIsFixedReadOnlyAndHidesPrivateFailures(t *testing.T) {
	s, dir := wafInventoryFixture(t)
	m := http.NewServeMux()
	s.wafBackupInventoryRoutes(m)
	read := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		m.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	for _, path := range []string{"/v1/software/nginx-waf/config-backups?", "/v1/software/nginx-waf/config-backups?path=/etc/shadow", "/v1/software/nginx-waf/config-backups?page=1&page=2"} {
		if w := read(path); w.Code != 400 {
			t.Fatal("unknown query accepted", w.Code)
		}
	}
	w := read("/v1/software/nginx-waf/config-backups")
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code)
	}
	if err := os.Chmod(filepath.Join(dir, "index.json"), 0644); err != nil {
		t.Fatal(err)
	}
	w = read("/v1/software/nginx-waf/config-backups")
	if w.Code != 409 || strings.Contains(w.Body.String(), s.Config.SystemRoot) || strings.Contains(w.Body.String(), `"entries"`) {
		t.Fatal("partial inventory or private error leaked", w.Code, w.Body.String())
	}
}

func TestWAFBackupInventoryNeverReadsCurrentSourcesOrPublishesEarlyRows(t *testing.T) {
	s, dir := wafInventoryFixture(t)
	original := s.Config.NginxConf
	if err := os.Rename(original, original+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/shadow", original); err != nil {
		t.Fatal(err)
	}
	before := wafInventoryTree(t, s.Config.SystemRoot)
	out, err := s.readWAFBackupInventory(context.Background())
	if err != nil || !out.Available || len(out.Entries) != 1 || !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("inventory consulted current source or changed it", out, err)
	}
	base := filepath.Dir(dir)
	first := filepath.Join(base, strings.Repeat("0", 32))
	if err = os.Rename(dir, first); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(base, strings.Repeat("f", 32)), 0700); err != nil {
		t.Fatal(err)
	}
	before = wafInventoryTree(t, s.Config.SystemRoot)
	out, err = s.readWAFBackupInventory(context.Background())
	if err == nil || out.Available || len(out.Entries) != 0 || out.Bytes != 0 || !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("failed later row published early inventory or repaired it", out, err)
	}
}

func TestWAFBackupInventoryLockIdentityAndPermissionsAreStable(t *testing.T) {
	s, _ := wafInventoryFixture(t)
	path := filepath.Join(s.Config.SecurityDir, "waf-configuration.lock")
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err = wafBackupLockUnchanged(f, path, before); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err = wafBackupLockUnchanged(f, path, before); err == nil {
		t.Fatal("permission change ignored")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+".retained"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = wafBackupLockUnchanged(f, path, before); err == nil {
		t.Fatal("replaced lock inode accepted")
	}
}

func TestWAFBackupInventoryFullScanAndPerSnapshotByteLimits(t *testing.T) {
	s := wafPolicyFixture(t)
	f, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	// Exact real producer format and contents, not an injected inventory count.
	if err = os.WriteFile(s.Config.NginxConf, []byte(strings.Repeat("x", 8<<20)), 0644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		if _, err = s.backupWAFConfiguration(); err != nil {
			t.Fatal(err)
		}
	}
	out, err := s.readWAFBackupInventory(context.Background())
	if err == nil || out.Available || len(out.Entries) != 0 || out.Bytes != 0 {
		t.Fatal("128 MiB plus actual indices claimed complete", out, err)
	}
	entries, err := os.ReadDir(filepath.Join(s.Config.SecurityDir, "waf-backups"))
	if err != nil || len(entries) != 16 {
		t.Fatal("capacity rejection removed evidence", err)
	}
	selected, err := s.readWAFBackupSnapshot(context.Background(), entries[0].Name())
	if err != nil || selected.ID != entries[0].Name() || selected.Bytes <= 8<<20 || selected.Bytes > 9<<20 {
		t.Fatal("selected complete snapshot unavailable solely because full scan exceeds quota", selected, err)
	}
	first := filepath.Join(s.Config.SecurityDir, "waf-backups", entries[0].Name(), "000.conf")
	file, err := os.OpenFile(first, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate((8 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	out, err = s.readWAFBackupInventory(context.Background())
	if err == nil || out.Available || len(out.Entries) != 0 || out.Bytes != 0 {
		t.Fatal("per-snapshot logical bound ignored", out, err)
	}
	st, err := os.Stat(first)
	if err != nil || st.Size() != (8<<20)+1 {
		t.Fatal("overflow evidence changed", err)
	}
}

func TestWAFBackupSnapshotOnlyCertifiesSelectedCompleteEvidence(t *testing.T) {
	s, dir := wafInventoryFixture(t)
	id := filepath.Base(dir)
	other, err := s.backupWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(other, "index.json"), []byte("damaged evidence kept"), 0600); err != nil {
		t.Fatal(err)
	}
	before := wafInventoryTree(t, s.Config.SystemRoot)
	if out, err := s.readWAFBackupInventory(context.Background()); err == nil || out.Available || len(out.Entries) != 0 {
		t.Fatal("damaged whole inventory accepted", err)
	}
	row, err := s.readWAFBackupSnapshot(context.Background(), id)
	if err != nil || row.ID != id || row.Files != 5 || len(row.SHA) != 64 {
		t.Fatal("independent genuine snapshot rejected", row, err)
	}
	m := http.NewServeMux()
	s.wafBackupInventoryRoutes(m)
	read := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		m.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	w := read("/v1/software/nginx-waf/config-backups/" + id)
	var out core.WAFBackupInventoryRow
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.ID != id || strings.Contains(w.Body.String(), `"entries"`) || strings.Contains(w.Body.String(), `"available"`) || strings.Contains(w.Body.String(), s.Config.SystemRoot) {
		t.Fatal("selected evidence falsely became whole inventory or leaked sources", w.Code, w.Body.String())
	}
	for _, path := range []string{"/v1/software/nginx-waf/config-backups/" + id + "?", "/v1/software/nginx-waf/config-backups/" + id + "?path=/etc/shadow", "/v1/software/nginx-waf/config-backups/BAD"} {
		if w := read(path); w.Code != 400 {
			t.Fatal("unreviewed identifier/query", w.Code)
		}
	}
	if w := read("/v1/software/nginx-waf/config-backups/" + core.ID()); w.Code != 404 {
		t.Fatal("missing snapshot invented", w.Code)
	}
	if w := read("/v1/software/nginx-waf/config-backups/" + filepath.Base(other)); w.Code != 409 || strings.Contains(w.Body.String(), "damaged evidence kept") {
		t.Fatal("damaged selected snapshot or raw contents relayed", w.Code)
	}
	if !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("selected observation changed or repaired evidence")
	}
}

func TestWAFBackupSlotsOnlyListPrivateDirectoryIdentitiesWithoutReadingOrWrites(t *testing.T) {
	s, dir := wafInventoryFixture(t)
	id := filepath.Base(dir)
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte("broken evidence remains untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	before := wafInventoryTree(t, s.Config.SystemRoot)
	if _, err := s.readWAFBackupSnapshot(context.Background(), id); err == nil {
		t.Fatal("damaged contents were certified")
	}
	out, err := s.readWAFBackupSlots(context.Background())
	if err != nil || !out.Available || out.ContentsVerified || !out.ReadOnly || out.CountMax != 100 || !reflect.DeepEqual(out.IDs, []string{id}) {
		t.Fatal("directory identity observation", out, err)
	}
	m := http.NewServeMux()
	s.wafBackupInventoryRoutes(m)
	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/nginx-waf/config-backup-slots", nil))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), s.Config.SystemRoot) || strings.Contains(w.Body.String(), "broken evidence") || strings.Contains(w.Body.String(), `"entries"`) {
		t.Fatal("raw source or fake content inventory", w.Code, w.Body.String())
	}
	if !reflect.DeepEqual(before, wafInventoryTree(t, s.Config.SystemRoot)) {
		t.Fatal("metadata observation repaired or changed evidence")
	}
	if err = os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	out, err = s.readWAFBackupSlots(context.Background())
	if err == nil || out.Available || len(out.IDs) != 0 {
		t.Fatal("unsafe directory accepted or partial IDs returned", out, err)
	}
	absent := wafPolicyFixture(t)
	out, err = absent.readWAFBackupSlots(context.Background())
	if err != nil || out.Available || len(out.IDs) != 0 {
		t.Fatal("missing lock certified as zero", out, err)
	}
}
