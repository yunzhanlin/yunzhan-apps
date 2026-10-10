//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// Synthetic private filesystem fixture: not a genuine installed Apache app,
// business request, normal signed package, or authenticated live-panel proof.
func apacheHistoryFixture(t *testing.T) (*Service, wafTransaction, string, []byte) {
	t.Helper()
	s, plan := apacheTransactionFixture(t, true, false)
	installed := filepath.Join(s.moduleDir("apache-waf"), "installed.json")
	if err := moduleWrite(installed, map[string]any{"id": "apache-waf", "version": core.ApacheWAFVersion, "settings": core.WAFSettings(core.DefaultApacheWAFConfig()), "installed_at": "2026-10-10T00:00:00Z", "updated_at": "2026-10-10T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	b, err := s.apacheWAFStableBackup(installed)
	if err != nil {
		t.Fatal(err)
	}
	plan[2] = wafConfigChange{Path: installed, OldData: b.data, OldExists: true, OldMode: b.mode, OldOwner: b.owner, NextData: append([]byte{}, b.data...), NextExists: true, NextMode: b.mode, NextOwner: b.owner}
	tx := wafTransaction{Format: 2, ID: core.ID(), State: "committed", CreatedAt: "2026-10-10T00:00:00Z", Changes: plan, Digests: map[string]string{}}
	for _, c := range plan {
		tx.Digests[c.Path+":old"] = core.Hash(string(c.OldData))
		tx.Digests[c.Path+":next"] = core.Hash(string(c.NextData))
	}
	if err = s.wafOwnedDirectory(filepath.Dir(s.wafPendingPath()), true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(s.wafPendingPath()), tx.ID+".json")
	if err = wafWriteTransaction(path, tx); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, ' ', '\n')
	if err = atomicWrite(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Error("transaction maintenance executed a system command")
		return "", errors.New("no commands allowed")
	}
	return s, tx, path, data
}
func apacheArchiveInput(tx wafTransaction, b []byte) core.ApacheWAFHistoryInput {
	return core.ApacheWAFHistoryInput{ID: tx.ID, SHA: core.Hash(string(b)), Confirm: "ARCHIVE APACHE TRANSACTION " + tx.ID}
}
func apacheHistoryReport(t *testing.T, s *Service, offset int) map[string]any {
	t.Helper()
	out, err := s.apacheWAFHistoryOperation(context.Background(), "transactions", core.ApacheWAFHistoryInput{Limit: 16, Offset: offset})
	if err != nil {
		t.Fatal(err)
	}
	return out.(map[string]any)
}

func TestApacheWAFHistoryArchiveExactBytesOwnerInodeAndLostReplyReplay(t *testing.T) {
	for _, state := range []string{"committed", "recovered"} {
		t.Run(state, func(t *testing.T) {
			s, tx, path, b := apacheHistoryFixture(t)
			tx.State = state
			if err := wafWriteTransaction(path, tx); err != nil {
				t.Fatal(err)
			}
			b, _ = os.ReadFile(path)
			b = append(b, ' ', '\n')
			if err := atomicWrite(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			before, _ := os.Stat(path)
			owner := before.Sys().(*syscall.Stat_t)
			configs := map[string][]byte{}
			for _, c := range tx.Changes {
				configs[c.Path], _ = os.ReadFile(c.Path)
			}
			in := apacheArchiveInput(tx, b)
			bad := in
			bad.SHA = strings.Repeat("0", 64)
			if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", bad); err == nil {
				t.Fatal("stale full-file SHA accepted")
			}
			if _, err := os.Lstat(s.apacheWAFArchiveDir()); !os.IsNotExist(err) {
				t.Fatal("rejected request created archive", err)
			}
			out, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", in)
			if err != nil {
				t.Fatal(err)
			}
			if out.(map[string]any)["replayed"] != false {
				t.Fatal("new move claimed replay")
			}
			archive := filepath.Join(s.apacheWAFArchiveDir(), tx.ID+".json")
			got, err := os.ReadFile(archive)
			if err != nil || !bytes.Equal(got, b) {
				t.Fatal("raw bytes changed", err)
			}
			after, _ := os.Stat(archive)
			a := after.Sys().(*syscall.Stat_t)
			if owner.Uid != a.Uid || owner.Gid != a.Gid || owner.Ino != a.Ino || owner.Dev != a.Dev || after.Mode() != before.Mode() {
				t.Fatal("original file identity changed")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("active record not moved", err)
			}
			fresh := New(s.Config).apacheWAFTransactionService()
			again, err := fresh.apacheWAFHistoryOperation(context.Background(), "archive-transaction", in)
			if err != nil || again.(map[string]any)["replayed"] != true {
				t.Fatal("lost reply not resolved with original identity", err)
			}
			if err := fresh.apacheWAFReserveTransaction(context.Background(), tx); err == nil {
				t.Fatal("archived identity reused")
			}
			for path, b := range configs {
				actual, _ := os.ReadFile(path)
				if !bytes.Equal(actual, b) {
					t.Fatal("archive changed configuration", path)
				}
			}
			report := apacheHistoryReport(t, fresh, 0)
			if report["total"] != 1 || report["transaction_active_count"] != 0 || report["transaction_archive_count"] != 1 || report["configuration_changed"] != false {
				t.Fatal(report)
			}
			public, _ := json.Marshal(report)
			for _, private := range []string{"old_data", "next_data", "old_owner", "next_owner", "backup_sha256", s.Config.SystemRoot} {
				if bytes.Contains(public, []byte(private)) {
					t.Fatal("backup content/private path leaked", private)
				}
			}
		})
	}
}

func TestApacheWAFHistoryKnownVersionsReadOnlyAndUnknownVersionsRefuse(t *testing.T) {
	for _, version := range []string{"2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.3.1", "2.4.0"} {
		t.Run(version, func(t *testing.T) {
			s, tx, path, b := apacheHistoryFixture(t)
			installed := filepath.Join(s.moduleDir("apache-waf"), "installed.json")
			var manifest map[string]any
			raw, _ := os.ReadFile(installed)
			json.Unmarshal(raw, &manifest)
			manifest["version"] = version
			if err := moduleWrite(installed, manifest); err != nil {
				t.Fatal(err)
			}
			out, err := s.apacheWAFHistoryOperation(context.Background(), "transactions", core.ApacheWAFHistoryInput{Limit: 16})
			known := core.ApacheWAFHistoryVersion(version)
			if (err == nil) != known {
				t.Fatal("version read contract", version, err)
			}
			if known && out.(map[string]any)["transaction_archive_ready"] != (version == core.ApacheWAFVersion) {
				t.Fatal("old app got new write authority")
			}
			_, err = s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, b))
			if (err == nil) != (version == core.ApacheWAFVersion) {
				t.Fatal("version archive contract", err)
			}
			if version != core.ApacheWAFVersion {
				actual, _ := os.ReadFile(path)
				if !bytes.Equal(actual, b) {
					t.Fatal("version refusal changed original record")
				}
			}
		})
	}
}

func TestApacheWAFHistoryPendingAndOrphanApplyingBlockArchiveAndCreation(t *testing.T) {
	for _, kind := range []string{"applying-pending", "recovered-pending", "orphan-applying", "unknown-pending", "mismatched-pending"} {
		t.Run(kind, func(t *testing.T) {
			s, tx, path, b := apacheHistoryFixture(t)
			pending := tx
			if kind == "applying-pending" || kind == "orphan-applying" {
				tx.State = "applying"
				pending.State = "applying"
				wafWriteTransaction(path, tx)
			}
			if kind == "recovered-pending" {
				pending.State = "recovered"
			}
			if kind == "mismatched-pending" {
				pending.CreatedAt = "2026-10-09T00:00:00Z"
			}
			if kind != "orphan-applying" {
				if kind == "unknown-pending" {
					if err := unix.Mkfifo(s.wafPendingPath(), 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := wafWriteTransaction(s.wafPendingPath(), pending); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, b)); err == nil {
				t.Fatal("unresolved transaction permitted archive")
			}
			if err := s.apacheWAFReserveTransaction(context.Background(), tx); err == nil {
				t.Fatal("unresolved transaction permitted creation")
			}
			if kind != "unknown-pending" && kind != "mismatched-pending" {
				report := apacheHistoryReport(t, s, 0)
				if report["pending"] != true || report["transaction_archive_ready"] != false || report["transaction_replay_ready"] != false {
					t.Fatal(report)
				}
				for _, row := range report["apache_transactions"].([]apacheWAFHistoryRow) {
					if row.Archivable {
						t.Fatal("pending advertised archive")
					}
				}
			}
		})
	}
}

func TestApacheWAFHistoryUnsafeEntireInventoryRefusesBeforeMovingAnyRecord(t *testing.T) {
	for _, kind := range []string{"unknown-file", "symlink", "fifo", "hardlink", "writable", "truncated", "duplicate-root", "escaped-duplicate", "case-duplicate", "nested-duplicate", "unknown-field", "missing-change-field", "wrong-path", "wrong-digest", "archive-duplicate-id", "unsafe-archive-mode", "archive-applying", "dangling-archive"} {
		t.Run(kind, func(t *testing.T) {
			s, tx, path, b := apacheHistoryFixture(t)
			other := tx
			other.ID = core.ID()
			p := filepath.Join(filepath.Dir(path), other.ID+".json")
			if err := wafWriteTransaction(p, other); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "unknown-file":
				os.WriteFile(filepath.Join(filepath.Dir(path), "unknown"), []byte("keep"), 0600)
			case "symlink":
				os.Remove(p)
				os.Symlink(path, p)
			case "fifo":
				os.Remove(p)
				unix.Mkfifo(p, 0600)
			case "hardlink":
				os.Remove(p)
				os.Link(path, p)
			case "writable":
				os.Chmod(p, 0660)
			case "truncated":
				os.WriteFile(p, []byte("{"), 0600)
			case "duplicate-root", "escaped-duplicate", "case-duplicate", "nested-duplicate", "unknown-field", "missing-change-field":
				data, _ := os.ReadFile(p)
				text := string(data)
				switch kind {
				case "duplicate-root":
					text = strings.Replace(text, `"format": 2`, `"format": 2, "format": 2`, 1)
				case "escaped-duplicate":
					text = strings.Replace(text, `"format": 2`, `"format": 2, "for\u006dat": 2`, 1)
				case "case-duplicate":
					text = strings.Replace(text, `"format": 2`, `"format": 2, "FORMAT": 2`, 1)
				case "nested-duplicate":
					text = strings.Replace(text, `"old_exists": true`, `"old_exists": true, "old_exists": true`, 1)
				case "unknown-field":
					text = strings.Replace(text, `"format": 2`, `"format": 2, "ids": null`, 1)
				case "missing-change-field":
					text = strings.Replace(text, `"old_exists": true,`, "", 1)
				}
				if text == string(data) {
					t.Fatal("fixture not changed")
				}
				os.WriteFile(p, []byte(text), 0600)
			case "wrong-path":
				other.Changes = append([]wafConfigChange{}, tx.Changes...)
				other.Changes[0].Path = s.Config.NginxConf
				wafWriteTransaction(p, other)
			case "wrong-digest":
				other.Digests = map[string]string{}
				for k, v := range tx.Digests {
					other.Digests[k] = v
				}
				other.Digests[other.Changes[0].Path+":old"] = strings.Repeat("0", 64)
				wafWriteTransaction(p, other)
			case "archive-duplicate-id", "unsafe-archive-mode", "archive-applying", "dangling-archive":
				if err := os.Mkdir(s.apacheWAFArchiveDir(), 0700); err != nil {
					t.Fatal(err)
				}
				if kind == "unsafe-archive-mode" {
					os.Chmod(s.apacheWAFArchiveDir(), 0750)
				}
				if kind == "archive-applying" {
					other.ID = core.ID()
					other.State = "applying"
				}
				wafWriteTransaction(filepath.Join(s.apacheWAFArchiveDir(), other.ID+".json"), other)
				if kind == "dangling-archive" {
					target := filepath.Dir(path) + "-retained"
					if err := os.Rename(filepath.Dir(path), target); err != nil {
						t.Fatal(err)
					}
					path = filepath.Join(target, tx.ID+".json")
				}
			}
			if _, err := s.apacheWAFHistoryOperation(context.Background(), "transactions", core.ApacheWAFHistoryInput{Limit: 16}); err == nil {
				t.Fatal("partial/untrusted inventory accepted", kind)
			}
			if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, b)); err == nil {
				t.Fatal("untrusted inventory permitted move", kind)
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, b) {
				t.Fatal("refusal changed selected original", err)
			}
		})
	}
}

func TestApacheWAFHistory100ActiveLimitArchiveReopensExactlyOneSlot(t *testing.T) {
	s, tx, path, b := apacheHistoryFixture(t)
	for i := 1; i < apacheWAFActiveTransactions; i++ {
		copy := tx
		copy.ID = fmt.Sprintf("%032x", i)
		if copy.ID == tx.ID {
			t.Fatal("fixture collision")
		}
		if err := wafWriteTransaction(filepath.Join(filepath.Dir(path), copy.ID+".json"), copy); err != nil {
			t.Fatal(err)
		}
	}
	newTx := tx
	newTx.ID = core.ID()
	newTx.State = "applying"
	if err := s.apacheWAFReserveTransaction(context.Background(), newTx); err == nil {
		t.Fatal("full active inventory accepted another transaction")
	}
	if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, b)); err != nil {
		t.Fatal(err)
	}
	if err := s.apacheWAFReserveTransaction(context.Background(), newTx); err != nil {
		t.Fatal("archive did not free exactly one slot", err)
	}
	out := apacheHistoryReport(t, s, 96)
	if out["total"] != 100 || out["transaction_active_count"] != 99 || out["transaction_archive_count"] != 1 || out["transaction_slots_available"] != 1 || len(out["apache_transactions"].([]apacheWAFHistoryRow)) != 4 {
		t.Fatal(out)
	}
	if _, err := s.startWAFTransaction(tx.Changes); err != nil {
		t.Fatal("actual new journal admission failed after archive", err)
	}
}

func TestApacheWAFHistory512ArchiveLimitOverflowAndSameIdentityReplay(t *testing.T) {
	s, tx, path, b := apacheHistoryFixture(t)
	if err := os.Mkdir(s.apacheWAFArchiveDir(), 0700); err != nil {
		t.Fatal(err)
	}
	var first wafTransaction
	var firstBytes []byte
	for i := 0; i < apacheWAFArchivedTransactions; i++ {
		copy := tx
		copy.ID = fmt.Sprintf("%032x", i)
		p := filepath.Join(s.apacheWAFArchiveDir(), copy.ID+".json")
		if err := wafWriteTransaction(p, copy); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = copy
			firstBytes, _ = os.ReadFile(p)
		}
	}
	out := apacheHistoryReport(t, s, 512)
	if out["total"] != 513 || out["transaction_archive_ready"] != false || out["transaction_replay_ready"] != true {
		t.Fatal(out)
	}
	if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, b)); err == nil {
		t.Fatal("full archive accepted new record")
	}
	if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(first, firstBytes)); err != nil {
		t.Fatal("full archive refused original replay", err)
	}
	actual, _ := os.ReadFile(path)
	if !bytes.Equal(actual, b) {
		t.Fatal("full archive destroyed active original")
	}
	extra := tx
	extra.ID = core.ID()
	if err := wafWriteTransaction(filepath.Join(s.apacheWAFArchiveDir(), extra.ID+".json"), extra); err != nil {
		t.Fatal(err)
	}
	if _, err := s.apacheWAFHistoryOperation(context.Background(), "transactions", core.ApacheWAFHistoryInput{Limit: 16}); err == nil {
		t.Fatal("overflow returned partial statistics")
	}
}

func TestApacheWAFHistoryCancellationAndSeparateApacheLock(t *testing.T) {
	s, tx, path, b := apacheHistoryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.apacheWAFHistoryOperation(ctx, "archive-transaction", apacheArchiveInput(tx, b)); err == nil {
		t.Fatal("cancelled operation moved record")
	}
	actual, _ := os.ReadFile(path)
	if !bytes.Equal(actual, b) {
		t.Fatal("cancellation changed record")
	}
	nginx := New(s.Config)
	lock, err := nginx.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := s.apacheWAFHistoryOperation(context.Background(), "transactions", core.ApacheWAFHistoryInput{Limit: 16}); err != nil {
		t.Fatal("independent Nginx lock blocked Apache observation", err)
	}
	apache, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, b)); !errors.Is(err, errWAFConfigurationBusy) {
		t.Fatal("Apache archive bypassed configuration lock", err)
	}
	apache.Close()
}

func TestApacheWAFHistoryExecutorHTTPClosedRoutesAndReplay(t *testing.T) {
	s, tx, _, b := apacheHistoryFixture(t)
	master := New(s.Config)
	mux := master.Handler()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	base := "/v1/software/apache-waf/"
	for _, v := range []struct{ method, path, body string }{{"GET", base + "transactions?offset=%zz", ""}, {"GET", base + "transactions?limit=16&limit=16", ""}, {"POST", base + "archive-transaction?unknown=1", "{}"}, {"POST", base + "archive-transaction", "{\"limit\":0}"}} {
		w := request(v.method, v.path, v.body)
		if w.Code != 400 {
			t.Fatal("unsafe executor HTTP input", w.Code, w.Body.String())
		}
	}
	in := apacheArchiveInput(tx, b)
	body, _ := json.Marshal(in)
	for i := 0; i < 2; i++ {
		w := request("POST", base+"archive-transaction", string(body))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		if out["replayed"] != (i == 1) {
			t.Fatal("wrong replay receipt", out)
		}
	}
	w := request("GET", base+"transactions?limit=16&offset=0", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "old_data") {
		t.Fatal("public inventory leaked/private handler failed", w.Code, w.Body.String())
	}
}

type apacheHistoryCrashDescriptor struct {
	Root, Sites, Conf, State, Security, Apache, Nginx, ID, SHA string
	Cut                                                        int
}

func TestApacheWAFHistoryArchiveSIGKILLChild(t *testing.T) {
	path := os.Getenv("PANEL_QA_APACHE_HISTORY_CRASH")
	if path == "" {
		t.Skip("only the exact private subprocess crash descriptor may select this helper")
	}
	rel, err := filepath.Rel(os.TempDir(), path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.Clean(path) != path {
		t.Fatal("crash descriptor outside private temporary namespace")
	}
	data, err := apacheWAFHistoryRead(path, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	var d apacheHistoryCrashDescriptor
	if decodeFTPPrivateJSON(data, &d) != nil || d.Root != filepath.Dir(path) || d.Cut < 0 || d.Cut > 1 {
		t.Fatal("invalid private descriptor")
	}
	s := New(Config{SystemRoot: d.Root, SitesDir: d.Sites, ConfDir: d.Conf, StateDir: d.State, SecurityDir: d.Security, ApacheSiteConfig: d.Apache, NginxConf: d.Nginx}).apacheWAFTransactionService()
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	inv, err := s.apacheWAFHistoryInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Rows) != 1 || inv.Rows[0].ID != d.ID || inv.Rows[0].SHA != d.SHA || !inv.Rows[0].Archivable {
		t.Fatal("private original record changed")
	}
	if d.Cut == 1 {
		if err = os.Mkdir(s.apacheWAFArchiveDir(), 0700); err != nil {
			t.Fatal(err)
		}
		active, err := os.OpenFile(filepath.Dir(s.wafPendingPath()), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer active.Close()
		archive, err := os.OpenFile(s.apacheWAFArchiveDir(), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer archive.Close()
		if err = unix.Renameat2(int(active.Fd()), d.ID+".json", int(archive.Fd()), d.ID+".json", unix.RENAME_NOREPLACE); err != nil {
			t.Fatal(err)
		}
	}
	// An actual process death before any acknowledgment/directory-sync cleanup,
	// not a returned error, in-memory rollback, or simulated power-loss claim.
	if err = syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	t.Fatal("SIGKILL returned")
}

func TestApacheWAFHistoryActualSIGKILLBeforeAndAfterNoOverwriteRename(t *testing.T) {
	for cut := 0; cut <= 1; cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			s, tx, path, b := apacheHistoryFixture(t)
			d := apacheHistoryCrashDescriptor{Root: s.Config.SystemRoot, Sites: s.Config.SitesDir, Conf: s.Config.ConfDir, State: s.Config.StateDir, Security: s.Config.SecurityDir, Apache: s.Config.ApacheSiteConfig, Nginx: s.Config.NginxConf, ID: tx.ID, SHA: core.Hash(string(b)), Cut: cut}
			descriptor := filepath.Join(d.Root, "archive-crash-descriptor.json")
			encoded, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(descriptor, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal("cannot resolve the exact running private companion", err)
			}
			child := exec.Command(executable, "-test.run", "^TestApacheWAFHistoryArchiveSIGKILLChild$", "-test.timeout", "12s")
			child.Env = append(os.Environ(), "PANEL_QA_APACHE_HISTORY_CRASH="+descriptor)
			output, err := child.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal("child did not actually die", err, string(output))
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("not actual SIGKILL", err, string(output))
			}
			fresh := New(s.Config).apacheWAFTransactionService()
			out, err := fresh.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, b))
			if err != nil || out.(map[string]any)["replayed"] != (cut == 1) {
				t.Fatal("fresh process did not resolve exact original identity", err)
			}
			actual, err := os.ReadFile(filepath.Join(s.apacheWAFArchiveDir(), tx.ID+".json"))
			if err != nil || !bytes.Equal(actual, b) {
				t.Fatal("process death changed original backup", err)
			}
			if _, err = os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("fresh acknowledgment retained active duplicate", err)
			}
		})
	}
}

func TestApacheWAFHistoryPrivateReadRejectsOversizeAndUnsafeAncestors(t *testing.T) {
	for _, kind := range []string{"oversize-record", "special-mode", "unsafe-active-directory", "unsafe-module-directory", "module-link", "duplicate-install-version", "unknown-install-field"} {
		t.Run(kind, func(t *testing.T) {
			s, tx, path, b := apacheHistoryFixture(t)
			switch kind {
			case "oversize-record":
				f, err := os.OpenFile(filepath.Join(filepath.Dir(path), core.ID()+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				err = f.Truncate(apacheWAFRecordBytes + 1)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "special-mode":
				if err := os.Chmod(path, os.ModeSetgid|0600); err != nil {
					t.Fatal(err)
				}
			case "unsafe-active-directory":
				os.Chmod(filepath.Dir(path), 0770)
			case "unsafe-module-directory":
				os.Chmod(s.moduleDir("apache-waf"), 0770)
			case "module-link":
				module := s.moduleDir("apache-waf")
				if err := os.Rename(module, module+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(module+"-retained", module); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(module+"-retained", "config-transactions", tx.ID+".json")
			case "duplicate-install-version", "unknown-install-field":
				installed := filepath.Join(s.moduleDir("apache-waf"), "installed.json")
				raw, _ := os.ReadFile(installed)
				key := `"version": "2.3.0"`
				next := key + `, "version": "2.3.0"`
				if kind == "unknown-install-field" {
					next = key + `, "invented": true`
				}
				changed := strings.Replace(string(raw), key, next, 1)
				if changed == string(raw) {
					t.Fatal("fixture not changed")
				}
				if err := os.WriteFile(installed, []byte(changed), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.apacheWAFHistoryOperation(context.Background(), "transactions", core.ApacheWAFHistoryInput{Limit: 16}); err == nil {
				t.Fatal("unsafe private identity accepted", kind)
			}
			if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, b)); err == nil {
				t.Fatal("unsafe private identity permitted archive", kind)
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, b) {
				t.Fatal("refusal changed private original", kind, err)
			}
		})
	}
}

func TestApacheWAFHistoryByteBudgetsAreAdmissionLimitsNotPartialStatistics(t *testing.T) {
	s, tx, path, _ := apacheHistoryFixture(t)
	writePadded := func(copy wafTransaction, path string) []byte {
		t.Helper()
		data, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, bytes.Repeat([]byte(" "), int(apacheWAFRecordBytes)-len(data))...)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return data
	}
	b := writePadded(tx, path)
	for i := 1; i < 8; i++ {
		copy := tx
		copy.ID = fmt.Sprintf("%032x", i+0x1000)
		if copy.ID == tx.ID {
			t.Fatal("fixture collision")
		}
		writePadded(copy, filepath.Join(filepath.Dir(path), copy.ID+".json"))
	}
	report := apacheHistoryReport(t, s, 0)
	if report["transaction_active_bytes"] != apacheWAFActiveBytes || report["transaction_active_count"] != 8 || report["transaction_slots_available"] != 92 {
		t.Fatal("byte budget inventory", report)
	}
	newTx := tx
	newTx.ID = core.ID()
	newTx.State = "applying"
	if err := s.apacheWAFReserveTransaction(context.Background(), newTx); err == nil {
		t.Fatal("byte-full active inventory permitted another journal")
	}
	if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, b)); err != nil {
		t.Fatal(err)
	}
	if err := s.apacheWAFReserveTransaction(context.Background(), newTx); err != nil {
		t.Fatal("byte-capacity archive did not free admission", err)
	}
	for i := 0; i < 15; i++ {
		copy := tx
		copy.ID = fmt.Sprintf("%032x", i+0x2000)
		writePadded(copy, filepath.Join(s.apacheWAFArchiveDir(), copy.ID+".json"))
	}
	report = apacheHistoryReport(t, s, 0)
	if report["transaction_archive_bytes"] != apacheWAFArchiveBytes || report["transaction_archive_count"] != 16 || report["transaction_archive_ready"] != false || report["transaction_replay_ready"] != true {
		t.Fatal("exact full byte budget", report)
	}
	if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, b)); err != nil {
		t.Fatal("byte-full archive cannot acknowledge original ID", err)
	}
	copy := tx
	copy.ID = core.ID()
	if err := wafWriteTransaction(filepath.Join(s.apacheWAFArchiveDir(), copy.ID+".json"), copy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.apacheWAFHistoryOperation(context.Background(), "transactions", core.ApacheWAFHistoryInput{Limit: 16}); err == nil {
		t.Fatal("byte overflow returned partial inventory")
	}
}

func TestApacheWAFHistoryWrongOwnerRefusesWithoutTakingOver(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact private root/CHOWN ownership fixture is separately selected")
	}
	for _, kind := range []string{"record", "active-directory", "archive-directory", "module-directory", "installed-record"} {
		t.Run(kind, func(t *testing.T) {
			s, tx, path, b := apacheHistoryFixture(t)
			target := path
			switch kind {
			case "active-directory":
				target = filepath.Dir(path)
			case "archive-directory":
				target = s.apacheWAFArchiveDir()
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			case "module-directory":
				target = s.moduleDir("apache-waf")
			case "installed-record":
				target = filepath.Join(s.moduleDir("apache-waf"), "installed.json")
			}
			before, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			original := before.Sys().(*syscall.Stat_t)
			if err = os.Chown(target, 501, int(original.Gid)); err != nil {
				t.Fatal("explicit ownership fixture requires CHOWN", err)
			}
			if _, err := s.apacheWAFHistoryOperation(context.Background(), "transactions", core.ApacheWAFHistoryInput{Limit: 16}); err == nil {
				t.Fatal("foreign owner accepted", kind)
			}
			if _, err := s.apacheWAFHistoryOperation(context.Background(), "archive-transaction", apacheArchiveInput(tx, b)); err == nil {
				t.Fatal("foreign owner allowed archive", kind)
			}
			current, err := os.Stat(target)
			if err != nil || current.Sys().(*syscall.Stat_t).Uid != 501 {
				t.Fatal("production maintenance took over foreign ownership", err)
			}
			// Restore only this private test fixture's own intentional foreign owner
			// so the byte-retention assertion and Go temporary cleanup can proceed.
			if err = os.Chown(target, int(original.Uid), int(original.Gid)); err != nil {
				t.Fatal(err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, b) {
				t.Fatal("refusal changed original backup bytes", err)
			}
		})
	}
}

func TestApacheWAFHistoryLegacyBackupNamespaceIsRetainedAndNeverCountsAsNewJournal(t *testing.T) {
	s, tx, _, _ := apacheHistoryFixture(t)
	legacy := filepath.Join(s.moduleDir("apache-waf"), "config-backups")
	if err := os.Mkdir(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		name := filepath.Join(legacy, fmt.Sprintf("%032x", i))
		if err := os.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(name, "index.json"), []byte(fmt.Sprint("original legacy evidence ", i)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.startWAFTransaction(tx.Changes); err != nil {
		t.Fatal("old full backup namespace blocked new complete journal", err)
	}
	entries, err := os.ReadDir(legacy)
	if err != nil || len(entries) != 100 {
		t.Fatal("old backup namespace changed", err)
	}
	for i := 0; i < 100; i++ {
		actual, err := os.ReadFile(filepath.Join(legacy, fmt.Sprintf("%032x", i), "index.json"))
		if err != nil || string(actual) != fmt.Sprint("original legacy evidence ", i) {
			t.Fatal("legacy evidence removed or changed", i, err)
		}
	}
}
