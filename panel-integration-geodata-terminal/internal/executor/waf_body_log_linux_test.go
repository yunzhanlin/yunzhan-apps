//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

func TestWAFBodyLogSixCutpointsReconstructWithoutDoubleTruncateOrFalseSuccess(t *testing.T) {
	for _, cut := range []string{"intent-durable", "snapshot-created", "snapshot-durable", "prepared-durable", "truncate-durable", "completed-durable"} {
		t.Run(cut, func(t *testing.T) {
			s, path, data := wafBodyLogFixture(t)
			hit := false
			entry, err := s.snapshotAndTruncateWAFBodyLogAt(context.Background(), func(at string) error {
				if at == cut {
					hit = true
					return errors.New("owned cutpoint interruption")
				}
				return nil
			})
			if err == nil || !hit || !core.ValidID(entry.ID) {
				t.Fatal("cutpoint not reached", entry, err)
			}
			before, _ := os.ReadFile(path)
			if cut == "truncate-durable" || cut == "completed-durable" {
				if len(before) != 0 {
					t.Fatal("truncate not durable")
				}
			} else if string(before) != string(data) {
				t.Fatal("early interruption discarded live data")
			}
			fresh := New(s.Config)
			pending, err := fresh.wafBodyLogRecoveryEntries(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if cut == "completed-durable" {
				if len(pending) != 0 {
					t.Fatal("completed rotation fabricated as unknown", pending)
				}
			} else {
				if len(pending) != 1 || pending[0].Archive.ID != entry.ID {
					t.Fatal("durable intent not reconstructed", pending)
				}
				selected := pending[0]
				bad := selected
				bad.IndexSHA = strings.Repeat("0", 64)
				if err := fresh.retainWAFBodyLogSnapshot(context.Background(), bad); err == nil {
					t.Fatal("stale recovery digest trusted")
				}
				if err := fresh.retainWAFBodyLogSnapshot(context.Background(), selected); err != nil {
					t.Fatal(err)
				}
				entries, err := fresh.wafBodyLogArchives()
				if err != nil || len(entries) != 1 || entries[0].State == "completed" {
					t.Fatal("unknown recovery marked successful", entries, err)
				}
				if err := fresh.retainWAFBodyLogSnapshot(context.Background(), selected); err == nil {
					t.Fatal("stale uncertain recovery replay accepted")
				}
				w := httptest.NewRecorder()
				fresh.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/nginx-waf/body-log/archives/"+entry.ID, nil))
				if w.Code != 200 || strings.Contains(w.Body.String(), "private") {
					t.Fatal("retained snapshot export", w.Code, w.Body.String())
				}
				if cut == "intent-durable" && !strings.Contains(w.Body.String(), `"available":false`) {
					t.Fatal("missing snapshot shown as available zero")
				}
				if err := fresh.removeWAFBodyLogArchive(context.Background(), entry.ID, entries[0].SHA256); err != nil {
					t.Fatal("retained evidence cannot be explicitly managed", err)
				}
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(before) {
				t.Fatal("recovery/deletion double truncated or changed live log")
			}
		})
	}
}

func TestWAFBodyLogInterruptedDeletionRetriesExactDigestOnly(t *testing.T) {
	for _, cut := range []string{"remove-intent-durable", "snapshot-unlink-durable"} {
		t.Run(cut, func(t *testing.T) {
			s, path, data := wafBodyLogFixture(t)
			entry, err := s.snapshotAndTruncateWAFBodyLog(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			os.WriteFile(path, data, 0640)
			if err := s.removeWAFBodyLogArchiveAt(context.Background(), entry.ID, entry.SHA256, func(at string) error {
				if at == cut {
					return errors.New("owned delete interruption")
				}
				return nil
			}); err == nil {
				t.Fatal("deletion cutpoint not injected")
			}
			fresh := New(s.Config)
			pending, err := fresh.wafBodyLogRecoveryEntries(context.Background())
			if err != nil || len(pending) != 1 || pending[0].Archive.State != "removing" {
				t.Fatal(pending, err)
			}
			if err := fresh.retainWAFBodyLogSnapshot(context.Background(), pending[0]); err == nil {
				t.Fatal("deleting snapshot reclassified as a successful backup")
			}
			if err := fresh.removeWAFBodyLogArchive(context.Background(), entry.ID, strings.Repeat("0", 64)); err == nil {
				t.Fatal("different digest resumed deletion")
			}
			if err := fresh.removeWAFBodyLogArchive(context.Background(), entry.ID, entry.SHA256); err != nil {
				t.Fatal(err)
			}
			entries, err := fresh.wafBodyLogArchives()
			if err != nil || len(entries) != 0 {
				t.Fatal(entries, err)
			}
			actual, _ := os.ReadFile(path)
			if string(actual) != string(data) {
				t.Fatal("retry deleted current log")
			}
		})
	}
}

func TestWAFBodyLogRecoveryHTTPClosedInputsAndRetainedEvidence(t *testing.T) {
	s, path, data := wafBodyLogFixture(t)
	entry, _ := s.snapshotAndTruncateWAFBodyLogAt(context.Background(), func(stage string) error {
		if stage == "snapshot-created" {
			return errors.New("fixture incomplete copy")
		}
		return nil
	})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/nginx-waf/body-log/archives", nil))
	var inventory struct {
		Recovery []wafBodyLogRecovery `json:"recovery_entries"`
		Warning  string               `json:"inventory_warning"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &inventory) != nil || len(inventory.Recovery) != 1 || inventory.Warning == "" {
		t.Fatal("safe incomplete inventory not visible", w.Code, w.Body.String())
	}
	selected := inventory.Recovery[0]
	in := core.WAFBodyLogRetainRequest{IndexSHA256: selected.IndexSHA, SnapshotSHA256: selected.SnapshotSHA, SnapshotMissing: selected.SnapshotMissing, Acknowledged: true}
	body, _ := json.Marshal(in)
	target := "/v1/software/nginx-waf/body-log/archives/" + entry.ID + "/retain"
	for _, bad := range []string{`{}`, strings.Replace(string(body), `incomplete_snapshot":true`, `incomplete_snapshot":false`, 1), strings.TrimSuffix(string(body), "}") + `,"path":"/private"}`, string(body) + ` {}`} {
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", target, strings.NewReader(bad)))
		if w.Code != 400 {
			t.Fatal("unclosed recovery", w.Code, w.Body.String())
		}
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("POST", target, strings.NewReader(string(body))))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "unknown_not_marked_successful") {
		t.Fatal(w.Code, w.Body.String())
	}
	actual, _ := os.ReadFile(path)
	if string(actual) != string(data) {
		t.Fatal("HTTP recovery changed active log")
	}
}

func wafBodyLogFixture(t *testing.T) (*Service, string, []byte) {
	t.Helper()
	s := wafPolicyFixture(t)
	if err := s.prepareWAFBodyLog(); err != nil {
		t.Fatal(err)
	}
	path := s.systemPath(wafBodyLogPath)
	data := []byte("2026/10/08 01:00:00 [warn] 123#123: yunzhan_waf_body rule=941100 phase=2 severity=2 disruptive=1 site=" + strings.Repeat("a", 32) + "\n")
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	return s, path, data
}

func TestWAFBodyLogRotationRetainsExactSnapshotSameInodeAndPrivacy(t *testing.T) {
	s, path, data := wafBodyLogFixture(t)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.snapshotAndTruncateWAFBodyLog(context.Background())
	if err != nil || result.State != "completed" || result.Bytes != int64(len(data)) {
		t.Fatal(result, err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || after.Size() != 0 || after.Mode().Perm() != 0640 {
		t.Fatal("native writer descriptor/path identity lost", after, err)
	}
	archive, err := s.openWAFBodyLogArchive(result.ID)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := io.ReadAll(archive)
	archive.Close()
	sha := sha256.Sum256(data)
	if err != nil || string(bytes) != string(data) || result.SHA256 != hex.EncodeToString(sha[:]) {
		t.Fatal("retained exact numerical snapshot", err)
	}
	entries, err := s.wafBodyLogArchives()
	if err != nil || len(entries) != 1 || entries[0] != result {
		t.Fatal(entries, err)
	}
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	page, err := s.readWAFBodyEvents()
	if err != nil || len(page.Events) != 1 || !page.BestEffort || page.LegacyLog || page.MaxBytes != wafBodyLogLimit {
		t.Fatal(page, err)
	}
	if err := os.Chmod(filepath.Join(s.wafBodyLogArchiveDirectory(), result.ID+".json"), 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := s.wafBodyLogArchives(); err == nil {
		t.Fatal("writable snapshot index trusted")
	}
	if err := s.removeWAFBodyLogArchive(context.Background(), result.ID, result.SHA256); err == nil {
		t.Fatal("writable snapshot allowed deletion")
	}
	os.Chmod(filepath.Join(s.wafBodyLogArchiveDirectory(), result.ID+".json"), 0600)
	if err := s.removeWAFBodyLogArchive(context.Background(), result.ID, strings.Repeat("0", 64)); err == nil {
		t.Fatal("unmatched snapshot digest removed")
	}
	if err := s.removeWAFBodyLogArchive(context.Background(), result.ID, result.SHA256); err != nil {
		t.Fatal(err)
	}
	entries, err = s.wafBodyLogArchives()
	if err != nil || len(entries) != 0 {
		t.Fatal("snapshot quota not released", entries, err)
	}
	current, err := os.ReadFile(path)
	if err != nil || string(current) != string(data) {
		t.Fatal("snapshot removal touched current log", err)
	}
}

func TestWAFBodyLogRotationFailsClosedAndKeepsLiveData(t *testing.T) {
	for _, name := range []string{"writable", "symlink", "hardlink", "canceled", "private-content", "oversize", "unknown-archive", "quota", "incomplete-snapshot"} {
		t.Run(name, func(t *testing.T) {
			s, path, data := wafBodyLogFixture(t)
			ctx := context.Background()
			switch name {
			case "writable":
				os.Chmod(path, 0666)
			case "symlink":
				target := path + ".retained"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "private-content":
				data = append(data, []byte("secret Cookie=private\n")...)
				os.WriteFile(path, data, 0640)
			case "oversize":
				f, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				f.Truncate(wafBodyLogLimit + 1)
				f.Close()
			case "unknown-archive":
				directory := s.wafBodyLogArchiveDirectory()
				os.Mkdir(directory, 0700)
				os.WriteFile(filepath.Join(directory, "foreign.log"), data, 0600)
			case "quota", "incomplete-snapshot":
				directory := s.wafBodyLogArchiveDirectory()
				os.Mkdir(directory, 0700)
				count := wafBodyLogArchiveLimit
				if name == "incomplete-snapshot" {
					count = 1
				}
				for i := 0; i < count; i++ {
					id := core.ID()
					sha := sha256.Sum256(data)
					entry := wafBodyLogArchive{ID: id, CapturedAt: core.Now(), Bytes: int64(len(data)), SHA256: hex.EncodeToString(sha[:]), State: "completed"}
					if name == "incomplete-snapshot" {
						entry.State = "prepared"
					}
					os.WriteFile(filepath.Join(directory, id+".log"), data, 0600)
					moduleWrite(filepath.Join(directory, id+".json"), entry)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.snapshotAndTruncateWAFBodyLog(ctx); err == nil {
				t.Fatal("unsafe rotation accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(before) != string(after) {
				t.Fatal("failure discarded live evidence", err)
			}
		})
	}
}

func TestWAFBodyLogPOSIXLockHelper(t *testing.T) {
	path := os.Getenv("PANEL_WAF_LOG_LOCK_FIXTURE")
	if path == "" {
		t.Skip("private subprocess fixture")
	}
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fl := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart}
	if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &fl); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".lock-held", []byte("owned-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, err := os.Stat(path + ".release"); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture lock release timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWAFBodyLogCrossProcessWriterLockPreservesData(t *testing.T) {
	s, path, data := wafBodyLogFixture(t)
	cmd := exec.Command(os.Args[0], "-test.run", "^TestWAFBodyLogPOSIXLockHelper$", "-test.timeout", "10s")
	cmd.Env = append(os.Environ(), "PANEL_WAF_LOG_LOCK_FIXTURE="+path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.WriteFile(path+".release", nil, 0600)
		if err := cmd.Wait(); err != nil {
			t.Error(err)
		}
	}()
	for deadline := time.Now().Add(3 * time.Second); ; {
		if _, err := os.Stat(path + ".lock-held"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lock child did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := s.snapshotAndTruncateWAFBodyLog(context.Background()); err == nil {
		t.Fatal("contended native POSIX writer lock ignored")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(data) {
		t.Fatal("contended rotation changed evidence")
	}
}

func TestWAFBodyLogCapAndParentContract(t *testing.T) {
	s, path, _ := wafBodyLogFixture(t)
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(wafBodyLogLimit)
	f.Close()
	page, err := s.readWAFBodyEvents()
	if err != nil || !page.CapacityExhausted || !page.Partial || page.LogBytes != wafBodyLogLimit || !page.BestEffort {
		t.Fatal(page, err)
	}
	os.Chmod(filepath.Dir(path), 0777)
	if _, err := s.readWAFBodyEvents(); err == nil {
		t.Fatal("writable log parent trusted")
	}
	if err := s.prepareWAFBodyLog(); err == nil {
		t.Fatal("foreign writable directory silently repaired")
	}
}
