//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestApacheNumericLogPrivateDirectoryDurabilityBeforeMutation(t *testing.T) {
	s, live, original := apacheNumericLogFixture(t)
	path := s.apacheNumericLogArchiveDirectory()
	parent := filepath.Dir(path)
	var calls []string
	fault := errors.New("owned parent fsync failure")
	sync := func(value string) error {
		calls = append(calls, value)
		if value == parent {
			return fault
		}
		return nil
	}
	if err := s.apacheNumericLogPrivateDirectoryAt(path, false, sync); !errors.Is(err, os.ErrNotExist) || len(calls) != 0 {
		t.Fatal("read fence created or synced absent state", err, calls)
	}
	if err := s.apacheNumericLogPrivateDirectoryAt(path, true, sync); !errors.Is(err, fault) || !reflect.DeepEqual(calls, []string{path, parent}) {
		t.Fatal("parent name was not committed before permission to mutate", err, calls)
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode().Perm() != 0700 {
		t.Fatal("failed durability state was removed or repaired", err)
	}
	raw, _ := os.ReadFile(live)
	if string(raw) != string(original) {
		t.Fatal("directory admission changed live data")
	}
	calls = nil
	if err := s.apacheNumericLogPrivateDirectoryAt(path, false, sync); err != nil || len(calls) != 0 {
		t.Fatal("read fence attempted durability repair", err, calls)
	}
	// A preexisting leaf may be the residue of the failed parent sync. Every
	// explicit write admission must resync both; mere existence proves nothing.
	if err := s.apacheNumericLogPrivateDirectoryAt(path, true, func(value string) error {
		calls = append(calls, value)
		return apacheNumericLogSyncDirectory(value)
	}); err != nil || !reflect.DeepEqual(calls, []string{path, parent}) {
		t.Fatal("existing directory skipped parent durability", err, calls)
	}
	after, _ := os.Lstat(path)
	if !os.SameFile(before, after) {
		t.Fatal("existing failed directory was replaced")
	}
	if err := s.apacheNumericLogPrivateDirectoryAt(path, true, nil); err == nil {
		t.Fatal("missing actual durability step admitted")
	}
	missingParent := filepath.Join(parent, "must-not-create", "archives")
	if err := s.apacheNumericLogPrivateDirectoryAt(missingParent, true, sync); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unknown parent was recursively created", err)
	}
	if _, err := os.Lstat(filepath.Dir(missingParent)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing native parent was provisioned by maintenance", err)
	}
	if err := os.Chmod(path, 0750); err != nil {
		t.Fatal(err)
	}
	calls = nil
	if err := s.apacheNumericLogPrivateDirectoryAt(path, true, sync); err == nil || len(calls) != 0 {
		t.Fatal("foreign permissions were repaired or synced", err, calls)
	}
}

func TestApacheNumericLogRetainedEvidenceDataSyncAndIdentity(t *testing.T) {
	for _, kind := range []string{"snapshot", "index-stage"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _ := apacheNumericLogFixture(t)
			directory, suffix := s.apacheNumericLogArchiveDirectory(), ".log"
			if kind == "index-stage" {
				directory, suffix = s.apacheNumericLogIndexDirectory(), ".json"
			}
			if err := s.apacheNumericLogPrivateDirectory(directory, true); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, strings.Repeat("a", 32)+suffix)
			data := []byte("exact interrupted private evidence")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			want := hex.EncodeToString(digest[:])
			before, _ := os.Lstat(path)
			calls := 0
			fault := errors.New("owned evidence fsync failure")
			if err := s.syncApacheNumericLogEvidenceAt(context.Background(), path, want, func(*os.File) error {
				calls++
				return fault
			}); !errors.Is(err, fault) || calls != 1 {
				t.Fatal("file durability failure was ignored", err, calls)
			}
			if err := s.syncApacheNumericLogEvidence(context.Background(), path, want); err != nil {
				t.Fatal("actual original inode fsync failed", err)
			}
			after, _ := os.Lstat(path)
			raw, _ := os.ReadFile(path)
			if !os.SameFile(before, after) || string(raw) != string(data) {
				t.Fatal("durability admission rewrote evidence")
			}
			if err := s.syncApacheNumericLogEvidence(context.Background(), path, strings.Repeat("0", 64)); err == nil {
				t.Fatal("foreign observed digest accepted")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			calls = 0
			if err := s.syncApacheNumericLogEvidenceAt(ctx, path, want, func(*os.File) error { calls++; return nil }); !errors.Is(err, context.Canceled) || calls != 0 {
				t.Fatal("cancelled admission flushed evidence", err, calls)
			}
			if err := s.syncApacheNumericLogEvidenceAt(context.Background(), path, want, func(f *os.File) error {
				if err := f.Sync(); err != nil {
					return err
				}
				if err := os.Rename(path, path+".original"); err != nil {
					return err
				}
				return os.WriteFile(path, data, 0600)
			}); err == nil {
				t.Fatal("same-byte path substitution accepted")
			}
		})
	}
}

func TestApacheNumericLogPreparedDeletionCannotEraseUnknownEvidence(t *testing.T) {
	for _, cut := range []string{"prepared-durable", "truncate-durable"} {
		t.Run(cut, func(t *testing.T) {
			s, live, _ := apacheNumericLogFixture(t)
			entry, err := s.snapshotAndTruncateApacheNumericLogAt(context.Background(), func(stage string) error {
				if stage == cut {
					return errors.New("owned unknown rotation result")
				}
				return nil
			})
			if err == nil || entry.State != "prepared" {
				t.Fatal("unknown boundary not reached", err, entry)
			}
			before, beforeSHA, err := s.readApacheNumericLogIndex(entry.ID)
			if err != nil {
				t.Fatal(err)
			}
			liveBefore, _ := os.ReadFile(live)
			copyPath := filepath.Join(s.apacheNumericLogArchiveDirectory(), entry.ID+".log")
			copyBefore, _ := os.Lstat(copyPath)
			if err := s.removeApacheNumericLogArchive(context.Background(), entry.ID, entry.SHA256); err == nil || !strings.Contains(err.Error(), "尚未确认") {
				t.Fatal("direct deletion bypassed unknown-result retention", err)
			}
			after, afterSHA, err := s.readApacheNumericLogIndex(entry.ID)
			copyAfter, _ := os.Lstat(copyPath)
			liveAfter, _ := os.ReadFile(live)
			if err != nil || before != after || beforeSHA != afterSHA || !os.SameFile(copyBefore, copyAfter) || string(liveBefore) != string(liveAfter) {
				t.Fatal("refused deletion changed original intent, copy or current log", err)
			}
			pending, err := s.apacheNumericLogRecoveryEntries(context.Background())
			if err != nil || len(pending) != 1 || pending[0].Archive.ID != entry.ID {
				t.Fatal("original unknown barrier lost", err, pending)
			}
		})
	}
}

func apacheNumericLogFixture(t *testing.T) (*Service, string, []byte) {
	t.Helper()
	root := t.TempDir()
	s := New(Config{SystemRoot: root, SecurityDir: filepath.Join(root, "etc/panel/security-apps"), SitesDir: filepath.Join(root, "srv/panel/sites")}).apacheNumericLogService()
	for _, dir := range []string{s.Config.SecurityDir, s.systemPath(apacheBodyMetadataDirectory)} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// The native test unit deliberately uses umask 0077. Provision only this
	// newly created private fixture leaf with the actual fixed 0755 contract.
	if err := os.Chmod(s.systemPath(apacheBodyMetadataDirectory), 0755); err != nil {
		t.Fatal(err)
	}
	path := s.systemPath(apacheBodyMetadataLog)
	data := []byte(apacheBodyNumericEventFixture() + "\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return s, path, data
}
func TestApacheNumericLogSameInodeAndBSDWriterExclusion(t *testing.T) {
	s, path, data := apacheNumericLogFixture(t)
	before, _ := os.Stat(path)
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(writer.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := s.snapshotAndTruncateApacheNumericLog(context.Background()); err == nil || !strings.Contains(err.Error(), "正在写入") {
		t.Fatal("Apache BSD writer lock exclusion not reached", err)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != string(data) {
		t.Fatal("busy writer data truncated")
	}
	writer.Close()
	entry, err := s.snapshotAndTruncateApacheNumericLog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	after, _ := os.Stat(path)
	if entry.State != "completed" || entry.Bytes != int64(len(data)) || entry.SHA256 != hex.EncodeToString(sum[:]) || after.Size() != 0 || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		t.Fatal("rotation did not retain exact inode/data", entry)
	}
	original, err := os.ReadFile(filepath.Join(s.apacheNumericLogArchiveDirectory(), entry.ID+".log"))
	if err != nil || string(original) != string(data) {
		t.Fatal("snapshot bytes changed", err)
	}
	index, indexSHA, err := s.readApacheNumericLogIndex(entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.exportApacheNumericLogArchive(context.Background(), index, indexSHA)
	if err != nil || out["selected_snapshot_digest_verified"] != true {
		t.Fatal("numeric-only selected export", out, err)
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.verifyApacheNumericLock(lock); err != nil {
		t.Fatal(err)
	}
	lock.Close()
	unlocked, err := os.OpenFile(filepath.Join(s.moduleDir("apache-waf"), "waf-configuration.lock"), os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.verifyApacheNumericLock(unlocked); err == nil {
		t.Fatal("unowned descriptor accepted as an exclusive lock")
	}
	unlocked.Close()
}
func TestApacheNumericLogSixInterruptionsDoNotRepeatTruncate(t *testing.T) {
	for _, cut := range []string{"intent-durable", "snapshot-created", "snapshot-durable", "prepared-durable", "truncate-durable", "completed-durable"} {
		t.Run(cut, func(t *testing.T) {
			s, path, data := apacheNumericLogFixture(t)
			hit := false
			entry, err := s.snapshotAndTruncateApacheNumericLogAt(context.Background(), func(stage string) error {
				if stage == cut {
					hit = true
					return errors.New("owned interruption")
				}
				return nil
			})
			if err == nil || !hit {
				t.Fatal("failure seam not reached", cut, err)
			}
			before, _ := os.ReadFile(path)
			truncated := cut == "truncate-durable" || cut == "completed-durable"
			if truncated && len(before) != 0 || !truncated && string(before) != string(data) {
				t.Fatal("early data loss", cut)
			}
			fresh := New(s.Config).apacheNumericLogService()
			pending, err := fresh.apacheNumericLogRecoveryEntries(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if cut == "completed-durable" {
				if len(pending) != 0 {
					t.Fatal("completed record fabricated as pending")
				}
			} else {
				if len(pending) != 1 || pending[0].Archive.ID != entry.ID {
					t.Fatal("original pending intent missing", pending)
				}
				wrong := pending[0]
				wrong.IndexSHA = strings.Repeat("0", 64)
				if err := fresh.retainApacheNumericLogSnapshot(context.Background(), wrong); err == nil {
					t.Fatal("stale digest allowed")
				}
				if err := fresh.retainApacheNumericLogSnapshot(context.Background(), pending[0]); err != nil {
					t.Fatal(err)
				}
				rows, err := fresh.apacheNumericLogArchives()
				if err != nil || len(rows) != 1 || rows[0].State == "completed" {
					t.Fatal("unknown result relabelled successful", rows, err)
				}
				if err := fresh.retainApacheNumericLogSnapshot(context.Background(), pending[0]); err == nil {
					t.Fatal("old unknown selection replayed")
				}
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(before) {
				t.Fatal("evidence review changed active log")
			}
		})
	}
}
func TestApacheNumericLogIndexInterruptionsPreserveExactStage(t *testing.T) {
	for _, cut := range []string{"intent-index-stage-created", "intent-index-stage-written", "intent-index-stage-durable"} {
		t.Run(cut, func(t *testing.T) {
			s, path, data := apacheNumericLogFixture(t)
			hit := false
			_, err := s.snapshotAndTruncateApacheNumericLogAt(context.Background(), func(stage string) error {
				if stage == cut {
					hit = true
					return errors.New("owned stage interruption")
				}
				return nil
			})
			if err == nil || !hit {
				t.Fatal("stage fault not reached", err)
			}
			stages, err := s.apacheNumericLogIndexStages(context.Background())
			if err != nil || len(stages) != 1 {
				t.Fatal("stage not retained", stages, err)
			}
			old := filepath.Join(s.apacheNumericLogIndexDirectory(), stages[0].ID+".json")
			st, _ := os.Stat(old)
			if _, err := s.retainApacheNumericLogIndexStage(context.Background(), stages[0].ID, strings.Repeat("0", 64)); err == nil {
				t.Fatal("stale stage digest accepted")
			}
			retained, err := s.retainApacheNumericLogIndexStage(context.Background(), stages[0].ID, stages[0].SHA256)
			if err != nil {
				t.Fatal(err)
			}
			newPath := s.systemPath("/var/lib/panel-apache-body/retained-index-staging/" + retained + ".json")
			after, err := os.Stat(newPath)
			if err != nil || !os.SameFile(st, after) {
				t.Fatal("stage inode not preserved", err)
			}
			raw, _ := os.ReadFile(path)
			if string(raw) != string(data) {
				t.Fatal("stage preservation touched current data")
			}
		})
	}
}
func TestApacheNumericLogMalformedPrivacyAndCapacity(t *testing.T) {
	for _, bad := range []string{strings.TrimSuffix(apacheBodyNumericEventFixture()+"\n", "\n"), strings.TrimSuffix(apacheBodyNumericEventFixture(), "}") + `,"cookie":"private-value"}` + "\n", `{"time_us":1,"engine":"2.9.15-yz5","site_id":"a","mode":"block"}` + "\n"} {
		s, path, _ := apacheNumericLogFixture(t)
		os.WriteFile(path, []byte(bad), 0600)
		if _, err := s.snapshotAndTruncateApacheNumericLog(context.Background()); err == nil {
			t.Fatal("partial/private malformed line archived")
		}
		raw, _ := os.ReadFile(path)
		if string(raw) != bad {
			t.Fatal("rejected original modified")
		}
	}
	s, path, data := apacheNumericLogFixture(t)
	for i := 0; i < 8; i++ {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.snapshotAndTruncateApacheNumericLog(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(path, data, 0600)
	if _, err := s.snapshotAndTruncateApacheNumericLog(context.Background()); err == nil {
		t.Fatal("ninth snapshot silently evicted old evidence")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != string(data) {
		t.Fatal("full quota truncated source")
	}
}
