//go:build linux

package executor

import (
	"bytes"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRemoteIndependentRootPrivateCopyNamespace(t *testing.T) {
	if selected := os.Getenv("PANEL_INDEPENDENT_ROOT_READ_CHILD"); selected != "" {
		if os.Geteuid() != 33 || !filepath.IsAbs(selected) || !strings.Contains(selected, "TestRemoteIndependentRootPrivateCopyNamespace") {
			t.Fatal("not owned UID33 fixture")
		}
		if f, err := os.Open(selected); err == nil {
			f.Close()
			t.Fatal("UID33 could read Root private copy")
		} else if !errors.Is(err, os.ErrPermission) {
			t.Fatal(err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("Root-owned private namespace fixture requires Linux Root; unprivileged SFTP fixture is separate")
	}
	s, _, _ := appReliabilityFixture(t)
	tx, attempt := core.ID(), core.ID()
	d, err := s.remoteCopyDirectory("owned-target", tx, attempt, true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	f, err := d.OpenFile("staged", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("Root private original")); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := d.Lstat("staged")
	if err != nil {
		t.Fatal(err)
	}
	v := info.Sys().(*syscall.Stat_t)
	if v.Uid != 0 || v.Nlink != 1 || info.Mode().Perm() != 0600 {
		t.Fatal("not actual Root private independent file", info)
	}
	for _, name := range d.paths[1:] {
		z, err := os.Lstat(name)
		if err != nil || z.Sys().(*syscall.Stat_t).Uid != 0 || !z.IsDir() || z.Mode().Perm()&0022 != 0 {
			t.Fatal("private ancestor widened", name, err)
		}
	}
	path := filepath.Join(d.paths[len(d.paths)-1], "staged")
	// The actual test executable can itself live below a Root0700 QA anchor.
	// Pass only a read-only, executable code inode; do not widen any private
	// directory or pass a handle to the backup/data namespace to UID33.
	program, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer program.Close()
	codePath := filepath.Join(t.TempDir(), "owned-test-code")
	code, err := os.OpenFile(codePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(code, program)
	closeErr := code.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal(copyErr, closeErr)
	}
	if err = os.Chmod(codePath, 0555); err != nil {
		t.Fatal(err)
	}
	readOnlyCode, err := os.Open(codePath)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnlyCode.Close()
	child := exec.Command("/proc/self/fd/3", "-test.run=^TestRemoteIndependentRootPrivateCopyNamespace$", "-test.v")
	child.ExtraFiles = []*os.File{readOnlyCode}
	child.Env = append(os.Environ(), "PANEL_INDEPENDENT_ROOT_READ_CHILD="+path)
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 33, Gid: 33, Groups: []uint32{}}}
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatal("actual UID33 child did not deny private read", err, string(output))
	}
	t.Log("actual_Root_private_uid=0 actual_private_mode=0600 actual_UID33_private_read=EACCES")
}

func TestRemoteIndependentRootMetadataNoClobberAndDetachedParents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native Root filesystem fixture")
	}
	s, _, _ := appReliabilityFixture(t)
	tx := core.ID()
	d, err := s.remoteCopyDirectory("owned-target", tx, "", true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	original := remoteCopyAttempt{Format: 1, ID: core.ID(), IntentSHA: core.Hash("original intent"), CreatedAt: core.Now()}
	raw, err := remoteCopyPublish(d, "intent.json", original)
	if err != nil {
		t.Fatal(err)
	}
	before, err := d.Lstat("intent.json")
	if err != nil {
		t.Fatal(err)
	}
	changed := original
	changed.IntentSHA = core.Hash("replacement")
	if _, err = remoteCopyPublish(d, "intent.json", changed); err == nil {
		t.Fatal("immutable original record overwritten")
	}
	var actual remoteCopyAttempt
	afterRaw, err := remoteCopyMetadata(d, "intent.json", &actual)
	after, statErr := d.Lstat("intent.json")
	if err != nil || statErr != nil || !bytes.Equal(raw, afterRaw) || !os.SameFile(before, after) || actual != original {
		t.Fatal("no-clobber refusal changed original", err, statErr)
	}
	named := d.paths[len(d.paths)-1]
	preserved := named + ".original-preserved"
	outside := t.TempDir()
	if err = os.Rename(named, preserved); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, named); err != nil {
		t.Fatal(err)
	}
	if _, err = remoteCopyPublish(d, "result.json", original); err == nil {
		t.Fatal("detached held directory accepted")
	}
	if _, err = os.Lstat(filepath.Join(outside, "result.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("outside symlink was followed", err)
	}
	b, err := os.ReadFile(filepath.Join(preserved, "intent.json"))
	if err != nil || !bytes.Equal(b, raw) {
		t.Fatal("original detached data lost", err)
	}
}

func TestRemoteIndependentRootRejectsLinksForeignOwnersAndPublicRecords(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native Root ownership fixture")
	}
	for _, kind := range []string{"symlink", "hardlink", "foreign-owner", "public-mode"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _ := appReliabilityFixture(t)
			d, err := s.remoteCopyDirectory("owned-target", core.ID(), "", true)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			outside := filepath.Join(t.TempDir(), "original")
			content := []byte("preserved original")
			if err = os.WriteFile(outside, content, 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(d.paths[len(d.paths)-1], "intent.json")
			switch kind {
			case "symlink":
				err = os.Symlink(outside, path)
			case "hardlink":
				err = os.Link(outside, path)
			default:
				err = os.WriteFile(path, []byte("{\"format\":1}\n"), 0600)
				if err == nil {
					if kind == "foreign-owner" {
						err = os.Chown(path, 33, 33)
					} else {
						err = os.Chmod(path, 0644)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before, _ := os.Lstat(path)
			var value remoteCopyAttempt
			if _, err = remoteCopyMetadata(d, "intent.json", &value); err == nil {
				t.Fatal("unsafe Root metadata accepted")
			}
			after, _ := os.Lstat(path)
			if !programQueueSame(before, after) {
				t.Fatal("rejection repaired original ownership or permissions")
			}
			actual, err := os.ReadFile(outside)
			if err != nil || !bytes.Equal(actual, content) {
				t.Fatal("outside original changed", err)
			}
		})
	}
}

func TestRemoteIndependentRootFullRecordAndByteBudgetsRemainReadable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native Root capacity fixture")
	}
	s, _, _ := appReliabilityFixture(t)
	firstTx, firstAttempt := "", ""
	witness := map[string]os.FileInfo{}
	zeroFileSHA := core.Hash(string(make([]byte, remoteCopyFileLimit)))
	for n := 0; n < remoteCopyMaxRecords; n++ {
		tx, attempt := core.ID(), core.ID()
		now := core.Now()
		files := []remoteBackupArchiveFile{{Name: "staged", File: moduleFile{Size: remoteCopyFileLimit, SHA: zeroFileSHA, Mode: 0644}}}
		if n == 0 {
			files = append([]remoteBackupArchiveFile{{Name: "previous", File: moduleFile{Size: 1, SHA: core.Hash("\x00"), Mode: 0644}}}, files...)
			firstTx, firstAttempt = tx, attempt
		}
		snapshot := remoteBackupSnapshot{TargetID: "owned-target", TransactionID: tx, Revision: 1, SpecSHA: core.Hash("owned capacity state fixture"), Owner: 501, Files: files}
		source := remoteBackupArchiveRecord{Snapshot: snapshot, SHA: remoteBackupSnapshotSHA(snapshot), State: "committed", CreatedAt: now, CompletedAt: now}
		d, err := s.remoteCopyDirectory("owned-target", tx, "", true)
		if err != nil {
			t.Fatal(err)
		}
		_, err = remoteCopyPublish(d, "intent.json", remoteCopyIntent{Format: 1, Version: appcatalog.FilesSyncIndependentBackupVersion, Source: source, CreatedAt: now})
		d.Close()
		if err != nil {
			t.Fatal(err)
		}
		record, err := s.readRemoteCopyRecord("owned-target", tx)
		if err != nil {
			t.Fatal(err)
		}
		d, err = s.remoteCopyDirectory("owned-target", tx, attempt, true)
		if err != nil {
			t.Fatal(err)
		}
		_, err = remoteCopyPublish(d, "attempt.json", remoteCopyAttempt{Format: 1, ID: attempt, IntentSHA: record.SHA, CreatedAt: now})
		if err != nil {
			t.Fatal(err)
		}
		f, err := d.OpenFile("staged", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		err = f.Truncate(remoteCopyFileLimit)
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			t.Fatal(err, closeErr)
		}
		path := filepath.Join(d.paths[len(d.paths)-1], "staged")
		witness[path], err = d.Lstat("staged")
		d.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	records, total, err := s.allRemoteCopyRecords()
	duration := time.Since(start)
	if err != nil || len(records) != 128 || total != remoteCopyMaxBytes {
		t.Fatal(len(records), total, err)
	}
	// Sparse ordinary files exercise actual inode/logical-byte inventory only.
	// No claim is made that 1 GiB of original source data was transferred/hashed.
	t.Logf("actual_Root_inventory_records=%d logical_bytes=%d inventory_elapsed=%s full_content_claim=false", len(records), total, duration)
	d, err := s.remoteCopyDirectory("owned-target", firstTx, firstAttempt, false)
	if err != nil {
		t.Fatal(err)
	}
	f, err := d.OpenFile("previous", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte{0})
	closeErr := f.Close()
	d.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	if _, _, err = s.allRemoteCopyRecords(); err == nil {
		t.Fatal("1GiB+1 accepted or evidence silently omitted")
	}
	for path, original := range witness {
		current, err := os.Lstat(path)
		if err != nil || !programQueueSame(original, current) {
			t.Fatal("capacity refusal changed original sparse inode", path, err)
		}
	}
}
