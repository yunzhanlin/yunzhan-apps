//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// Use a private chroot so the real production UID lookup and fixed log paths
// cannot reach an installed panel. The child opens its own FD as UID/GID33.
func TestApacheCCArchiveHeldProducerFDIndependentCopy(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires explicit native Linux Root fixture")
	}
	if mode := os.Getenv("PANEL_CC_COPY_CASE"); mode != "" {
		testApacheCCHeldFD(t, mode)
		return
	}
	for _, mode := range []string{"completed", "retained-unknown"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range []string{"/etc", "/tmp", apacheCCLogDirectory, "/var/lib/panel-apache-body", "/etc/panel/security-apps"} {
				path := filepath.Join(root, name)
				if err := os.MkdirAll(path, 0755); err != nil {
					t.Fatal(err)
				}
				// Only newly-created fixture directories, never a real service path.
				for path != root {
					if err := os.Chmod(path, 0755); err != nil {
						t.Fatal(err)
					}
					path = filepath.Dir(path)
				}
			}
			if err := os.Chmod(root, 0755); err != nil {
				t.Fatal(err)
			}
			for name, data := range map[string]string{"passwd": "root:x:0:0::/:/bin/false\nwww-data:x:33:33::/:/bin/false\n", "group": "root:x:0:\nwww-data:x:33:\n"} {
				if err := os.WriteFile(filepath.Join(root, "etc", name), []byte(data), 0644); err != nil {
					t.Fatal(err)
				}
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(exe)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "fixture.test"), raw, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(root, "fixture.test"), 0755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/fixture.test", "-test.v", "-test.run=^TestApacheCCArchiveHeldProducerFDIndependentCopy$", "-test.timeout=25s")
			cmd.Env = []string{"PANEL_CC_COPY_CASE=" + mode, "TMPDIR=/tmp"}
			cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: root, Unshareflags: syscall.CLONE_NEWNS}
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("actual UID33 %s: %v\n%s", mode, err, output)
			}
			t.Logf("actual UID33 %s child output: %q", mode, output)
		})
	}
}

func testApacheCCHeldFD(t *testing.T, mode string) {
	// Go's Unshareflags creates a private mount namespace before chroot.
	// A real read-only procfs is required for the genuine fd-bound WAF lock
	// witness; fixture data must never fabricate that witness.
	if err := os.Mkdir("/proc", 0555); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		t.Fatal(err)
	}
	defer syscall.Unmount("/proc", syscall.MNT_DETACH)
	ctx := context.Background()
	s := New(Config{SystemRoot: "/", SecurityDir: "/etc/panel/security-apps", SitesDir: "/srv/panel/sites"}).apacheNumericLogService()
	original := []byte("original private CC event\npreserved partial tail")
	if err := os.WriteFile(apacheCCLogPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(apacheCCLogPath, 33, 33); err != nil {
		t.Fatal(err)
	}
	originalInfo, err := os.Lstat(apacheCCLogPath)
	if err != nil {
		t.Fatal(err)
	}
	worker := exec.Command("/fixture.test", "-test.run=^TestApacheCCArchiveHeldProducerFDChild$")
	worker.Env = []string{"PANEL_CC_PRODUCER_CHILD=1"}
	worker.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 33, Gid: 33}}
	input, err := worker.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := worker.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	worker.Stderr = &stderr
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		input.Close()
		if worker.ProcessState == nil {
			worker.Process.Kill()
			worker.Wait()
		}
	}()
	reader := bufio.NewReader(output)
	if line, err := reader.ReadString('\n'); err != nil || line != "READY uid=33 gid=33\n" {
		t.Fatal("producer did not open its own descriptor", line, err, stderr.String())
	}
	id := core.ID()
	entry, err := s.archiveApacheCCLogAt(ctx, id, func(stage string) error {
		if mode == "retained-unknown" && stage == "names-exchanged" {
			return errors.New("owned interrupted exchange")
		}
		return nil
	})
	lock, lockErr := s.lockWAFConfiguration()
	if lockErr != nil {
		t.Fatal(lockErr)
	}
	defer lock.Close()
	if mode == "retained-unknown" {
		if err == nil {
			t.Fatal("owned interruption missing")
		}
		snapshot, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		entry, err = s.retainApacheCCArchiveUnderLock(ctx, lock, id, apacheCCArchiveSnapshotSHA(snapshot), nil)
		if err != nil || entry.State != "retained-unknown" {
			t.Fatal(entry, err)
		}
	} else if err != nil || entry.State != "completed" {
		t.Fatal(entry, err)
	}
	dir, _, err := s.apacheCCArchiveEntryDirectory(id)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(dir, "data.log")
	if raw, err := os.ReadFile(copyPath); err != nil || !bytes.Equal(raw, original) {
		t.Fatal("initial archive was incomplete", err)
	}
	// Deliberately omit cooperative flock/ownership checks. Root's earlier
	// chown cannot revoke this already-open producer file description.
	if _, err := io.WriteString(input, "mutate\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "MUTATED uid=33\n" {
		t.Fatal("old-FD control did not run", line, err, stderr.String())
	}
	if raw, err := os.ReadFile(copyPath); err != nil || !bytes.Equal(raw, original) {
		t.Fatalf("old producer FD modified acknowledged archive: %q %v", raw, err)
	}
	copyInfo, err := os.Lstat(copyPath)
	if err != nil || os.SameFile(originalInfo, copyInfo) {
		t.Fatal("copy shares producer inode", err)
	}
	owner := copyInfo.Sys().(*syscall.Stat_t)
	if owner.Uid != 0 || owner.Gid != 0 || owner.Nlink != 1 || copyInfo.Mode().Perm() != 0600 {
		t.Fatal("copy not Root private")
	}
	sourceInfo, err := os.Lstat(filepath.Join(dir, "next.log"))
	if err != nil || !os.SameFile(originalInfo, sourceInfo) {
		t.Fatal("original inode not retained", err)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "next.log")); err != nil || string(raw) != "producer changed original\n" {
		t.Fatal("producer control did not alter retained source", err)
	}
	if raw, err := os.ReadFile(apacheCCLogPath); err != nil || len(raw) != 0 {
		t.Fatal("new active log changed", err)
	}
	if _, err := s.readApacheCCArchive(ctx, id); err != nil {
		t.Fatal("original drift blocked protected copy", err)
	}
	chunk, err := s.apacheCCArchiveChunk(ctx, id, 0)
	if err != nil || chunk["sha256"] != core.Hash(string(original)) {
		t.Fatal("copy export unavailable", chunk, err)
	}
	snapshot, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.preserveApacheCCArchiveHistoryUnderLock(ctx, lock, id, apacheCCArchiveSnapshotSHA(snapshot), nil); err != nil {
		t.Fatal("history transfer failed", err)
	}
	// The same descriptor survives the whole-directory history move too.
	// A sparse over-limit source must not make the independent copy disappear
	// or turn its download into an unbounded read.
	if _, err := io.WriteString(input, "grow\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "GROWN uid=33\n" {
		t.Fatal("post-history old-FD control did not run", line, err)
	}
	input.Close()
	if err := worker.Wait(); err != nil {
		t.Fatal(err, stderr.String())
	}
	dir, _, err = s.apacheCCArchiveEntryDirectory(id)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(filepath.Join(dir, "next.log")); err != nil || info.Size() != apacheCCLogMaxBytes+1 {
		t.Fatal("over-limit original not preserved", err)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "data.log")); err != nil || !bytes.Equal(raw, original) {
		t.Fatal("post-history producer changed private copy", err)
	}
	if err := s.apacheCCArchiveReadFence(ctx); err != nil {
		t.Fatal("intact independent copy blocked upgrade fence", err)
	}
	if _, err := s.apacheCCArchiveChunk(ctx, id, 0); err != nil {
		t.Fatal("history copy export failed", err)
	}
	t.Log("UID33 old-FD modification succeeded; independent Root bytes, new active log, history export and upgrade fence remained intact")
}

func TestApacheCCArchiveHeldProducerFDChild(t *testing.T) {
	if os.Getenv("PANEL_CC_PRODUCER_CHILD") != "1" {
		return
	}
	if os.Geteuid() != 33 || os.Getegid() != 33 {
		t.Fatal("producer account differs")
	}
	f, err := os.OpenFile(apacheCCLogPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fmt.Println("READY uid=33 gid=33")
	reader := bufio.NewReader(os.Stdin)
	if line, err := reader.ReadString('\n'); err != nil || line != "mutate\n" {
		t.Fatal(line, err)
	}
	if err := f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("producer changed original\n"), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	fmt.Println("MUTATED uid=33")
	if line, err := reader.ReadString('\n'); err != nil || line != "grow\n" {
		t.Fatal(line, err)
	}
	if err := f.Truncate(apacheCCLogMaxBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	fmt.Println("GROWN uid=33")
}
