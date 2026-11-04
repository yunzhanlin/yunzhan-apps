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
	"reflect"
	"strconv"
	"strings"
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
	for _, c := range []struct {
		name, mode string
		group      uint32
	}{
		{"completed", "completed", 0}, {"retained-unknown", "retained-unknown", 0},
		{"completed-service-group", "completed", 987}, {"retained-unknown-service-group", "retained-unknown", 987},
		{"retained-sealed", "retained-sealed", 0}, {"retained-sealed-service-group", "retained-sealed", 987},
	} {
		t.Run(c.name, func(t *testing.T) {
			mode := c.mode
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
			cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: root, Unshareflags: syscall.CLONE_NEWNS, Credential: &syscall.Credential{Uid: 0, Gid: c.group}}
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
		if mode == "retained-unknown" && stage == "names-exchanged" || mode == "retained-sealed" && stage == "sealed-durable" {
			return errors.New("owned interrupted exchange")
		}
		return nil
	})
	lock, lockErr := s.lockWAFConfiguration()
	if lockErr != nil {
		t.Fatal(lockErr)
	}
	defer lock.Close()
	if strings.HasPrefix(mode, "retained-") {
		if err == nil {
			t.Fatal("owned interruption missing")
		}
		snapshot, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
			t.Fatal(err)
		}
		testApacheCCOtherRootGroupRetain(t, id, apacheCCArchiveSnapshotSHA(snapshot))
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		entry, err = s.readApacheCCArchive(ctx, id)
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
	if owner.Uid != 0 || owner.Gid != uint32(os.Getegid()) || owner.Nlink != 1 || copyInfo.Mode().Perm() != 0600 {
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
	testApacheCCOtherRootGroup(t, id, entry.State, core.Hash(string(original)))
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
	testApacheCCOtherRootGroup(t, id, entry.State, core.Hash(string(original)))
	t.Log("UID33 old-FD modification succeeded; independent Root bytes, new active log, history export and upgrade fence remained intact")
}

func TestApacheCCArchiveHeldProducerFDChild(t *testing.T) {
	if id := os.Getenv("PANEL_CC_ROOT_RETAIN_ID"); id != "" {
		if os.Geteuid() != 0 || !core.ValidID(id) {
			t.Fatal("invalid Root retention fixture")
		}
		service := New(Config{SystemRoot: "/", SecurityDir: "/etc/panel/security-apps", SitesDir: "/srv/panel/sites"}).apacheNumericLogService()
		lock, err := service.lockWAFConfiguration()
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		entry, err := service.retainApacheCCArchiveUnderLock(context.Background(), lock, id, os.Getenv("PANEL_CC_ROOT_RETAIN_SHA"), nil)
		if err != nil || entry.State != "retained-unknown" {
			t.Fatal("cross-group retention", entry, err)
		}
		return
	}
	if id := os.Getenv("PANEL_CC_ROOT_READER_ID"); id != "" {
		testApacheCCRootReader(t, id)
		return
	}
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

// A separate real Root process has another primary group. It cannot infer a
// sealed inode's original group from its own credentials or rewrite witnesses.
func testApacheCCOtherRootGroup(t *testing.T, id, state, sha string) {
	gid := 987
	if os.Getegid() != 0 {
		gid = 0
	}
	cmd := exec.Command("/fixture.test", "-test.run=^TestApacheCCArchiveHeldProducerFDChild$", "-test.timeout=15s")
	cmd.Env = []string{"PANEL_CC_ROOT_READER_ID=" + id, "PANEL_CC_ROOT_READER_GID=" + strconv.Itoa(gid), "PANEL_CC_ROOT_READER_STATE=" + state, "PANEL_CC_ROOT_READER_SHA=" + sha, "TMPDIR=/tmp"}
	cmd.Stdin = bytes.NewReader(nil)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 0, Gid: uint32(gid)}}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-group Root reader: %v\n%s", err, output)
	}
}

func testApacheCCRootReader(t *testing.T, id string) {
	gid, err := strconv.Atoi(os.Getenv("PANEL_CC_ROOT_READER_GID"))
	if err != nil || os.Geteuid() != 0 || os.Getegid() != gid || !core.ValidID(id) {
		t.Fatal("wrong real Root reader identity", err)
	}
	s := New(Config{SystemRoot: "/", SecurityDir: "/etc/panel/security-apps", SitesDir: "/srv/panel/sites"}).apacheNumericLogService()
	witness := func() map[string]string {
		out := map[string]string{}
		for _, base := range []string{apacheCCLogDirectory} {
			if err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				st := info.Sys().(*syscall.Stat_t)
				value := fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d:%d", st.Dev, st.Ino, st.Uid, st.Gid, st.Mode, st.Nlink, st.Size, st.Mtim.Nano())
				if info.Mode().IsRegular() {
					raw, e := os.ReadFile(path)
					if e != nil {
						return e
					}
					value += ":" + core.Hash(string(raw))
				}
				out[path] = value
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		return out
	}
	before := witness()
	ctx := context.Background()
	entry, err := s.readApacheCCArchive(ctx, id)
	if err != nil || entry.State != os.Getenv("PANEL_CC_ROOT_READER_STATE") {
		t.Fatal("cross-group original receipt", entry, err)
	}
	if err := s.apacheCCArchiveReadFence(ctx); err != nil {
		t.Fatal("cross-group upgrade fence", err)
	}
	if _, err := s.apacheCCRecoverySnapshot(ctx, id, "", nil); err != nil {
		t.Fatal("cross-group snapshot", err)
	}
	chunk, err := s.apacheCCArchiveChunk(ctx, id, 0)
	if err != nil || chunk["sha256"] != os.Getenv("PANEL_CC_ROOT_READER_SHA") {
		t.Fatal("cross-group chunk", chunk, err)
	}
	if !reflect.DeepEqual(before, witness()) {
		t.Fatal("cross-group observation altered original private files")
	}
}

func testApacheCCOtherRootGroupRetain(t *testing.T, id, sha string) {
	gid := 987
	if os.Getegid() != 0 {
		gid = 0
	}
	cmd := exec.Command("/fixture.test", "-test.run=^TestApacheCCArchiveHeldProducerFDChild$", "-test.timeout=15s")
	cmd.Env = []string{"PANEL_CC_ROOT_RETAIN_ID=" + id, "PANEL_CC_ROOT_RETAIN_SHA=" + sha, "TMPDIR=/tmp"}
	cmd.Stdin = bytes.NewReader(nil)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 0, Gid: uint32(gid)}}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-group Root retention: %v\n%s", err, output)
	}
}
