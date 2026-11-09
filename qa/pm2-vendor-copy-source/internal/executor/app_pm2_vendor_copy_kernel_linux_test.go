//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func pm2VendorKernelParent(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("dedicated native Root filesystem test")
	}
	parent, err := os.MkdirTemp("/var/lib", "panel-pm2-vendor-owned-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) }) // Only this new test namespace.
	return parent
}

func pm2VendorKernelBuild(t *testing.T, parent string) (*pm2VendorWorkspace, string) {
	t.Helper()
	w, err := newPM2VendorWorkspace(parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.close)
	source := filepath.Join(w.path, "build")
	if err = os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	return w, source
}

func pm2VendorKernelWrite(t *testing.T, name string, value []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, value, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

func TestPM2RootVendorKernelIndependentOwnerAndInternalLinks(t *testing.T) {
	parent := pm2VendorKernelParent(t)
	w, source := pm2VendorKernelBuild(t, parent)
	code := filepath.Join(source, "node_modules", "owned", "bin", "pm2.js")
	pm2VendorKernelWrite(t, code, []byte("// original locked npm bytes\n"), 0777|os.ModeSetuid)
	if err := os.Chown(code, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(code, 0777|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(source, "node_modules", ".bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../owned/bin/pm2.js", filepath.Join(bin, "pm2")); err != nil {
		t.Fatal(err)
	}
	// Cache objects and their foreign ownership never enter the public tree.
	pm2VendorKernelWrite(t, filepath.Join(source, ".cache", "retained"), []byte("original-cache"), 0600)
	entries, err := w.copyIndependent(context.Background(), "build", "candidate")
	if err != nil {
		t.Fatal(err)
	}
	if err = w.verifyIndependent(context.Background(), "candidate", entries, true); err != nil {
		t.Fatal(err)
	}
	copyFile := filepath.Join(w.path, "candidate", "node_modules", "owned", "bin", "pm2.js")
	var before, after unix.Stat_t
	if err = unix.Stat(code, &before); err != nil {
		t.Fatal(err)
	}
	if err = unix.Stat(copyFile, &after); err != nil {
		t.Fatal(err)
	}
	if before.Uid != 1000 || after.Uid != 0 || after.Gid != 0 || before.Ino == after.Ino || after.Nlink != 1 || after.Mode&07777 != 0755 {
		t.Fatalf("not an independent canonical Root inode: original=%+v new=%+v", before, after)
	}
	if _, ok := entries[".cache"]; ok {
		t.Fatal("private npm cache was included")
	}
	if _, err = os.Lstat(filepath.Join(w.path, "candidate", ".cache")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cache unexpectedly published", err)
	}
	if _, err = w.copyIndependent(context.Background(), "build", "candidate"); err == nil {
		t.Fatal("existing candidate was overwritten")
	}
}

func TestPM2RootVendorKernelOldUnprivilegedWriterCannotChangePublishedCopy(t *testing.T) {
	parent := pm2VendorKernelParent(t)
	public := filepath.Join(parent, "pm2", "runtime.js")
	pm2VendorKernelWrite(t, public, []byte("original-old-runtime"), 0600)
	if err := os.Chmod(filepath.Dir(public), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(public, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	// The original writer itself opens the old pathname while allowed to do
	// so, retains the writable FD across publication, and then truncates and
	// pwrites it. Its independent attempt to open the new public file fails.
	script := `import os,sys,errno
assert os.geteuid()==65534 and os.getegid()==65534
fd=os.open(sys.argv[1],os.O_RDWR|os.O_NOFOLLOW)
print('original-writer-ready',flush=True)
assert sys.stdin.readline().strip()=='write-original'
os.ftruncate(fd,7);assert os.pwrite(fd,b'changed',0)==7;os.fsync(fd)
try:
 new=os.open(sys.argv[1],os.O_WRONLY|os.O_NOFOLLOW)
except OSError as e:
 assert e.errno==errno.EACCES
else:
 os.close(new);raise AssertionError('writer opened the new Root copy')
os.close(fd);print('original-writer-only-changed-retained-inode',flush=True)
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", script, public)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || line != "original-writer-ready\n" {
		t.Fatalf("old writer did not open its ordinary file: %q %v %s", line, err, stderr.String())
	}
	var original unix.Stat_t
	if err = unix.Stat(public, &original); err != nil {
		t.Fatal(err)
	}
	w, source := pm2VendorKernelBuild(t, parent)
	fresh := bytes.Repeat([]byte("verified-new-package-bytes\n"), 32768)
	pm2VendorKernelWrite(t, filepath.Join(source, "runtime.js"), fresh, 0644)
	if err = os.Chown(filepath.Join(source, "runtime.js"), 501, 20); err != nil {
		t.Fatal(err)
	}
	entries, err := w.copyIndependent(context.Background(), "build", "candidate")
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.publishIndependent(context.Background(), "candidate", entries)
	if err != nil || !result.Published || !result.Retained {
		t.Fatalf("atomic independent publication failed: %+v %v", result, err)
	}
	if _, err = io.WriteString(stdin, "write-original\n"); err != nil {
		t.Fatal(err)
	}
	stdin.Close()
	if line, err := reader.ReadString('\n'); err != nil || line != "original-writer-only-changed-retained-inode\n" {
		t.Fatalf("old FD semantics were not exercised: %q %v %s", line, err, stderr.String())
	}
	if err = cmd.Wait(); err != nil {
		t.Fatalf("old unprivileged writer failed: %v %s", err, stderr.String())
	}
	actual, err := os.ReadFile(public)
	if err != nil || !bytes.Equal(actual, fresh) {
		t.Fatal("old writer altered the independently published bytes", err)
	}
	retained := filepath.Join(w.path, "candidate", "runtime.js")
	actual, err = os.ReadFile(retained)
	if err != nil || string(actual) != "changed" {
		t.Fatal("original write did not reach the retained original", err)
	}
	var oldStat, newStat unix.Stat_t
	if err = unix.Stat(retained, &oldStat); err != nil {
		t.Fatal(err)
	}
	if err = unix.Stat(public, &newStat); err != nil {
		t.Fatal(err)
	}
	if oldStat.Ino != original.Ino || oldStat.Uid != 65534 || newStat.Ino == original.Ino || newStat.Uid != 0 || newStat.Gid != 0 || newStat.Nlink != 1 {
		t.Fatal("original or new inode/owner identity was lost")
	}
	if _, err = w.publishIndependent(context.Background(), "candidate", entries); err == nil {
		t.Fatal("already published original intent was replayed")
	}
	t.Log("actual UID65534 original writable FD truncated/pwrote retained original; new Root-owned public bytes unchanged and new write open denied")
}

func TestPM2RootVendorKernelRejectsSourceBoundaries(t *testing.T) {
	for _, kind := range []string{"external-link", "escape-link", "dangling-link", "loop-link", "directory-link", "hard-link", "fifo", "oversize", "reserved-index"} {
		t.Run(kind, func(t *testing.T) {
			parent := pm2VendorKernelParent(t)
			pm2VendorKernelWrite(t, filepath.Join(parent, "pm2", "original"), []byte("unchanged-public"), 0644)
			w, source := pm2VendorKernelBuild(t, parent)
			file := filepath.Join(source, "input")
			var err error
			switch kind {
			case "external-link":
				err = os.Symlink("/etc/passwd", file)
			case "escape-link":
				err = os.Symlink("../../outside", file)
			case "dangling-link":
				err = os.Symlink("missing", file)
			case "loop-link":
				err = os.Symlink("input", file)
			case "directory-link":
				err = os.Mkdir(filepath.Join(source, "directory"), 0755)
				if err == nil {
					err = os.Symlink("directory", file)
				}
			case "hard-link":
				pm2VendorKernelWrite(t, file, []byte("original-private"), 0644)
				err = os.Link(file, filepath.Join(source, "alias"))
			case "fifo":
				err = unix.Mkfifo(file, 0600)
			case "oversize":
				pm2VendorKernelWrite(t, file, nil, 0644)
				err = os.Truncate(file, pm2VendorMaxFile+1)
			case "reserved-index":
				pm2VendorKernelWrite(t, filepath.Join(source, pm2VendorIndexName), []byte("untrusted-index"), 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			if st, err := os.Stat(source); err != nil || st.Mode().Perm() != 0700 {
				t.Fatal("invalid test precondition: original extracted input lost its private parent", err)
			}
			_, err = w.copyIndependent(context.Background(), "build", "candidate")
			if err == nil {
				t.Fatal("unsafe original source accepted")
			}
			reason := "link"
			switch kind {
			case "hard-link", "oversize":
				reason = "ordinary-file"
			case "fifo":
				reason = "nonordinary"
			case "reserved-index":
				reason = "reserved index"
			}
			if !strings.Contains(err.Error(), reason) {
				t.Fatalf("boundary did not reach its actual %s refusal: %v", kind, err)
			}
			actual, err := os.ReadFile(filepath.Join(parent, "pm2", "original"))
			if err != nil || string(actual) != "unchanged-public" {
				t.Fatal("refusal changed the original public runtime", err)
			}
			if _, err := os.Lstat(filepath.Join(w.path, "original-publication-prepared.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed copy reached publication", err)
			}
		})
	}
}

func TestPM2RootVendorKernelCancellationAndOriginalSymlinkPreserved(t *testing.T) {
	parent := pm2VendorKernelParent(t)
	w, source := pm2VendorKernelBuild(t, parent)
	pm2VendorKernelWrite(t, filepath.Join(source, "runtime.js"), []byte("new-ordinary-code"), 0644)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.copyIndependent(ctx, "build", "cancelled"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled copy was dispatched", err)
	}
	if _, err := os.Lstat(filepath.Join(w.path, "cancelled")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled copy created a candidate")
	}
	entries, err := w.copyIndependent(context.Background(), "build", "candidate")
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "original-link-target")
	pm2VendorKernelWrite(t, target, []byte("original-canary"), 0600)
	if err = os.Symlink(target, filepath.Join(parent, "pm2")); err != nil {
		t.Fatal(err)
	}
	result, err := w.publishIndependent(context.Background(), "candidate", entries)
	if err == nil || result.Published || result.Retained {
		t.Fatalf("unknown original symlink replaced: %+v %v", result, err)
	}
	if value, err := os.ReadFile(target); err != nil || string(value) != "original-canary" {
		t.Fatal("original link target modified")
	}
	if value, err := os.Readlink(filepath.Join(parent, "pm2")); err != nil || value != target {
		t.Fatal("original link replaced")
	}
}

func TestPM2RootVendorKernelInitialPublicationAndTamperRefusal(t *testing.T) {
	for _, tamper := range []string{"none", "owner", "mode", "contents", "hard-link", "extra-file"} {
		t.Run(tamper, func(t *testing.T) {
			parent := pm2VendorKernelParent(t)
			w, source := pm2VendorKernelBuild(t, parent)
			pm2VendorKernelWrite(t, filepath.Join(source, "runtime.js"), []byte("original-pinned-code"), 0644)
			entries, err := w.copyIndependent(context.Background(), "build", "candidate")
			if err != nil {
				t.Fatal(err)
			}
			candidate := filepath.Join(w.path, "candidate", "runtime.js")
			switch tamper {
			case "owner":
				err = os.Chown(candidate, 1000, 1000)
			case "mode":
				err = os.Chmod(candidate, 0666)
			case "contents":
				err = os.WriteFile(candidate, []byte("other-pinned-length!"), 0644)
			case "hard-link":
				err = os.Link(candidate, filepath.Join(w.path, "alias"))
			case "extra-file":
				err = os.WriteFile(filepath.Join(w.path, "candidate", "unknown"), []byte("extra"), 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := w.publishIndependent(context.Background(), "candidate", entries)
			if tamper == "none" {
				if err != nil || !result.Published || result.Retained {
					t.Fatalf("ordinary initial publication failed: %+v %v", result, err)
				}
				if _, err = os.Stat(filepath.Join(w.path, "original-publication-completed.json")); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || result.Published {
				t.Fatalf("modified private candidate published: %+v %v", result, err)
			} else if _, e := os.Lstat(filepath.Join(parent, "pm2")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("refusal changed the original absent namespace", e)
			}
		})
	}
}

func TestPM2RootVendorKernelProtectedParentAndPrivateEvidence(t *testing.T) {
	parent := pm2VendorKernelParent(t)
	unsafe := filepath.Join(parent, "writable")
	if err := os.Mkdir(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	if w, err := newPM2VendorWorkspace(unsafe); err == nil {
		w.close()
		t.Fatal("writable original parent accepted")
	}
	if err := os.Symlink(parent, filepath.Join(parent, "linked")); err != nil {
		t.Fatal(err)
	}
	if w, err := newPM2VendorWorkspace(filepath.Join(parent, "linked")); err == nil {
		w.close()
		t.Fatal("original parent link followed")
	}
	w, _ := pm2VendorKernelBuild(t, parent)
	if err := w.writeRecord("original.json", map[string]any{"original": true}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := w.writeRecord("original.json", map[string]any{"replay": true}, 0600); err == nil {
		t.Fatal("original receipt overwritten")
	}
	if err := os.Chmod(w.path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := w.private(); err == nil {
		t.Fatal("nonprivate evidence directory accepted")
	}
	for _, name := range []string{"", ".", "..", "../escape", "/absolute", "a/b", "a\x00b", strings.Repeat("a", 256)} {
		if pm2VendorComponent(name) {
			t.Fatal(fmt.Sprintf("unsafe component accepted: %q", name))
		}
	}
}
