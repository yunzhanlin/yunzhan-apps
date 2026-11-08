//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func integrityFlagTestRoot(t *testing.T) (string, *os.File) {
	t.Helper()
	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return dir, f
}

func TestIntegrityFlagTargetRejectsAliasesAndEscapes(t *testing.T) {
	_, root := integrityFlagTestRoot(t)
	for _, name := range []string{"", "..", "../data", "/data", "a/../data", "a/./data", "a\\data", "data\n", "data\x00", string([]byte{0xff}), "."} {
		t.Run(strconv.QuoteToASCII(name), func(t *testing.T) {
			f, err := openIntegrityFlagTarget(root, name, false)
			if f != nil {
				f.Close()
			}
			if err == nil {
				t.Fatal("invalid target was accepted")
			}
		})
	}
}

func TestIntegrityFlagTargetRejectsLinksAndSpecialInodes(t *testing.T) {
	dir, root := integrityFlagTestRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "data"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ name, target string }{{"inside-link", "data"}, {"outside-link", outside}, {"magic-link", "/proc/self/fd/" + strconv.Itoa(int(root.Fd()))}} {
		if err := os.Symlink(item.target, filepath.Join(dir, item.name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"inside-link", "outside-link", "magic-link", "fifo", "directory"} {
		t.Run(name, func(t *testing.T) {
			f, err := openIntegrityFlagTarget(root, name, false)
			if f != nil {
				f.Close()
			}
			if err == nil {
				t.Fatal("linked or non-regular target was accepted")
			}
		})
	}
	for name, want := range map[string]string{filepath.Join(dir, "data"): "original", outside: "outside"} {
		got, err := os.ReadFile(name)
		if err != nil || string(got) != want {
			t.Fatal("original file changed", name, err)
		}
	}
}

func TestIntegrityFlagTargetRejectsEveryHardlinkAlias(t *testing.T) {
	dir, root := integrityFlagTestRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "data"), []byte("shared original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(dir, "data"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"data", "alias"} {
		f, err := openIntegrityFlagTarget(root, name, false)
		if f != nil {
			f.Close()
		}
		if err == nil {
			t.Fatal("shared inode accepted", name)
		}
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != "shared original" {
			t.Fatal("original shared data changed", err)
		}
	}
}

func TestIntegrityFlagTargetKeepsPinnedDescriptorAfterRename(t *testing.T) {
	dir, root := integrityFlagTestRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "data"), []byte("pinned original"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openIntegrityFlagTarget(root, "data", false)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Rename(filepath.Join(dir, "data"), filepath.Join(dir, "retained-original")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 64)
	n, err := f.ReadAt(got, 0)
	if n != len("pinned original") || string(got[:n]) != "pinned original" {
		t.Fatal("descriptor followed the replacement path", n, err)
	}
	var original, replacement unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &original); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(filepath.Join(dir, "data"), &replacement); err != nil {
		t.Fatal(err)
	}
	if original.Dev == replacement.Dev && original.Ino == replacement.Ino {
		t.Fatal("replacement unexpectedly has original identity")
	}
}

func TestIntegrityFlagTargetAcceptsOnlyExplicitDirectoryRoot(t *testing.T) {
	dir, root := integrityFlagTestRoot(t)
	f, err := openIntegrityFlagTarget(root, ".", true)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(dir)
	if err != nil || !os.SameFile(got, want) || !got.IsDir() {
		t.Fatal("explicit root did not retain its real directory identity", err)
	}
}
