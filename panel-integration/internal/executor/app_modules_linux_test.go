//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestModuleAtomicWriteAndNestedOwnership(t *testing.T) {
	dir := t.TempDir()
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	outside := filepath.Join(t.TempDir(), "owned.txt")
	if e = os.WriteFile(outside, []byte("protected"), 0644); e != nil {
		t.Fatal(e)
	}
	if e = os.Link(outside, filepath.Join(dir, "hardlink.txt")); e != nil {
		t.Fatal(e)
	}
	f := &siteFiles{public: root, uid: os.Getuid(), gid: os.Getgid()}
	if e = moduleWriteSiteFile(f, "hardlink.txt", []byte("replacement"), 0644); e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(outside)
	if string(data) != "protected" {
		t.Fatal("hardlink target truncated")
	}
	if e = moduleWriteSiteFile(f, "nested/deep/file.txt", []byte("nested"), 0644); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(filepath.Join(dir, "nested"))
	if st.Mode().Perm() != 0755 {
		t.Fatal("nested directory unreadable")
	}
	if e = os.Symlink("nested", filepath.Join(dir, "link")); e != nil {
		t.Fatal(e)
	}
	if e = moduleWriteSiteFile(f, "link/write.txt", []byte("bad"), 0644); e == nil {
		t.Fatal("symlink parent accepted")
	}
	if e = moduleWriteSiteFile(f, "../escape", []byte("bad"), 0644); e == nil {
		t.Fatal("path traversal accepted")
	}
}
