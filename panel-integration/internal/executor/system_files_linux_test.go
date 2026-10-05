//go:build linux

package executor

import (
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemDirectoryReadOnlyAndNoSymlinkTraversal(t *testing.T) {
	root := t.TempDir()
	if e := os.Mkdir(filepath.Join(root, "safe"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "safe", "file.txt"), []byte("secret"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("safe", filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	listing, e := listSystemDirectory(root, "/", "")
	if e != nil {
		t.Fatal(e)
	}
	items := listing["entries"].([]core.FileEntry)
	if len(items) != 2 || items[0].Name != "safe" || items[1].Kind != "link" {
		t.Fatalf("unexpected entries: %+v", items)
	}
	if dir := listing["directory"].(core.FileEntry); dir.Kind != "directory" || dir.Path != "/" {
		t.Fatalf("unexpected directory metadata: %+v", dir)
	}
	if _, e = listSystemDirectory(root, "/link", ""); e == nil {
		t.Fatal("followed symlink")
	}
	if _, e = listSystemDirectory(root, "/safe/../", ""); e == nil {
		t.Fatal("accepted traversal")
	}
}
