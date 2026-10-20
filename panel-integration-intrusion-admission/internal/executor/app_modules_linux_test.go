//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModuleDiskReportIsBoundedForManyAndLongPaths(t *testing.T) {
	f, site := fileFixture(t)
	for i := 0; i < 1100; i++ {
		path := fmt.Sprintf("folder-%04d-%s", i, strings.Repeat("x", 180))
		if err := f.public.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(site, "public", path, "one.txt"), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	long := strings.Repeat(strings.Repeat("y", 180)+"/", 6) + "long.txt"
	if err := f.public.MkdirAll(filepath.Dir(long), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(site, "public", long), []byte("xx"), 0644); err != nil {
		t.Fatal(err)
	}
	svc := New(Config{SitesDir: filepath.Dir(site)})
	out, err := svc.moduleDiskAt(context.Background(), filepath.Base(site), "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	r := out.(map[string]any)
	if len(data) >= 1<<20 || r["files"] != 1101 || r["total_bytes"] != int64(1102) || r["partial"] != true {
		t.Fatalf("bytes=%d files=%v total=%v partial=%v", len(data), r["files"], r["total_bytes"], r["partial"])
	}
	first := r["largest_files"].([]map[string]any)[0]
	if first["can_drill"] != false || len(first["path"].(string)) > 515 {
		t.Fatal(first)
	}
}

func TestModuleDiskSubdirectoryAndActualSize(t *testing.T) {
	f, site := fileFixture(t)
	if e := f.public.MkdirAll("assets/nested", 0755); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(site, "public/assets/a.txt"), []byte("12345"), 0644)
	os.WriteFile(filepath.Join(site, "public/assets/nested/b.txt"), []byte("1234567"), 0644)
	os.WriteFile(filepath.Join(site, "public/other.bin"), []byte("123"), 0644)
	svc := New(Config{SitesDir: filepath.Dir(site)})
	id := filepath.Base(site)
	out, e := svc.moduleDiskAt(context.Background(), id, "assets")
	if e != nil {
		t.Fatal(e)
	}
	r := out.(map[string]any)
	if r["total_bytes"] != int64(12) || r["files"] != 2 || r["extensions"].(map[string]int64)[".txt"] != 12 {
		t.Fatal(r)
	}
	if r["largest_files"].([]map[string]any)[0]["path"] != "assets/nested/b.txt" {
		t.Fatal(r)
	}
	os.Symlink("assets", filepath.Join(site, "public/link"))
	for _, p := range []string{"../escape", "/etc", "link", "link/nested", "assets/a.txt"} {
		if _, e = svc.moduleDiskAt(context.Background(), id, p); e == nil {
			t.Fatal("invalid directory accepted", p)
		}
	}
	if _, e = svc.runAppModule(context.Background(), "disk-analysis", "run", core.AppModuleInput{SiteID: id, Path: "assets"}); e != nil {
		t.Fatal(e)
	}
}

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
