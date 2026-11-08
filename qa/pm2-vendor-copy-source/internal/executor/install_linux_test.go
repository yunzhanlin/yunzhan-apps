//go:build linux

package executor

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceExtractionRejectsEscapesAndLinks(t *testing.T) {
	for _, h := range []*tar.Header{{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0644}, {Name: "/etc/passwd", Typeflag: tar.TypeReg, Mode: 0644}, {Name: "php/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}} {
		t.Run(h.Name, func(t *testing.T) {
			root := t.TempDir()
			archive := filepath.Join(root, "source.gz")
			f, e := os.Create(archive)
			if e != nil {
				t.Fatal(e)
			}
			gz := gzip.NewWriter(f)
			tw := tar.NewWriter(gz)
			if e = tw.WriteHeader(h); e != nil {
				t.Fatal(e)
			}
			tw.Close()
			gz.Close()
			f.Close()
			dest := filepath.Join(root, "dest")
			os.Mkdir(dest, 0755)
			if e = extractSource(archive, dest); e == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}
func TestBuildPromotionInternalLinksOnly(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	os.Mkdir(src, 0755)
	os.WriteFile(filepath.Join(src, "phar.phar"), []byte("data"), 0755)
	os.Symlink("phar.phar", filepath.Join(src, "phar"))
	dest := filepath.Join(root, "dest")
	if e := copyBuildTree(src, dest); e != nil {
		t.Fatal(e)
	}
	st, e := os.Lstat(filepath.Join(dest, "phar"))
	if e != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("internal link not preserved")
	}
	if link, e := os.Readlink(filepath.Join(dest, "phar")); e != nil || link != "phar.phar" {
		t.Fatal("internal link target changed")
	}
	os.Symlink("/etc/passwd", filepath.Join(src, "escape"))
	if e = copyBuildTree(src, filepath.Join(root, "unsafe")); e == nil {
		t.Fatal("external link was accepted")
	}
}

func TestSourceExtractionAllowsBoundedRelativeLink(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "source.gz")
	f, e := os.Create(archive)
	if e != nil {
		t.Fatal(e)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	data := []byte("node")
	if e = tw.WriteHeader(&tar.Header{Name: "node/lib/cli.js", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(data))}); e != nil {
		t.Fatal(e)
	}
	if _, e = tw.Write(data); e != nil {
		t.Fatal(e)
	}
	if e = tw.WriteHeader(&tar.Header{Name: "node/bin/npm", Typeflag: tar.TypeSymlink, Linkname: "../lib/cli.js"}); e != nil {
		t.Fatal(e)
	}
	if e = tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e = gz.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(root, "dest")
	if e = os.Mkdir(dest, 0755); e != nil {
		t.Fatal(e)
	}
	if e = extractSource(archive, dest); e != nil {
		t.Fatal(e)
	}
	if got, e := os.Readlink(filepath.Join(dest, "node/bin/npm")); e != nil || got != "../lib/cli.js" {
		t.Fatalf("relative link missing: %q %v", got, e)
	}
}

func TestSourceExtractionIgnoresPAXMetadataObject(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "source.gz")
	f, e := os.Create(archive)
	if e != nil {
		t.Fatal(e)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if e = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": "metadata"}}); e != nil {
		t.Fatal(e)
	}
	data := []byte("redis")
	if e = tw.WriteHeader(&tar.Header{Name: "redis/src/server.c", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(data))}); e != nil {
		t.Fatal(e)
	}
	if _, e = tw.Write(data); e != nil {
		t.Fatal(e)
	}
	if e = tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e = gz.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(root, "dest")
	if e = os.Mkdir(dest, 0755); e != nil {
		t.Fatal(e)
	}
	if e = extractSource(archive, dest); e != nil {
		t.Fatal(e)
	}
	if got, e := os.ReadFile(filepath.Join(dest, "redis/src/server.c")); e != nil || string(got) != "redis" {
		t.Fatalf("regular file missing: %q %v", got, e)
	}
	if _, e = os.Lstat(filepath.Join(dest, "pax_global_header")); !os.IsNotExist(e) {
		t.Fatal("PAX metadata became a filesystem object")
	}
}
