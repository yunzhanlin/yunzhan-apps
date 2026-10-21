//go:build linux

package executor

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/ulikunitz/xz"
	"io"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func fileFixture(t *testing.T) (*siteFiles, string) {
	t.Helper()
	base := t.TempDir()
	id := core.ID()
	site := filepath.Join(base, id)
	if e := os.MkdirAll(filepath.Join(site, "public"), 0755); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(map[string]string{"id": id})
	os.WriteFile(filepath.Join(site, ".panel-site.json"), b, 0600)
	svc := New(Config{SitesDir: base})
	f, e := svc.openFiles(id)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(f.Close)
	return f, site
}
func TestDirectorySizeCountsFilesWithoutFollowingLinks(t *testing.T) {
	f, site := fileFixture(t)
	base := filepath.Join(site, "public", "content")
	if e := os.MkdirAll(filepath.Join(base, "nested"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(base, "one.txt"), []byte("12345"), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(base, "nested", "two.txt"), []byte("123"), 0644); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if e := os.WriteFile(outside, []byte("not counted"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(base, "external")); e != nil {
		t.Fatal(e)
	}
	result, e := f.DirectorySize(context.Background(), "content")
	if e != nil {
		t.Fatal(e)
	}
	if result["bytes"] != int64(8) || result["files"] != int64(2) || result["directories"] != int64(2) || result["skipped"] != int64(1) {
		t.Fatalf("unexpected bounded directory size: %#v", result)
	}
	if _, e := f.DirectorySize(context.Background(), "content/external"); e == nil {
		t.Fatal("symlink accepted as directory")
	}
	if _, e := f.DirectorySize(context.Background(), "../outside"); e == nil {
		t.Fatal("path escaped site")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := f.DirectorySize(cancelled, "content"); e != context.Canceled {
		t.Fatalf("cancellation not honored: %v", e)
	}
}
func TestSearchTreeFindsNestedNamesWithoutFollowingLinks(t *testing.T) {
	f, site := fileFixture(t)
	base := filepath.Join(site, "public", "docs")
	if e := os.MkdirAll(filepath.Join(base, "nested"), 0755); e != nil {
		t.Fatal(e)
	}
	for name, value := range map[string]string{"report.txt": "one", "nested/report.txt": "two", "nested/other.txt": "three"} {
		if e := os.WriteFile(filepath.Join(base, name), []byte(value), 0644); e != nil {
			t.Fatal(e)
		}
	}
	outside := t.TempDir()
	if e := os.WriteFile(filepath.Join(outside, "report-secret.txt"), []byte("private"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(base, "external")); e != nil {
		t.Fatal(e)
	}
	result, e := f.SearchTree(context.Background(), "docs", "REPORT")
	if e != nil {
		t.Fatal(e)
	}
	entries := result["entries"].([]core.FileEntry)
	if len(entries) != 2 || entries[0].Path != "docs/nested/report.txt" || entries[1].Path != "docs/report.txt" {
		t.Fatalf("unexpected recursive results: %#v", entries)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/v1/sites/"+filepath.Base(site)+"/files?path=docs&search=REPORT&recursive=1&limit=20", nil)
	New(Config{SitesDir: filepath.Dir(site)}).Handler().ServeHTTP(recorder, request)
	if recorder.Code != 200 {
		t.Fatalf("recursive HTTP search returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var page struct {
		Entries []core.FileEntry `json:"entries"`
	}
	if e := json.Unmarshal(recorder.Body.Bytes(), &page); e != nil || len(page.Entries) != 2 {
		t.Fatalf("unexpected recursive HTTP page: %v, %s", e, recorder.Body.String())
	}
	if _, e := f.SearchTree(context.Background(), "../outside", "report"); e == nil {
		t.Fatal("path traversal accepted")
	}
	if _, e := f.SearchTree(context.Background(), "docs/external", "report"); e == nil {
		t.Fatal("link accepted as search root")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := f.SearchTree(cancelled, "docs", "report"); e != context.Canceled {
		t.Fatalf("cancellation not honored: %v", e)
	}
}
func TestSiteFilesSymlinksAndSpecialFilesCannotEscape(t *testing.T) {
	f, site := fileFixture(t)
	outside := t.TempDir()
	secret := filepath.Join(outside, "keep")
	os.WriteFile(secret, []byte("untouched"), 0600)
	os.Symlink(secret, filepath.Join(site, "public/escape"))
	os.Symlink(outside, filepath.Join(site, "public/outside"))
	if _, e := f.Text("escape"); e == nil {
		t.Fatal("read followed external link")
	}
	if _, e := f.Upload("outside/new", "", strings.NewReader("bad"), 3); e == nil {
		t.Fatal("upload escaped public tree")
	}
	if _, e := f.Action(core.FileAction{Action: "chmod", Path: "escape", Mode: "777"}); e == nil {
		t.Fatal("chmod followed link")
	}
	if b, _ := os.ReadFile(secret); string(b) != "untouched" {
		t.Fatal("outside content modified")
	}
	if e := syscall.Mkfifo(filepath.Join(site, "public/pipe"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := f.Text("pipe"); e == nil {
		t.Fatal("FIFO opened as regular file")
	}
}
func TestFileConflictsRecycleAndPermissions(t *testing.T) {
	f, site := fileFixture(t)
	p := filepath.Join(site, "public/config.txt")
	os.WriteFile(p, []byte("original"), 0600)
	first, e := f.Text("config.txt")
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(p, []byte("external change"), 0600)
	if _, e = f.Action(core.FileAction{Action: "save", Path: "config.txt", Content: "overwrite", ExpectedSHA256: first.SHA256}); e == nil {
		t.Fatal("stale editor overwrote changed file")
	}
	current, _ := f.Text("config.txt")
	if _, e = f.Action(core.FileAction{Action: "save", Path: "config.txt", Content: "saved", ExpectedSHA256: current.SHA256}); e != nil {
		t.Fatal(e)
	}
	trash, e := f.Trash()
	if e != nil || len(trash) != 1 || trash[0].Reason != "edit" {
		t.Fatal("editing did not preserve revision", e)
	}
	if _, e = f.Action(core.FileAction{Action: "restore", TrashID: trash[0].ID, Destination: "restored.txt"}); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(filepath.Join(site, "public/restored.txt"))
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("restored revision broadened permissions")
	}
	if b, _ := os.ReadFile(filepath.Join(site, "public/restored.txt")); string(b) != "external change" {
		t.Fatal("revision content mismatch")
	}
	if _, e = f.Upload("config.txt", "", strings.NewReader("bad"), 3); e == nil {
		t.Fatal("upload replaced existing file")
	}
	if _, e = f.Action(core.FileAction{Action: "rename", Path: "restored.txt", Destination: "config.txt"}); e == nil {
		t.Fatal("rename replaced existing file")
	}
	result, e := f.Action(core.FileAction{Action: "trash", Path: "config.txt"})
	if e != nil {
		t.Fatal(e)
	}
	deleted := result.(core.TrashEntry)
	if _, e = os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("deleted file remains public")
	}
	if _, e = f.Action(core.FileAction{Action: "restore", TrashID: deleted.ID}); e != nil {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(p); string(b) != "saved" {
		t.Fatal("trash restore changed data")
	}
	if _, e = f.Action(core.FileAction{Action: "purge", TrashID: trash[0].ID}); e != nil {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(p); string(b) != "saved" {
		t.Fatal("purging revision touched live file")
	}
}
func TestFilePinsPersistAndSortBeforePagination(t *testing.T) {
	f, site := fileFixture(t)
	for i := 0; i < 120; i++ {
		name := fmt.Sprintf("file-%03d.txt", i)
		if e := os.WriteFile(filepath.Join(site, "public", name), []byte(name), 0644); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := f.Action(core.FileAction{Action: "pin", Path: "file-119.txt"}); e != nil {
		t.Fatal(e)
	}
	listing, e := f.List("", "")
	if e != nil {
		t.Fatal(e)
	}
	entries := listing["entries"].([]core.FileEntry)
	if len(entries) != 120 || entries[0].Name != "file-119.txt" || !entries[0].Pinned {
		t.Fatalf("pinned item was not first before paging: %+v", entries[0])
	}
	if _, e = f.Action(core.FileAction{Action: "unpin", Path: "file-119.txt"}); e != nil {
		t.Fatal(e)
	}
	listing, e = f.List("", "")
	if e != nil {
		t.Fatal(e)
	}
	entries = listing["entries"].([]core.FileEntry)
	if entries[0].Name != "file-000.txt" || entries[119].Pinned {
		t.Fatal("unpin did not restore ordinary order")
	}
	if _, e = f.Action(core.FileAction{Action: "pin", Path: "file-119.txt"}); e != nil {
		t.Fatal(e)
	}
	if b, e := os.ReadFile(filepath.Join(site, ".panel-files", "pins.json")); e != nil || !strings.Contains(string(b), "file-119.txt") {
		t.Fatal("pin was not persisted in site-private metadata", e)
	}
	if e := os.Symlink("/etc/passwd", filepath.Join(site, "public", "link")); e != nil {
		t.Fatal(e)
	}
	if _, e = f.Action(core.FileAction{Action: "pin", Path: "link"}); e == nil {
		t.Fatal("symbolic link was pinned")
	}
}
func TestFilePinsFollowRenameAndClearOnTrash(t *testing.T) {
	f, site := fileFixture(t)
	if e := os.MkdirAll(filepath.Join(site, "public", "folder"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(site, "public", "folder", "item.txt"), []byte("one"), 0644); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"folder", "folder/item.txt"} {
		if _, e := f.Action(core.FileAction{Action: "pin", Path: path}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := f.Action(core.FileAction{Action: "rename", Path: "folder", Destination: "renamed"}); e != nil {
		t.Fatal(e)
	}
	pins, e := f.readPins()
	if e != nil || !pins["renamed"] || !pins["renamed/item.txt"] || pins["folder"] {
		t.Fatalf("rename lost or leaked pins: %v %v", pins, e)
	}
	if _, e = f.Action(core.FileAction{Action: "trash", Path: "renamed"}); e != nil {
		t.Fatal(e)
	}
	pins, e = f.readPins()
	if e != nil || len(pins) != 0 {
		t.Fatalf("trash left stale pins: %v %v", pins, e)
	}
	if e = os.Mkdir(filepath.Join(site, "public", "renamed"), 0755); e != nil {
		t.Fatal(e)
	}
	listing, e := f.List("", "")
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range listing["entries"].([]core.FileEntry) {
		if entry.Name == "renamed" && entry.Pinned {
			t.Fatal("recreated path inherited deleted entry's pin")
		}
	}
}
func TestFileShareSnapshotDoesNotFollowChangesOrLinks(t *testing.T) {
	f, site := fileFixture(t)
	filePath := filepath.Join(site, "public", "report.txt")
	if e := os.WriteFile(filePath, []byte("original"), 0644); e != nil {
		t.Fatal(e)
	}
	id := core.ID()
	result, e := f.prepareShare("report.txt", id)
	if e != nil {
		t.Fatal(e)
	}
	if result.(map[string]any)["bytes"] != int64(8) {
		t.Fatal("snapshot size incorrect")
	}
	if e = os.WriteFile(filePath, []byte("changed"), 0644); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(site, ".panel-files", "shares", id, "payload"))
	if e != nil || string(b) != "original" {
		t.Fatal("share snapshot changed with source", e)
	}
	if _, e = f.purgeShare(id); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(site, ".panel-files", "shares", id)); !os.IsNotExist(e) {
		t.Fatal("revoked snapshot remained")
	}
	if e = os.Symlink("/etc/passwd", filepath.Join(site, "public", "link")); e != nil {
		t.Fatal(e)
	}
	if _, e = f.prepareShare("link", core.ID()); e == nil {
		t.Fatal("shared a symlink")
	}
}
func makeZip(t *testing.T, name string, mode os.FileMode) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	h := &zip.FileHeader{Name: name, Method: zip.Store}
	h.SetMode(mode)
	out, e := w.CreateHeader(h)
	if e != nil {
		t.Fatal(e)
	}
	io.WriteString(out, "content")
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestZIPExtractionBoundaryAndAtomicPublication(t *testing.T) {
	for _, c := range []struct {
		name, path string
		mode       os.FileMode
		mutate     string
	}{{"parent", "../escape", 0644, ""}, {"absolute", "/tmp/escape", 0644, ""}, {"link", "symlink", os.ModeSymlink | 0777, ""}, {"reserved", ".panel-files/key", 0644, ""}, {"oversized", "large", 0644, "size"}, {"bad CRC", "regular", 0644, "crc"}} {
		t.Run(c.name, func(t *testing.T) {
			f, site := fileFixture(t)
			z := makeZip(t, c.path, c.mode)
			if c.mutate == "size" {
				at := bytes.Index(z, []byte{'P', 'K', 1, 2})
				binary.LittleEndian.PutUint32(z[at+24:], uint32(core.MaxFileUpload+1))
			}
			if c.mutate == "crc" {
				at := bytes.Index(z, []byte("content"))
				z[at] = 'X'
			}
			os.WriteFile(filepath.Join(site, "public/bad.zip"), z, 0644)
			if _, e := f.extract("bad.zip", "destination"); e == nil {
				t.Fatal("unsafe archive accepted")
			}
			if _, e := os.Stat(filepath.Join(site, "public/destination")); !os.IsNotExist(e) {
				t.Fatal("partial archive was published")
			}
		})
	}
	f, site := fileFixture(t)
	os.Mkdir(filepath.Join(site, "public/assets"), 0755)
	os.WriteFile(filepath.Join(site, "public/assets/hello.txt"), []byte("中文 ZIP"), 0644)
	if _, e := f.compress("assets", "assets.zip"); e != nil {
		t.Fatal(e)
	}
	if _, e := f.extract("assets.zip", "expanded"); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(site, "public/expanded/assets/hello.txt"))
	if e != nil || string(b) != "中文 ZIP" {
		t.Fatal("valid ZIP round trip failed", e)
	}
	if _, e = f.extract("assets.zip", "expanded"); e == nil {
		t.Fatal("extract replaced existing destination")
	}
}

func tarBytes(t *testing.T, name string, kind byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	data := []byte("压缩文件验收")
	header := &tar.Header{Name: name, Mode: 0644, Typeflag: kind, Size: int64(len(data))}
	if kind != tar.TypeReg {
		header.Size = 0
	}
	if e := w.WriteHeader(header); e != nil {
		t.Fatal(e)
	}
	if kind == tar.TypeReg {
		if _, e := w.Write(data); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return buf.Bytes()
}

func TestTARExtractionFormatsAndBoundaries(t *testing.T) {
	raw := tarBytes(t, "dir/hello.txt", tar.TypeReg)
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, e := gw.Write(raw); e != nil {
		t.Fatal(e)
	}
	if e := gw.Close(); e != nil {
		t.Fatal(e)
	}
	var xzb bytes.Buffer
	xw, e := xz.NewWriter(&xzb)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = xw.Write(raw); e != nil {
		t.Fatal(e)
	}
	if e = xw.Close(); e != nil {
		t.Fatal(e)
	}
	bzb, e := base64.StdEncoding.DecodeString("QlpoOTFBWSZTWYg58+8AAG77+cqAQABAAf0ACABmZJ5AAI0FAAAwAQwHoAgIIAB1FahoAA0GmmQAMnpBJST0mTCNNMmNRo0wJoabOiHkIMmoQiR00Jyj4QIEMBg6Di0TWCOjwEkMWOl2YpoQqrPbgdBMUJUpKp+N+lsIsfWfCtotaOgAg/i7kinChIRBz594")
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		ext  string
		data []byte
	}{{".tar", raw}, {".tar.gz", gz.Bytes()}, {".tar.bz2", bzb}, {".tar.xz", xzb.Bytes()}} {
		t.Run(tc.ext, func(t *testing.T) {
			f, site := fileFixture(t)
			if e := os.WriteFile(filepath.Join(site, "public/archive"+tc.ext), tc.data, 0644); e != nil {
				t.Fatal(e)
			}
			if _, e := f.extract("archive"+tc.ext, "expanded"); e != nil {
				t.Fatal(e)
			}
			content, e := os.ReadFile(filepath.Join(site, "public/expanded/dir/hello.txt"))
			if e != nil || string(content) != "压缩文件验收" {
				t.Fatal("wrong extracted content", e)
			}
			if _, e := f.extract("archive"+tc.ext, "expanded"); e == nil {
				t.Fatal("replaced existing directory")
			}
		})
	}
	for _, tc := range []struct {
		name string
		kind byte
	}{{"../outside", tar.TypeReg}, {"/tmp/outside", tar.TypeReg}, {".panel-secret/key", tar.TypeReg}, {"link", tar.TypeSymlink}, {"hardlink", tar.TypeLink}} {
		t.Run(tc.name, func(t *testing.T) {
			f, site := fileFixture(t)
			if e := os.WriteFile(filepath.Join(site, "public/bad.tar"), tarBytes(t, tc.name, tc.kind), 0644); e != nil {
				t.Fatal(e)
			}
			if _, e := f.extract("bad.tar", "expanded"); e == nil {
				t.Fatal("unsafe TAR accepted")
			}
			if _, e := os.Stat(filepath.Join(site, "public/expanded")); !os.IsNotExist(e) {
				t.Fatal("partial TAR published")
			}
		})
	}
}

func TestTARCreationRoundTrip(t *testing.T) {
	f, site := fileFixture(t)
	if e := os.MkdirAll(filepath.Join(site, "public", "bundle", "empty"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(site, "public", "bundle", "中文.txt"), []byte("tar 创建与解压\n"), 0644); e != nil {
		t.Fatal(e)
	}
	for _, suffix := range []string{".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"} {
		archive := "bundle" + suffix
		if _, e := f.compress("bundle", archive); e != nil {
			t.Fatalf("create %s: %v", suffix, e)
		}
		target := "restored-" + strings.ReplaceAll(strings.TrimPrefix(suffix, "."), ".", "-")
		if _, e := f.extract(archive, target); e != nil {
			t.Fatalf("extract %s: %v", suffix, e)
		}
		b, e := os.ReadFile(filepath.Join(site, "public", target, "bundle", "中文.txt"))
		if e != nil || string(b) != "tar 创建与解压\n" {
			t.Fatalf("content %s: %v", suffix, e)
		}
		if st, e := os.Stat(filepath.Join(site, "public", target, "bundle", "empty")); e != nil || !st.IsDir() {
			t.Fatalf("empty directory %s: %v", suffix, e)
		}
	}
}

func TestFileCopyAndNestedUploadDirectories(t *testing.T) {
	f, site := fileFixture(t)
	if _, e := f.Action(core.FileAction{Action: "mkdirs", Path: "assets/css/theme"}); e != nil {
		t.Fatal(e)
	}
	if _, e := f.Upload("assets/css/theme/site.css", "", strings.NewReader("body{}"), 6); e != nil {
		t.Fatal(e)
	}
	if _, e := f.Action(core.FileAction{Action: "copy", Path: "assets", Destination: "assets-copy"}); e != nil {
		t.Fatal(e)
	}
	content, e := os.ReadFile(filepath.Join(site, "public/assets-copy/css/theme/site.css"))
	if e != nil || string(content) != "body{}" {
		t.Fatal("copy mismatch", e)
	}
	if _, e := f.Action(core.FileAction{Action: "copy", Path: "assets", Destination: "assets-copy"}); e == nil {
		t.Fatal("overwrote copy")
	}
	if _, e := f.Action(core.FileAction{Action: "copy", Path: "assets", Destination: "assets/new"}); e == nil {
		t.Fatal("copied folder inside itself")
	}
	if e := os.Symlink("assets", filepath.Join(site, "public/link")); e != nil {
		t.Fatal(e)
	}
	if _, e := f.Action(core.FileAction{Action: "mkdirs", Path: "link/new"}); e == nil {
		t.Fatal("mkdirs followed symlink")
	}
	if _, e := f.Action(core.FileAction{Action: "copy", Path: "link", Destination: "copied-link"}); e == nil {
		t.Fatal("copied symlink")
	}
}
func TestUploadRejectsTruncationAndWrongDigest(t *testing.T) {
	f, site := fileFixture(t)
	if _, e := f.Upload("short.bin", "", strings.NewReader("ab"), 3); e == nil {
		t.Fatal("accepted truncated upload")
	}
	if _, e := f.Upload("digest.bin", core.Hash("other"), strings.NewReader("ab"), 2); e == nil {
		t.Fatal("accepted wrong checksum")
	}
	entries, _ := os.ReadDir(filepath.Join(site, "public"))
	if len(entries) != 0 {
		t.Fatal("failed upload was published")
	}
}

func TestFilePublicationCannotFollowLinkIntoSitePrivateDirectory(t *testing.T) {
	f, site := fileFixture(t)
	if e := os.Mkdir(filepath.Join(site, "private"), 0700); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(site, "private/secret"), []byte("keep private"), 0600)
	os.Symlink("../private", filepath.Join(site, "public/private-link"))
	if _, e := f.Upload("private-link/new", "", strings.NewReader("bad"), 3); e == nil {
		t.Fatal("upload entered site-private directory")
	}
	f.Upload("ordinary.txt", "", strings.NewReader("text"), 4)
	operations := []core.FileAction{
		{Action: "rename", Path: "private-link/secret", Destination: "leaked.txt"},
		{Action: "rename", Path: "ordinary.txt", Destination: "private-link/secret2"},
		{Action: "trash", Path: "private-link/secret"},
		{Action: "compress", Path: "ordinary.txt", Destination: "private-link/archive.zip"},
	}
	for _, in := range operations {
		if _, e := f.Action(in); e == nil {
			t.Fatalf("%s entered private directory", in.Action)
		}
	}
	f.Upload("zip.zip", "", bytes.NewReader(makeZip(t, "safe.txt", 0600)), int64(len(makeZip(t, "safe.txt", 0600))))
	if _, e := f.Action(core.FileAction{Action: "extract", Path: "zip.zip", Destination: "private-link/unpacked"}); e == nil {
		t.Fatal("extract entered private directory")
	}
	recycled, e := f.Action(core.FileAction{Action: "trash", Path: "ordinary.txt"})
	if e != nil {
		t.Fatal(e)
	}
	item := recycled.(core.TrashEntry)
	if _, e := f.Action(core.FileAction{Action: "restore", TrashID: item.ID, Destination: "private-link/restored"}); e == nil {
		t.Fatal("restore entered private directory")
	}
	b, e := os.ReadFile(filepath.Join(site, "private/secret"))
	if e != nil || string(b) != "keep private" {
		t.Fatal("private file changed")
	}
	entries, _ := os.ReadDir(filepath.Join(site, "private"))
	if len(entries) != 1 {
		t.Fatal("unexpected private file publication")
	}
}
func TestFilePaginationBoundsResponseAndAvoidsOverflow(t *testing.T) {
	entries := make([]core.FileEntry, 130)
	for i := range entries {
		entries[i] = core.FileEntry{Name: fmt.Sprint(i), Path: strings.Repeat("<", 1000)}
	}
	for _, query := range []string{"page=1&limit=30", "page=2&limit=100", "page=9223372036854775807&limit=100", "page=-1&limit=999999"} {
		out := filePage(httptest.NewRequest("GET", "/?"+query, nil), entries)
		batch := out["entries"].([]core.FileEntry)
		if len(batch) > 100 {
			t.Fatal("unbounded page")
		}
		b, _ := json.Marshal(out)
		if len(b) > 1024*1024 {
			t.Fatal("response exceeds executor transport limit")
		}
	}
	empty := filePage(httptest.NewRequest("GET", "/?page=99", nil), []core.FileEntry{})
	if len(empty["entries"].([]core.FileEntry)) != 0 || empty["page"].(int) != 1 {
		t.Fatal("empty pagination mismatch")
	}
}
