//go:build linux

package executor

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
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
