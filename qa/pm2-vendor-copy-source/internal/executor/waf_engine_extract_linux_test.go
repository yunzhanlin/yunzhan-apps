//go:build linux

package executor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type wafArchiveFixture struct {
	name, link, body string
	kind             byte
	mode             int64
}

func wafArchiveFixtureBytes(t *testing.T, entries []wafArchiveFixture) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Linkname: e.link, Mode: e.mode, Typeflag: e.kind}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func wafStageFixture(t *testing.T, data []byte) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	archive := filepath.Join(dir, "source.tar.gz")
	if err := os.WriteFile(archive, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return archive, filepath.Join(dir, "extracted"), hex.EncodeToString(sum[:])
}

func TestWAFExtractionPreflightAndSafeRelativeLinks(t *testing.T) {
	data := wafArchiveFixtureBytes(t, []wafArchiveFixture{
		{"reviewed", "", "", tar.TypeDir, 07777},
		{"reviewed/source.c", "", "ordinary source", tar.TypeReg, 06777},
		{"reviewed/include/source.c", "../source.c", "", tar.TypeSymlink, 0777},
		{"reviewed/include", "", "", tar.TypeDir, 0777},
	})
	archive, dest, sum := wafStageFixture(t, data)
	if err := extractPinnedWAFSource(context.Background(), archive, dest, "reviewed", sum); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "reviewed/include/source.c"))
	if err != nil || string(b) != "ordinary source" {
		t.Fatal("safe relative symlink/source not retained", err)
	}
	for _, pair := range []struct {
		path string
		mode os.FileMode
	}{{dest, 0700}, {filepath.Join(dest, "reviewed"), 0755}, {filepath.Join(dest, "reviewed/source.c"), 0755}} {
		st, err := os.Stat(pair.path)
		if err != nil || st.Mode().Perm() != pair.mode || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			t.Fatal("archive privilege bits leaked", pair.path, err)
		}
	}
	if st, err := os.Stat(filepath.Join(dest, "reviewed/source.c")); err != nil || st.ModTime().Unix() != 0 {
		t.Fatal("reviewed generated-source timestamp ordering not preserved", err)
	}
	if err := extractPinnedWAFSource(context.Background(), archive, dest, "reviewed", sum); err == nil {
		t.Fatal("reused/overwrote extracted destination")
	}
	b, _ = os.ReadFile(filepath.Join(dest, "reviewed/source.c"))
	if string(b) != "ordinary source" {
		t.Fatal("existing source changed")
	}
}

func TestWAFExtractionRejectsDangerousArchiveBeforeFirstWrite(t *testing.T) {
	file := wafArchiveFixture{"reviewed/source", "", "safe bytes", tar.TypeReg, 0644}
	for name, entries := range map[string][]wafArchiveFixture{
		"absolute":           {{"/reviewed/escape", "", "bad", tar.TypeReg, 0644}},
		"parent":             {{"reviewed/../escape", "", "bad", tar.TypeReg, 0644}},
		"other-root":         {{"other/escape", "", "bad", tar.TypeReg, 0644}},
		"noncanonical":       {{"reviewed//escape", "", "bad", tar.TypeReg, 0644}},
		"backslash":          {{"reviewed/\\escape", "", "bad", tar.TypeReg, 0644}},
		"control":            {{"reviewed/escape\n", "", "bad", tar.TypeReg, 0644}},
		"duplicate":          {file, file},
		"top-file":           {{"reviewed", "", "bad", tar.TypeReg, 0644}},
		"hardlink":           {file, {"reviewed/hard", "reviewed/source", "", tar.TypeLink, 0644}},
		"fifo":               {{"reviewed/fifo", "", "", tar.TypeFifo, 0600}},
		"device":             {{"reviewed/device", "", "", tar.TypeChar, 0600}},
		"absolute-link":      {file, {"reviewed/link", "/etc/passwd", "", tar.TypeSymlink, 0777}},
		"escape-link":        {file, {"reviewed/link", "../../outside", "", tar.TypeSymlink, 0777}},
		"missing-link":       {file, {"reviewed/link", "missing", "", tar.TypeSymlink, 0777}},
		"cycle":              {{"reviewed/a", "b", "", tar.TypeSymlink, 0777}, {"reviewed/b", "a", "", tar.TypeSymlink, 0777}},
		"chain":              {file, {"reviewed/a", "source", "", tar.TypeSymlink, 0777}, {"reviewed/b", "a", "", tar.TypeSymlink, 0777}},
		"write-through-link": {{"reviewed/real", "", "", tar.TypeDir, 0755}, {"reviewed/a", "real", "", tar.TypeSymlink, 0777}, {"reviewed/a/file", "", "bad", tar.TypeReg, 0644}},
		"late-link-parent":   {{"reviewed/a/file", "", "bad", tar.TypeReg, 0644}, {"reviewed/real", "", "", tar.TypeDir, 0755}, {"reviewed/a", "real", "", tar.TypeSymlink, 0777}},
		"file-parent":        {file, {"reviewed/source/file", "", "bad", tar.TypeReg, 0644}},
	} {
		t.Run(name, func(t *testing.T) {
			archive, dest, sum := wafStageFixture(t, wafArchiveFixtureBytes(t, entries))
			if err := extractPinnedWAFSource(context.Background(), archive, dest, "reviewed", sum); err == nil {
				t.Fatal("dangerous archive accepted")
			}
			if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("wrote files before complete preflight", err)
			}
		})
	}
}

func TestWAFExtractionDigestCRCAndFileBoundaries(t *testing.T) {
	good := wafArchiveFixtureBytes(t, []wafArchiveFixture{{"reviewed/a", "", "source", tar.TypeReg, 0644}})
	corrupt := bytes.Clone(good)
	corrupt[len(corrupt)-8] ^= 1
	for name, data := range map[string][]byte{"crc": corrupt, "truncated": good[:len(good)-4], "empty": wafArchiveFixtureBytes(t, nil)} {
		t.Run(name, func(t *testing.T) {
			archive, dest, sum := wafStageFixture(t, data)
			if err := extractPinnedWAFSource(context.Background(), archive, dest, "reviewed", sum); err == nil {
				t.Fatal("invalid gzip/tar accepted")
			}
			if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid archive produced a destination")
			}
		})
	}
	archive, dest, sum := wafStageFixture(t, good)
	if err := extractPinnedWAFSource(context.Background(), archive, dest, "reviewed", strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong fixed digest accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := extractPinnedWAFSource(ctx, archive, dest, "reviewed", sum); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled extraction continued", err)
	}
	link := archive + ".link"
	if err := os.Symlink(archive, link); err != nil {
		t.Fatal(err)
	}
	if err := extractPinnedWAFSource(context.Background(), link, dest, "reviewed", sum); err == nil {
		t.Fatal("source archive symbolic link accepted")
	}
	if err := os.Link(archive, archive+".hard"); err != nil {
		t.Fatal(err)
	}
	if err := extractPinnedWAFSource(context.Background(), archive, dest, "reviewed", sum); err == nil {
		t.Fatal("shared hard-linked source archive accepted")
	}
	for _, h := range []*tar.Header{{Name: "reviewed/a", Typeflag: tar.TypeReg, Size: -1}, {Name: "reviewed/a", Typeflag: tar.TypeReg, Size: wafSourceExpandedBytes + 1}, {Name: "reviewed/" + strings.Repeat("a", 1025), Typeflag: tar.TypeReg}, {Name: "reviewed/a", Typeflag: tar.TypeReg, ModTime: time.Unix(-1, 0)}, {Name: "reviewed/a", Typeflag: tar.TypeReg, ModTime: time.Unix(4102444801, 0)}} {
		if _, err := wafSourceEntry(h, "reviewed"); err == nil {
			t.Fatal("unbounded header accepted")
		}
	}
	source := wafEngineSources()[0]
	source.URL = "https://untrusted.invalid/source"
	if err := extractWAFEngineSource(context.Background(), source, "/missing", "/missing"); err == nil {
		t.Fatal("unreviewed source accepted")
	}
}

func TestWAFExtractionAgainstActualPinnedOfficialArchives(t *testing.T) {
	dir := os.Getenv("PANEL_WAF_SOURCE_QA_DIR")
	if dir == "" {
		t.Skip("requires retained official archives; ordinary fixture tests still run")
	}
	if !filepath.IsAbs(dir) || !strings.HasPrefix(dir, "/workspace/.local/commercial-next.oUsYHb/.local/waf-source.") {
		t.Fatal("unexpected owned source fixture directory")
	}
	sources := wafEngineSources()
	for _, version := range []string{"1.24.0", "1.26.3"} {
		source, _ := wafNginxBuildSource(version)
		sources = append(sources, source)
	}
	for _, source := range sources {
		t.Run(source.Name+"-"+source.Version, func(t *testing.T) {
			prefix, err := wafArchivePrefix(source)
			if err != nil {
				t.Fatal(err)
			}
			name := prefix + ".tar.gz"
			if source.Name == "owasp-crs" {
				name = prefix + "-minimal.tar.gz"
			}
			input, err := os.Open(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			staged := filepath.Join(t.TempDir(), "source.tar.gz")
			out, err := os.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, copyErr := io.Copy(out, io.LimitReader(input, wafNativeSourceBytes+1))
			closeErr := out.Close()
			if copyErr != nil || closeErr != nil {
				t.Fatal(copyErr, closeErr)
			}
			dest := filepath.Join(filepath.Dir(staged), "source")
			if err := extractWAFEngineSource(context.Background(), source, staged, dest); err != nil {
				t.Fatal(err)
			}
			if st, err := os.Stat(filepath.Join(dest, prefix)); err != nil || !st.IsDir() {
				t.Fatal("actual source root missing", err)
			}
		})
	}
}
