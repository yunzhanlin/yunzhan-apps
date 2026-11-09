package executor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"testing"
)

func TestAnalyticsHTMLHeaderPatchRejectsUnreviewedSource(t *testing.T) {
	for _, source := range [][]byte{nil, []byte(analyticsNJSHeaderBefore), []byte(analyticsNJSHeaderBefore + analyticsNJSHeaderBefore), []byte(analyticsNJSHeaderAfter)} {
		if result, err := patchAnalyticsNJSHeaders(source); err == nil || result != nil {
			t.Fatal("unreviewed source received compiler authority")
		}
	}
}

func TestAnalyticsHTMLHeaderPatchActualPinnedSource(t *testing.T) {
	archive := os.Getenv("PANEL_QA_ANALYTICS_NJS_ARCHIVE")
	if archive == "" && os.Getenv("PANEL_QA_ANALYTICS_NATIVE") == "1" {
		archive = "/tmp/sources/njs-1.0.1.tar.gz"
	}
	if archive == "" {
		t.Skip("requires retained pinned official njs archive")
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	reader := tar.NewReader(z)
	for {
		header, err := reader.Next()
		if err != nil {
			t.Fatal("fixed source file absent", err)
		}
		if header.Name != "njs-1.0.1/nginx/ngx_http_js_module.c" {
			continue
		}
		original, err := io.ReadAll(io.LimitReader(reader, (2<<20)+1))
		if err != nil || len(original) > 2<<20 {
			t.Fatal("bounded source read", err)
		}
		patched, err := patchAnalyticsNJSHeaders(original)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Count(patched, []byte(analyticsNJSHeaderAfter)) != 1 || !bytes.Equal(bytes.Replace(patched, []byte(analyticsNJSHeaderAfter), []byte(analyticsNJSHeaderBefore), 1), original) {
			t.Fatal("patch changed bytes outside the single reviewed deletion handler")
		}
		if _, err := patchAnalyticsNJSHeaders(patched); err == nil {
			t.Fatal("already patched source accepted again")
		}
		break
	}
}
