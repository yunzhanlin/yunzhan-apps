package core

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPanelStaticHandlerCompressedAsset(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "assets"), 0755); err != nil {
		t.Fatal(err)
	}
	content := []byte(strings.Repeat("const panel = true;\n", 500))
	asset := filepath.Join(root, "assets", "index-abc.js")
	if err := os.WriteFile(asset, content, 0644); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(asset+".gz", compressed.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	handler := panelStaticHandler(root)

	request := httptest.NewRequest(http.MethodGet, "/assets/index-abc.js", nil)
	request.Header.Set("Accept-Encoding", "gzip, deflate")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 || response.Header().Get("Content-Encoding") != "gzip" || !strings.Contains(response.Header().Get("Content-Type"), "javascript") || !strings.Contains(response.Header().Get("Cache-Control"), "immutable") || response.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatalf("compressed asset headers: code=%d headers=%v", response.Code, response.Header())
	}
	reader, err := gzip.NewReader(bytes.NewReader(response.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(decoded, content) || response.Body.Len() >= len(content) {
		t.Fatalf("compressed asset does not decode or save transfer bytes: %v", err)
	}

	request = httptest.NewRequest(http.MethodGet, "/assets/index-abc.js", nil)
	request.Header.Set("Accept-Encoding", "gzip;q=0")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 || response.Header().Get("Content-Encoding") != "" || !bytes.Equal(response.Body.Bytes(), content) {
		t.Fatal("client that rejects gzip did not receive the ordinary asset")
	}
}
