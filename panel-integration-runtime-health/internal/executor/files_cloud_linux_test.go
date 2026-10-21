//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"local/panel/internal/core"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCloudFileUploadVerifiesAndWillNotOverwrite(t *testing.T) {
	_, site := fileFixture(t)
	siteID := filepath.Base(site)
	content := []byte("cloud-file-check")
	if e := os.WriteFile(filepath.Join(site, "public", "source.txt"), content, 0600); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	_ = os.WriteFile(outside, []byte("secret"), 0600)
	_ = os.Symlink(outside, filepath.Join(site, "public", "link.txt"))
	var mu sync.Mutex
	objects := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, _ := r.BasicAuth()
		if user != "admin" || password != "test-password" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "MKCOL":
			w.WriteHeader(201)
		case http.MethodPut:
			objects[r.URL.Path], _ = io.ReadAll(r.Body)
			w.WriteHeader(201)
		case http.MethodGet:
			item, ok := objects[r.URL.Path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write(item)
		case "MOVE":
			u, _ := url.Parse(r.Header.Get("Destination"))
			if _, exists := objects[u.Path]; exists {
				w.WriteHeader(412)
				return
			}
			objects[u.Path] = objects[r.URL.Path]
			delete(objects, r.URL.Path)
			w.WriteHeader(201)
		case http.MethodDelete:
			delete(objects, r.URL.Path)
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	}))
	defer server.Close()
	svc := New(Config{SitesDir: filepath.Dir(site)})
	in := core.FileCloudUpload{Path: "source.txt", Remote: core.BackupRemote{BaseURL: server.URL + "/dav", Username: "admin", PathPrefix: "host-a", Enabled: true}, Password: "test-password"}
	out, e := svc.uploadSiteFileToDAV(context.Background(), siteID, in)
	sum := sha256.Sum256(content)
	if e != nil || out.Bytes != int64(len(content)) || out.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal(out, e)
	}
	remoteURL, _ := url.Parse(out.RemotePath)
	mu.Lock()
	remoteBytes := append([]byte(nil), objects[remoteURL.Path]...)
	mu.Unlock()
	if string(remoteBytes) != string(content) {
		t.Fatal("remote content differs")
	}
	if _, e = svc.uploadSiteFileToDAV(context.Background(), siteID, in); e == nil {
		t.Fatal("remote collision overwrote existing file")
	}
	in.Path = "link.txt"
	if _, e = svc.uploadSiteFileToDAV(context.Background(), siteID, in); e == nil {
		t.Fatal("cloud upload followed symlink")
	}
}
