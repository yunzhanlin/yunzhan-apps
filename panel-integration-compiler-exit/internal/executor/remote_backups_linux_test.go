//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func TestWebDAVRemoteCopyUploadsVerifiesMovesAndWritesManifest(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private backup ownership test requires root")
	}
	var mu sync.Mutex
	objects := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		if user != "panel" || pass != "secret" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "PROPFIND":
			w.WriteHeader(207)
		case "MKCOL":
			w.WriteHeader(201)
		case http.MethodPut:
			objects[r.URL.Path], _ = io.ReadAll(r.Body)
			w.WriteHeader(201)
		case http.MethodGet:
			value, ok := objects[r.URL.Path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write(value)
		case "MOVE":
			destination, _ := url.Parse(r.Header.Get("Destination"))
			value, ok := objects[r.URL.Path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			objects[destination.Path] = value
			delete(objects, r.URL.Path)
			w.WriteHeader(201)
		default:
			w.WriteHeader(405)
		}
	}))
	defer server.Close()
	previous := siteBackups
	siteBackups = filepath.Join(t.TempDir(), "sites")
	t.Cleanup(func() { siteBackups = previous })
	siteID, backupID := core.ID(), core.ID()
	dir := filepath.Join(siteBackups, siteID)
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	content := []byte("verified remote zip bytes")
	sum := sha256.Sum256(content)
	backup := core.SiteBackup{ID: backupID, SiteID: siteID, Format: "zip", Files: 1, SourceBytes: 8, Bytes: int64(len(content)), SHA256: hex.EncodeToString(sum[:]), CreatedAt: core.Now()}
	raw, _ := json.Marshal(backup)
	if e := os.WriteFile(filepath.Join(dir, backupID+".zip"), content, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, backupID+".json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	request := core.RemoteBackupRequest{CopyID: core.ID(), Remote: core.BackupRemote{ID: core.ID(), BaseURL: server.URL + "/dav", Username: "panel", PathPrefix: "host-a"}, Password: "secret", Kind: "site", Site: &backup}
	result, e := syncRemoteBackup(context.Background(), request)
	if e != nil || result.Bytes != backup.Bytes || result.SHA256 != backup.SHA256 {
		t.Fatal(result, e)
	}
	mu.Lock()
	defer mu.Unlock()
	remotePath := "/dav" + result.RemotePath
	if string(objects[remotePath]) != string(content) || len(objects[remotePath+".manifest.json"]) == 0 {
		t.Fatal("remote file or manifest missing", objects)
	}
	for name := range objects {
		if filepath.Ext(name) == ".part-"+request.CopyID {
			t.Fatal("partial object retained", name)
		}
	}
}
