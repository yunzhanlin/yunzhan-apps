//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type moduleBodyBarrier struct {
	io.Reader
	once sync.Once
	read chan struct{}
}

func (b *moduleBodyBarrier) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.read) })
	return b.Reader.Read(p)
}

func TestQueuedModuleOperationCannotRunAfterUninstall(t *testing.T) {
	for _, test := range []struct{ name, id, version, action string }{
		{"disk-read", "disk-analysis", "1.2.0", "run"},
		{"nfs-client-read", "nfs-manager", "1.3.1", "run"},
		{"nfs-server-start", "nfs-manager", "1.3.1", "server-start"},
		{"nfs-export-write", "nfs-manager", "1.3.1", "export-save"},
		{"nfs-client-mount", "nfs-manager", "1.3.1", "mount"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var commands atomic.Int32
			s := New(Config{SystemRoot: t.TempDir(), SecurityDir: t.TempDir(),
				Run: func(context.Context, string, ...string) (string, error) {
					commands.Add(1)
					return "", errors.New("queued test must not invoke a system command")
				}})
			path := filepath.Join(s.moduleDir(test.id), "installed.json")
			if err := moduleWrite(path, map[string]any{"id": test.id, "version": test.version}); err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			s.appModuleRoutes(mux)
			body := &moduleBodyBarrier{Reader: strings.NewReader("{}"), read: make(chan struct{})}
			request := httptest.NewRequest("POST", "/v1/app-modules/"+test.id+"/"+test.action, body)
			response := httptest.NewRecorder()
			done := make(chan struct{})
			s.mu.Lock()
			go func() {
				defer close(done)
				mux.ServeHTTP(response, request)
			}()
			select {
			case <-body.read:
			case <-time.After(5 * time.Second):
				s.mu.Unlock()
				t.Fatal("queued operation did not pass the initial installed check")
			}
			if err := os.Remove(path); err != nil {
				s.mu.Unlock()
				t.Fatal(err)
			}
			s.mu.Unlock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("queued operation did not return")
			}
			if response.Code != 409 || !strings.Contains(response.Body.String(), "未执行排队操作") {
				t.Fatal("queued operation ran against an uninstalled module", response.Code, response.Body.String())
			}
			if commands.Load() != 0 {
				t.Fatal("queued operation invoked a command after uninstall")
			}
			entries, err := os.ReadDir(s.moduleDir(test.id))
			if err != nil || len(entries) != 0 {
				t.Fatal("uninstalled module recreated a report, lock, history or configuration", entries, err)
			}
		})
	}
}
