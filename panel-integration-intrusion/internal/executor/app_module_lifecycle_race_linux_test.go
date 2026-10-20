//go:build linux

package executor

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	s := New(Config{SystemRoot: t.TempDir(), SecurityDir: t.TempDir()})
	path := filepath.Join(s.moduleDir("disk-analysis"), "installed.json")
	if err := moduleWrite(path, map[string]any{"id": "disk-analysis", "version": "1.2.0"}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.appModuleRoutes(mux)
	body := &moduleBodyBarrier{Reader: strings.NewReader("{}"), read: make(chan struct{})}
	request := httptest.NewRequest("POST", "/v1/app-modules/disk-analysis/run", body)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	s.mu.Lock()
	go func() {
		mux.ServeHTTP(response, request)
		close(done)
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
	if response.Code != 409 || !strings.Contains(response.Body.String(), "已卸载") {
		t.Fatal("queued operation ran against an uninstalled module", response.Code, response.Body.String())
	}
	if exists(filepath.Join(s.moduleDir("disk-analysis"), "last-report.json")) {
		t.Fatal("uninstalled module recreated a report")
	}
}
