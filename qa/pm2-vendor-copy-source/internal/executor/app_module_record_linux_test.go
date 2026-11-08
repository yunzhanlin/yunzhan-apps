//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func moduleRecordFixture(t *testing.T) (*Service, string) {
	t.Helper()
	s := New(Config{SecurityDir: filepath.Join(t.TempDir(), "security")})
	path := filepath.Join(s.moduleDir("task-manager"), "installed.json")
	if err := moduleWrite(path, map[string]any{"id": "task-manager", "version": "1.2.0", "settings": map[string]any{}, "installed_at": core.Now()}); err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestModuleInstalledRecordAbsenceAndLegacyHaveDistinctKnownState(t *testing.T) {
	s, path := moduleRecordFixture(t)
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if status := s.appModuleStatus(context.Background(), "task-manager"); status.StateUnknown || !status.Installed || !status.Healthy {
		t.Fatal(status)
	}
	if after, err := os.Lstat(path); err != nil || !os.SameFile(before, after) {
		t.Fatal("status rewrote record")
	}
	if err := moduleWrite(path, map[string]any{"id": "task-manager", "settings": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if status := s.appModuleStatus(context.Background(), "task-manager"); status.StateUnknown || !status.Installed || status.Version != "1.0" {
		t.Fatal("pre-versioned record incompatible", status)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if status := s.appModuleStatus(context.Background(), "task-manager"); status.StateUnknown || status.Installed {
		t.Fatal("known absence lost", status)
	}
	if _, err := s.moduleInstalledRecord("task-manager"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestModuleUntrustedInstalledRecordFreezesLifecycleAndHidesReport(t *testing.T) {
	for _, mode := range []string{"public-file", "public-module", "writable-modules", "group-writable-modules", "writable-anchor", "foreign-owner", "symlink-file", "symlink-module", "hardlink", "fifo", "directory", "malformed", "duplicate", "escaped-duplicate", "wrong-id", "future-version", "bad-settings"} {
		t.Run(mode, func(t *testing.T) {
			s, path := moduleRecordFixture(t)
			outside := filepath.Join(t.TempDir(), "own-sentinel.json")
			sentinel := []byte(`{"id":"task-manager","version":"1.2.0","settings":{}}`)
			if err := os.WriteFile(outside, sentinel, 0600); err != nil {
				t.Fatal(err)
			}
			if err := moduleWrite(filepath.Join(s.moduleDir("task-manager"), "last-report.json"), map[string]string{"private": "not-returned-while-state-unknown"}); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "public-file":
				os.Chmod(path, 0644)
			case "public-module":
				os.Chmod(filepath.Dir(path), 0755)
			case "writable-modules":
				os.Chmod(filepath.Dir(filepath.Dir(path)), 0777)
			case "group-writable-modules":
				os.Chmod(filepath.Dir(filepath.Dir(path)), 0770)
			case "writable-anchor":
				os.Chmod(s.Config.SecurityDir, 0777)
			case "foreign-owner":
				if os.Geteuid() != 0 {
					t.Skip("actual root-owned private record fixture required for foreign UID")
				}
				if err := os.Chown(path, 1, -1); err != nil {
					t.Fatal(err)
				}
			case "symlink-file":
				os.Remove(path)
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "symlink-module":
				owned := filepath.Dir(path) + "-own-retained"
				if err := os.Rename(filepath.Dir(path), owned); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(owned, filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(filepath.Dir(path), "own-extra")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				os.Remove(path)
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				os.Remove(path)
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				raw := map[string]string{"malformed": "{", "duplicate": `{"id":"task-manager","id":"task-manager"}`, "escaped-duplicate": `{"id":"task-manager","\u0069d":"task-manager"}`, "wrong-id": `{"id":"files-sync"}`, "future-version": `{"id":"task-manager","version":"99.0.0"}`, "bad-settings": `{"id":"task-manager","settings":"not-an-object"}`}[mode]
				if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			status := s.appModuleStatus(context.Background(), "task-manager")
			if !status.StateUnknown || status.Installed || status.Healthy || s.moduleInstalled("task-manager") {
				t.Fatal("untrusted record treated as known installation/absence", mode, status)
			}
			calls := 0
			s.Config.Run = func(context.Context, string, ...string) (string, error) {
				calls++
				return "", errors.New("no external command allowed")
			}
			for _, action := range []string{"install", "configure", "uninstall"} {
				if err := s.appModuleLifecycle(context.Background(), "task-manager", action, nil, func(string) {}); err == nil || calls != 0 {
					t.Fatal("untrusted record mutated lifecycle", mode, action, err)
				}
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/app-modules/task-manager", nil))
			var page struct {
				Status core.SoftwareAppStatus `json:"status"`
				Report any                    `json:"report"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || !page.Status.StateUnknown || page.Report != nil || strings.Contains(w.Body.String(), "not-returned-while-state-unknown") {
				t.Fatal("unsafe report returned", mode, w.Code)
			}
			after, err := os.Lstat(path)
			actual, readErr := os.ReadFile(outside)
			if err != nil || readErr != nil || !os.SameFile(before, after) || string(actual) != string(sentinel) || calls != 0 {
				t.Fatal("refusal changed original fixture or sentinel", mode)
			}
		})
	}
}
