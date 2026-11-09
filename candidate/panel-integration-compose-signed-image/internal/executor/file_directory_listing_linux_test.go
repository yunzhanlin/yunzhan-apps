//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestDirectorySummaryIndependentOfFilteringAndPagination(t *testing.T) {
	f, site := fileFixture(t)
	root := filepath.Join(site, "public")
	for _, name := range []string{"alpha", "beta"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 23; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("file-%02d.txt", i)), []byte("original\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "alpha", "nested-hit.txt"), []byte("nested\n"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "nested-hit.txt"), []byte("outside\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "external-link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	want := fileDirectorySummary{Directories: 2, Files: 23, Links: 1, Special: 1, Complete: true}
	for _, kind := range []string{"managed", "system", "recursive"} {
		t.Run(kind, func(t *testing.T) {
			var listing map[string]any
			var err error
			switch kind {
			case "managed":
				listing, err = f.List("", "file-22")
			case "system":
				listing, err = listSystemDirectory(root, "/", "file-22")
			case "recursive":
				listing, err = f.SearchTree(context.Background(), "", "nested-hit")
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := listing["summary"].(fileDirectorySummary); got != want {
				t.Fatalf("filtered summary %+v, want %+v", got, want)
			}
			entries := listing["entries"].([]core.FileEntry)
			if len(entries) != 1 || kind == "recursive" && entries[0].Path != "alpha/nested-hit.txt" {
				t.Fatalf("search crossed boundary or changed result: %+v", entries)
			}
		})
	}
	// Exercise the real HTTP route: 27 visible entries, ten on page two, and
	// one filtered result. The direct counts must survive serialization.
	service := New(Config{SitesDir: filepath.Dir(site)})
	for _, query := range []string{"?page=2&limit=10", "?search=file-22&limit=10", "?search=nested-hit&recursive=1&limit=10"} {
		r := httptest.NewRecorder()
		service.Handler().ServeHTTP(r, httptest.NewRequest("GET", "/v1/sites/"+filepath.Base(site)+"/files"+query, nil))
		var result struct {
			Summary fileDirectorySummary `json:"summary"`
			Entries []core.FileEntry     `json:"entries"`
			Total   int                  `json:"total"`
		}
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &result) != nil || result.Summary != want {
			t.Fatalf("route lost summary: status=%d body=%s", r.Code, r.Body)
		}
		if query == "?page=2&limit=10" && (len(result.Entries) != 10 || result.Total != 27) {
			t.Fatalf("pagination changed: %+v", result)
		}
		if query != "?page=2&limit=10" && (len(result.Entries) != 1 || result.Total != 1) {
			t.Fatalf("filtered results changed: %+v", result)
		}
	}
}

func TestDirectorySummaryLimitReportsPartial(t *testing.T) {
	f, site := fileFixture(t)
	root := filepath.Join(site, "public")
	for i := 0; i < 10001; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("bounded-%05d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"managed", "system"} {
		t.Run(kind, func(t *testing.T) {
			var result map[string]any
			var err error
			if kind == "managed" {
				result, err = f.List("", "absent")
			} else {
				result, err = listSystemDirectory(root, "/", "absent")
			}
			if err != nil {
				t.Fatal(err)
			}
			want := fileDirectorySummary{Files: 10000, Truncated: true}
			if result["summary"].(fileDirectorySummary) != want || result["truncated"] != true || len(result["entries"].([]core.FileEntry)) != 0 {
				t.Fatalf("limit hidden as a complete count: %+v", result)
			}
		})
	}
}

func TestDirectorySummaryUsesOpenedDescriptor(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "original")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "kept.txt"), []byte("kept\n"), 0600); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := os.Rename(path, filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), path); err != nil {
		t.Fatal(err)
	}
	entries, summary, _, err := readFileDirectory(dir, path, false)
	if err != nil || summary != (fileDirectorySummary{Files: 1, Complete: true}) || len(entries) != 1 || entries[0].Name != "kept.txt" {
		t.Fatalf("read substituted pathname: entries=%+v summary=%+v err=%v", entries, summary, err)
	}
	before := []byte("kept\n")
	after, err := os.ReadFile(filepath.Join(root, "moved", "kept.txt"))
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("metadata read changed original file")
	}
}
