//go:build linux

package executor

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

func TestWAFObservationSharesReadsButExcludesMutation(t *testing.T) {
	s, path, data := wafBodyLogFixture(t)
	if err := s.writeSoftwareManifest(softwareManifest{ID: "nginx-waf", Version: core.WAFVersion, Settings: core.WAFSettings(core.DefaultWAFConfig()), InstalledAt: core.Now()}); err != nil {
		t.Fatal(err)
	}
	entry, err := s.snapshotAndTruncateWAFBodyLog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	first, err := s.lockWAFObservation()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(s.Config).lockWAFObservation()
	if err != nil {
		t.Fatal("independent reader rejected", err)
	}
	defer second.Close()
	if err := s.verifyWAFHealthLock(first); err == nil {
		t.Fatal("shared observation accepted as exclusive migration proof")
	}
	if _, err := s.lockWAFConfiguration(); err == nil {
		t.Fatal("mutation passed two active readers")
	}
	if _, err := s.rotateWAFBodyLog(context.Background()); err == nil {
		t.Fatal("rotation passed readers")
	}
	if err := s.removeWAFBodyLogArchive(context.Background(), entry.ID, entry.SHA256); err == nil {
		t.Fatal("deletion passed readers")
	}
	if err := s.wafBodyLogHealth(context.Background()); err != nil {
		t.Fatal("health observation conflicts with readers", err)
	}
	for _, url := range []string{"/v1/software/nginx-waf/body-report?limit=10", "/v1/software/nginx-waf/body-log/archives", "/v1/software/nginx-waf/body-log/archives/" + entry.ID} {
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, httptest.NewRequest("GET", url, nil))
		if response.Code != 200 {
			t.Fatal("compatible observation", url, response.Code, response.Body.String())
		}
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(data) {
		t.Fatal("read changed log", err)
	}
	first.Close()
	second.Close()
	writer, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := s.lockWAFObservation(); err == nil {
		t.Fatal("reader passed actual writer")
	}
	if err := s.verifyWAFHealthLock(writer); err != nil {
		t.Fatal("exclusive migration identity lost", err)
	}
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/v1/software/nginx-waf/body-log/archives", nil))
	if response.Code != 503 {
		t.Fatal("actual mutation not surfaced", response.Code)
	}
	if _, err := s.lockWAFFile(syscall.LOCK_UN); err == nil {
		t.Fatal("invalid lock operation accepted")
	}
}

func TestWAFAbsentLegacyLogOnUbuntuDefaultDirectory(t *testing.T) {
	s := wafPolicyFixture(t)
	if err := s.writeSoftwareManifest(softwareManifest{ID: "nginx-waf", Version: core.WAFVersion, Settings: core.WAFSettings(core.DefaultWAFConfig()), InstalledAt: core.Now()}); err != nil {
		t.Fatal(err)
	}
	directory := s.systemPath("/var/log/nginx")
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(directory)
	if err := os.Chmod(parent, 0775); err != nil {
		t.Fatal(err)
	}
	page, err := s.readWAFBodyEvents()
	if err != nil || page.Available || page.LegacyLog || len(page.Events) != 0 {
		t.Fatal("missing metadata fabricated or rejected", page, err)
	}
	info, _ := os.Stat(parent)
	if info.Mode().Perm() != 0775 {
		t.Fatal("system log permissions repaired by read")
	}
	legacy := filepath.Join(directory, "panel-waf-body-events.log")
	if err := os.WriteFile(legacy, []byte("private untrusted legacy payload\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readWAFBodyEvents(); err == nil {
		t.Fatal("group-writable legacy ancestor now trusted for existing content")
	}
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/v1/software/nginx-waf/body-report", nil))
	if response.Code != 503 || strings.Contains(response.Body.String(), "private untrusted") {
		t.Fatal("untrusted content read or exported", response.Code, response.Body.String())
	}
}

func TestWAFMissingLegacyObservationRejectsForeignPaths(t *testing.T) {
	for _, fault := range []string{"linked-log-directory", "linked-leaf", "world-writable-var-log", "group-writable-nginx", "non-directory"} {
		t.Run(fault, func(t *testing.T) {
			s := wafPolicyFixture(t)
			directory := s.systemPath("/var/log/nginx")
			if err := os.MkdirAll(filepath.Dir(directory), 0755); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "linked-log-directory":
				if err := os.Symlink(t.TempDir(), directory); err != nil {
					t.Fatal(err)
				}
			case "non-directory":
				if err := os.WriteFile(directory, []byte("not a directory"), 0644); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Mkdir(directory, 0755); err != nil {
					t.Fatal(err)
				}
				if fault == "world-writable-var-log" {
					if err := os.Chmod(filepath.Dir(directory), 0777); err != nil {
						t.Fatal(err)
					}
				}
				if fault == "group-writable-nginx" {
					if err := os.Chmod(directory, 0775); err != nil {
						t.Fatal(err)
					}
				}
				if fault == "linked-leaf" {
					if err := os.Symlink(filepath.Join(t.TempDir(), "absent"), filepath.Join(directory, "panel-waf-body-events.log")); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := s.readWAFBodyEvents(); err == nil {
				t.Fatal("foreign path hidden as missing")
			}
		})
	}
}
