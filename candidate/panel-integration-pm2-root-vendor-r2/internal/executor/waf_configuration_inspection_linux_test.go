//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func inspectionFixtureLock(t *testing.T, s *Service) {
	t.Helper()
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
}
func TestWAFConfigurationInspectionOriginalVersionAndDriftAreReadOnly(t *testing.T) {
	for _, version := range []string{"2.0.1", "2.1.0", "2.1.1", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.5.1", core.WAFVersion} {
		t.Run(version, func(t *testing.T) {
			s, _ := wafLegacyVersionFixture(t, version)
			inspectionFixtureLock(t, s)
			s.Config.Run = func(context.Context, string, ...string) (string, error) {
				t.Error("inspection executed an external command")
				return "", errors.New("denied")
			}
			before := wafConfigurationTree(t, s.Config.SystemRoot)
			got, err := s.inspectInstalledWAFConfiguration(context.Background())
			if err != nil || got.InstalledVersion != version || !got.FilesystemMatches || got.EnforcementVerified || len(got.Differences) != 0 {
				t.Fatal(got, err)
			}
			if after := wafConfigurationTree(t, s.Config.SystemRoot); !reflect.DeepEqual(before, after) {
				t.Fatal("inspection mutated configuration")
			}
			h, _ := wafFiles(s)
			f, err := os.OpenFile(h, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			f.WriteString("\n# private-policy-secret-not-for-browser\n")
			f.Close()
			before = wafConfigurationTree(t, s.Config.SystemRoot)
			got, err = s.inspectInstalledWAFConfiguration(context.Background())
			if err != nil || got.FilesystemMatches || got.EnforcementVerified || len(got.Differences) != 1 || got.Differences[0].Scope != "http-rules" || got.InstalledVersion != version {
				t.Fatal("unavailable or promoted legacy render", got, err)
			}
			raw, _ := json.Marshal(got)
			if strings.Contains(string(raw), "private-policy-secret") || strings.Contains(string(raw), s.Config.SystemRoot) {
				t.Fatal("raw config/path exposed")
			}
			if after := wafConfigurationTree(t, s.Config.SystemRoot); !reflect.DeepEqual(before, after) {
				t.Fatal("drift repaired by GET")
			}
		})
	}
}
func TestWAFConfigurationInspectionRejectsOriginalLockAndPendingWithoutCreation(t *testing.T) {
	for _, fault := range []string{"missing", "symlink", "hardlink", "mode", "nonempty", "held", "pending", "site-link"} {
		t.Run(fault, func(t *testing.T) {
			s, _ := wafLegacy201Fixture(t)
			inspectionFixtureLock(t, s)
			lockPath := filepath.Join(s.Config.SecurityDir, "waf-configuration.lock")
			var setupErr error
			switch fault {
			case "missing":
				setupErr = os.Remove(lockPath)
			case "symlink":
				if err := os.Rename(lockPath, lockPath+".original"); err != nil {
					t.Fatal(err)
				}
				setupErr = os.Symlink(lockPath+".original", lockPath)
			case "hardlink":
				setupErr = os.Link(lockPath, lockPath+".other")
			case "mode":
				setupErr = os.Chmod(lockPath, 0644)
			case "nonempty":
				setupErr = os.WriteFile(lockPath, []byte("foreign"), 0600)
			case "held":
				lock, err := s.lockWAFConfiguration()
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			case "pending":
				// The private transaction directory is absent in a freshly
				// rendered fixture. A failed setup write is not a pending case.
				if err := os.MkdirAll(filepath.Dir(s.wafPendingPath()), 0700); err != nil {
					t.Fatal(err)
				}
				setupErr = os.WriteFile(s.wafPendingPath(), []byte("original unknown transaction"), 0600)
			case "site-link":
				id := core.ID()
				setupErr = os.Symlink(s.Config.NginxConf, filepath.Join(s.Config.ConfDir, id+".conf"))
			}
			if setupErr != nil {
				t.Fatal("negative fixture preparation failed", fault, setupErr)
			}
			before := wafConfigurationTree(t, s.Config.SystemRoot)
			if got, err := s.inspectInstalledWAFConfiguration(context.Background()); err == nil {
				t.Fatal("unsafe observation accepted", fault, got)
			}
			if after := wafConfigurationTree(t, s.Config.SystemRoot); !reflect.DeepEqual(before, after) {
				t.Fatal("refusal mutated original files", fault)
			}
		})
	}
}
func TestWAFConfigurationInspectionFixedGETAndNoQueryOrCommands(t *testing.T) {
	s, _ := wafLegacy201Fixture(t)
	inspectionFixtureLock(t, s)
	mux := http.NewServeMux()
	s.wafConfigurationInspectionRoutes(mux)
	before := wafConfigurationTree(t, s.Config.SystemRoot)
	for _, suffix := range []string{"?", "?path=/etc/shadow", "?version=2.5.2", "?repair=1"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/nginx-waf/config-inspection"+suffix, nil))
		if w.Code != 400 {
			t.Fatal("query", suffix, w.Code)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, "/v1/software/nginx-waf/config-inspection", nil))
		if w.Code != 405 {
			t.Fatal("mutation method", method, w.Code)
		}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/nginx-waf/config-inspection", nil))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err := core.DecodeWAFConfigurationInspection(w.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if after := wafConfigurationTree(t, s.Config.SystemRoot); !reflect.DeepEqual(before, after) {
		t.Fatal("route mutated filesystem")
	}
}
