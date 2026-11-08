//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

func pm2ProjectHTTPRead(s *Service, query string) (*httptest.ResponseRecorder, map[string]any) {
	mux := http.NewServeMux()
	s.pm2ProjectsReadRoutes(mux)
	r := httptest.NewRecorder()
	mux.ServeHTTP(r, httptest.NewRequest("GET", "/v1/app-modules/pm2-manager/projects"+query, nil))
	var page map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &page)
	return r, page
}

func TestPM2ProjectsGETIgnoresDamagedRetrospectiveAndDoesNotAcquireMutationMutex(t *testing.T) {
	s, app, path, calls := pm2StopFixture(t)
	dir := s.moduleDir("pm2-manager")
	originals := map[string][]byte{}
	identities := map[string]os.FileInfo{}
	for _, name := range []string{"history.json", "last-report.json", "configuration-transactions/" + core.ID() + ".intent.json"} {
		file := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("{\"original_unfinished\":"), 0600); err != nil {
			t.Fatal(err)
		}
		originals[file], _ = os.ReadFile(file)
		identities[file], _ = os.Lstat(file)
	}
	originals[path], _ = os.ReadFile(path)
	identities[path], _ = os.Lstat(path)
	s.mu.Lock()
	type result struct {
		r    *httptest.ResponseRecorder
		page map[string]any
	}
	done := make(chan result, 1)
	go func() {
		r, page := pm2ProjectHTTPRead(s, "")
		done <- result{r, page}
	}()
	var got result
	select {
	case got = <-done:
		s.mu.Unlock()
	case <-time.After(2 * time.Second):
		s.mu.Unlock()
		<-done
		t.Fatal("read-only project observation waited for a mutation")
	}
	if got.r.Code != 200 || got.page["projects_readonly"] != true || got.page["project_page_complete"] != true || got.page["configuration_not_inspected"] != true || got.page["history_or_report_written"] != false || len(*calls) != 1 || !strings.HasPrefix((*calls)[0], "show panel-pm2@"+app.ID+".service ") {
		t.Fatal("damaged history prevented a genuine read or caused a mutation", got.r.Code, len(*calls))
	}
	if bytes.Contains(got.r.Body.Bytes(), []byte("environment_cipher")) || bytes.Contains(got.r.Body.Bytes(), []byte("private-environment-before-state-save")) {
		t.Fatal("private environment reached the public project view")
	}
	for file, raw := range originals {
		after, _ := os.ReadFile(file)
		info, _ := os.Lstat(file)
		if !bytes.Equal(raw, after) || !programQueueSame(identities[file], info) {
			t.Fatal("read-only observation rewrote an original", filepath.Base(file))
		}
	}
	for _, name := range []string{"locks", "history.sqlite", "history.sqlite-journal"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("read-only observation created or adopted a store", name, err)
		}
	}
}

func TestPM2ProjectsGETKeepsBadProjectsAndUnknownServicesDistinct(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "permissions", "identity", "service-unknown", "foreign-name", "missing-projects", "bad-query"} {
		t.Run(mode, func(t *testing.T) {
			s, app, path, calls := pm2StopFixture(t)
			query := ""
			dir := filepath.Dir(path)
			switch mode {
			case "symlink":
				if os.Rename(path, path+".original") != nil || os.Symlink(path+".original", path) != nil {
					t.Fatal("fixture link setup")
				}
				// Keep the independent original outside the enumerated namespace.
				if os.Rename(path+".original", filepath.Join(s.Config.SecurityDir, "original-project")) != nil || os.Remove(path) != nil || os.Symlink(filepath.Join(s.Config.SecurityDir, "original-project"), path) != nil {
					t.Fatal("fixture original setup")
				}
			case "hardlink":
				if os.Link(path, filepath.Join(s.Config.SecurityDir, "original-project")) != nil {
					t.Fatal("fixture hardlink setup")
				}
			case "permissions":
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			case "identity":
				app.ID = "different-project"
				if err := moduleWrite(path, app); err != nil {
					t.Fatal(err)
				}
			case "service-unknown":
				s.Config.Run = func(_ context.Context, command string, args ...string) (string, error) {
					if command != "/usr/bin/systemctl" || args[0] != "show" {
						t.Fatal("read-only fixture mutated a service")
					}
					*calls = append(*calls, "show unknown")
					return "", errors.New("owned original service observation unavailable")
				}
			case "foreign-name":
				if err := os.WriteFile(filepath.Join(dir, "original.unexpected"), []byte("retain"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-projects":
				if os.Remove(path) != nil || os.Remove(dir) != nil {
					t.Fatal("fixture empty setup")
				}
			case "bad-query":
				query = "?limit=65"
			}
			r, page := pm2ProjectHTTPRead(s, query)
			switch mode {
			case "foreign-name", "bad-query":
				want := 409
				if mode == "bad-query" {
					want = 400
				}
				if r.Code != want || len(*calls) != 0 {
					t.Fatal("unknown inventory dispatched a command", r.Code, len(*calls))
				}
			case "missing-projects":
				if r.Code != 200 || page["total"] != float64(0) || page["project_page_complete"] != true || len(*calls) != 0 {
					t.Fatal("genuine absence was not distinguished", r.Code, len(*calls))
				}
			case "service-unknown":
				if r.Code != 200 || page["project_page_complete"] != false || len(*calls) != 1 {
					t.Fatal("unknown service became a successful empty inventory", r.Code, len(*calls))
				}
				row := page["apps"].([]any)[0].(map[string]any)
				if row["state_known"] != false || row["state"] != "unknown" || row["boot_enabled"] != nil {
					t.Fatal("unknown service became stopped")
				}
			default:
				if r.Code != 200 || page["project_page_complete"] != false || len(page["apps"].([]any)) != 0 || len(page["unreadable_projects"].([]any)) != 1 || len(*calls) != 0 {
					t.Fatal("untrusted project became a known service", r.Code, len(*calls))
				}
			}
		})
	}
}

func TestPM2ProjectsGETDetectsChangedProjectAndHonorsBoundedPages(t *testing.T) {
	s, app, path, calls := pm2StopFixture(t)
	second := app
	second.ID = "zz-second-project"
	if err := moduleWrite(filepath.Join(filepath.Dir(path), second.ID+".json"), second); err != nil {
		t.Fatal(err)
	}
	s.Config.Run = func(_ context.Context, command string, args ...string) (string, error) {
		if command != "/usr/bin/systemctl" || len(args) != 3 || args[0] != "show" || args[1] != "panel-pm2@"+second.ID+".service" || args[2] != "--property=LoadState,MainPID,InvocationID,ActiveState,SubState,UnitFileState" {
			t.Fatal("bounded second page dispatched a different unit or mutation", command, args)
		}
		*calls = append(*calls, strings.Join(args, " "))
		return pm2TestStateText(pm2TestState("active", "enabled")), nil
	}
	r, page := pm2ProjectHTTPRead(s, "?limit=1&offset=1")
	if r.Code != 200 || len(*calls) != 1 || page["total"] != float64(2) || page["offset"] != float64(1) || page["apps"].([]any)[0].(map[string]any)["app"].(map[string]any)["id"] != second.ID {
		t.Fatal("project page was unbounded or silently omitted a known project", r.Code, len(*calls))
	}
	s.Config.Run = func(_ context.Context, command string, args ...string) (string, error) {
		if command != "/usr/bin/systemctl" || args[0] != "show" {
			t.Fatal("read-only changed-project fixture mutated a service")
		}
		app.Revision++
		if err := moduleWrite(path, app); err != nil {
			t.Fatal(err)
		}
		return pm2TestStateText(pm2TestState("active", "enabled")), nil
	}
	r, page = pm2ProjectHTTPRead(s, "?resource_id="+app.ID)
	if r.Code != 200 || page["project_page_complete"] != false || len(page["apps"].([]any)) != 0 || len(page["unreadable_projects"].([]any)) != 1 {
		t.Fatal("changed project was attested from stale service observation", r.Code)
	}
}
