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
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func pm2StopFixture(t *testing.T) (*Service, pm2App, string, *[]string) {
	t.Helper()
	s, app, path := pm2StateAppFixture(t)
	if err := moduleWrite(filepath.Join(s.moduleDir("pm2-manager"), "installed.json"), map[string]any{"id": "pm2-manager", "version": core.PM2ConfigurationAppVersion}); err != nil {
		t.Fatal(err)
	}
	state := pm2TestState("active", "enabled")
	calls := []string{}
	unit := "panel-pm2@" + app.ID + ".service"
	s.Config.Run = func(_ context.Context, command string, args ...string) (string, error) {
		if command != "/usr/bin/systemctl" {
			t.Fatal("Stop must not execute a project, dependency or arbitrary command")
		}
		calls = append(calls, strings.Join(args, " "))
		switch {
		case reflect.DeepEqual(args, []string{"disable", "--now", unit}):
			state = pm2TestState("inactive", "disabled")
			return "", nil
		case reflect.DeepEqual(args, []string{"show", unit, "--property=LoadState,MainPID,InvocationID,ActiveState,SubState,UnitFileState"}):
			return pm2TestStateText(state), nil
		default:
			t.Fatal("Stop dispatched a different unit or action", args)
			return "", errors.New("unexpected operation")
		}
	}
	return s, app, path, &calls
}

func TestPM2StopRetainsMalformedOriginalAndNeverReplaysConfiguration(t *testing.T) {
	s, app, path, calls := pm2StopFixture(t)
	dir := filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	damaged := filepath.Join(dir, core.ID()+".intent.json")
	raw := []byte("{\"format\":1,\"original_interrupted_bytes\":")
	if err := os.WriteFile(damaged, raw, 0600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Lstat(damaged)
	originalApp, _ := os.ReadFile(path)
	if _, err := s.pm2ConfigRecords(); err == nil {
		t.Fatal("Fixture must retain a genuinely rejected original")
	}
	result, err := s.modulePM2(context.Background(), "stop", core.AppModuleInput{ResourceID: app.ID, ExpectedRevision: app.Revision})
	row, known := pm2VerifiedStopResult("pm2-manager", "stop", result, err)
	if err != nil || !known || row["configuration_or_deployment_replayed"] != false || len(*calls) != 3 {
		t.Fatal("Stop did not independently verify its effect", err, len(*calls))
	}
	after, _ := os.Lstat(damaged)
	current, _ := os.ReadFile(damaged)
	currentApp, _ := os.ReadFile(path)
	if !programQueueSame(info, after) || !bytes.Equal(raw, current) || !bytes.Equal(originalApp, currentApp) {
		t.Fatal("Stop changed the original project or damaged evidence")
	}
	published, _ := json.Marshal(result)
	if bytes.Contains(published, []byte("environment_cipher")) || bytes.Contains(published, []byte("private-environment-before-state-save")) {
		t.Fatal("Stop exposed a private environment")
	}
	before := len(*calls)
	if _, err := s.modulePM2(context.Background(), "start", core.AppModuleInput{ResourceID: app.ID}); err == nil || len(*calls) != before {
		t.Fatal("Malformed evidence still must block start; no replay is authorized")
	}
	report, err := s.modulePM2(context.Background(), "run", core.AppModuleInput{})
	if err != nil {
		t.Fatal(err)
	}
	page := report.(map[string]any)
	if page["configuration_inventory_complete"] != false || page["configuration_error"] == "" {
		t.Fatal("A damaged inventory was presented as complete")
	}
	apps := page["apps"].([]any)
	if len(apps) != 1 || apps[0].(map[string]any)["state"] != "inactive" || apps[0].(map[string]any)["configuration_state"] != "unknown" {
		t.Fatal("Actual service observation and unknown configuration were conflated")
	}
}

func TestPM2StopRefusesUntrustedProjectAndLockWithoutEffects(t *testing.T) {
	for _, mode := range []string{"project-symlink", "project-hardlink", "project-mode", "project-id", "project-site", "lock-symlink", "lock-hardlink", "lock-mode", "busy", "revision"} {
		t.Run(mode, func(t *testing.T) {
			s, app, path, calls := pm2StopFixture(t)
			original, _ := os.ReadFile(path)
			lock := filepath.Join(s.moduleDir("pm2-manager"), "locks", app.ID+".lock")
			if err := os.MkdirAll(filepath.Dir(lock), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lock, nil, 0600); err != nil {
				t.Fatal(err)
			}
			in := core.AppModuleInput{ResourceID: app.ID, ExpectedRevision: app.Revision}
			target := path
			if strings.HasPrefix(mode, "lock-") {
				target = lock
			}
			switch {
			case strings.HasSuffix(mode, "-symlink"):
				keep := target + ".original"
				if os.Rename(target, keep) != nil || os.Symlink(keep, target) != nil {
					t.Fatal("Fixture link setup failed")
				}
			case strings.HasSuffix(mode, "-hardlink"):
				if err := os.Link(target, target+".original"); err != nil {
					t.Fatal(err)
				}
			case strings.HasSuffix(mode, "-mode"):
				if err := os.Chmod(target, 0640); err != nil {
					t.Fatal(err)
				}
			case mode == "project-id":
				changed := app
				changed.ID = "different-owned-project"
				if err := moduleWrite(path, changed); err != nil {
					t.Fatal(err)
				}
			case mode == "project-site":
				changed := app
				changed.SiteID = "unknown"
				if err := moduleWrite(path, changed); err != nil {
					t.Fatal(err)
				}
			case mode == "busy":
				held, err := s.lockPM2Project(app.ID)
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
			case mode == "revision":
				in.ExpectedRevision++
			}
			if _, err := s.modulePM2(context.Background(), "stop", in); err == nil || len(*calls) != 0 {
				t.Fatal("Unverified project or lock dispatched a stop", err, len(*calls))
			}
			if strings.Contains(mode, "symlink") || strings.Contains(mode, "hardlink") {
				kept, err := os.ReadFile(target + ".original")
				expected := original
				if strings.HasPrefix(mode, "lock-") {
					expected = nil
				}
				if err != nil || !bytes.Equal(kept, expected) {
					t.Fatal("Original linked bytes changed")
				}
			}
		})
	}
}

func TestPM2StopDoesNotClaimServiceSuccessOnUnknownSystemdOutcome(t *testing.T) {
	for _, mode := range []string{"show-error", "disable-error", "still-running"} {
		t.Run(mode, func(t *testing.T) {
			s, app, _, _ := pm2StopFixture(t)
			stops := 0
			s.Config.Run = func(_ context.Context, _ string, args ...string) (string, error) {
				if args[0] == "disable" {
					stops++
					if mode == "disable-error" {
						return "", errors.New("original stop result unavailable")
					}
					return "", nil
				}
				if mode == "show-error" {
					return "", errors.New("original observation unavailable")
				}
				return pm2TestStateText(pm2TestState("active", "enabled")), nil
			}
			out, err := s.modulePM2(context.Background(), "stop", core.AppModuleInput{ResourceID: app.ID})
			if _, known := pm2VerifiedStopResult("pm2-manager", "stop", out, err); err == nil || known || stops > 1 {
				t.Fatal("Unknown outcome was accepted or automatically retried", mode, stops)
			}
		})
	}
}

func TestPM2StopActualHTTPKeepsDamagedHistoryAndReportsPersistenceSeparately(t *testing.T) {
	for _, mode := range []string{"healthy", "history-malformed", "report-symlink"} {
		t.Run(mode, func(t *testing.T) {
			s, app, _, calls := pm2StopFixture(t)
			history := filepath.Join(s.moduleDir("pm2-manager"), "history.json")
			report := filepath.Join(s.moduleDir("pm2-manager"), "last-report.json")
			var originalPath string
			var original []byte
			if mode == "history-malformed" {
				originalPath, original = history, []byte("[{\"original_unfinished\":")
				if err := os.WriteFile(originalPath, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "report-symlink" {
				originalPath, original = filepath.Join(t.TempDir(), "outside-original"), []byte("original unrelated data")
				if os.WriteFile(originalPath, original, 0600) != nil || os.Symlink(originalPath, report) != nil {
					t.Fatal("Fixture setup failed")
				}
			}
			var info os.FileInfo
			if originalPath != "" {
				info, _ = os.Lstat(originalPath)
			}
			mux := http.NewServeMux()
			s.appModuleRoutes(mux)
			body, _ := json.Marshal(core.AppModuleInput{ResourceID: app.ID, ExpectedRevision: app.Revision})
			request := httptest.NewRequest("POST", "/v1/app-modules/pm2-manager/stop", bytes.NewReader(body))
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)
			if recorder.Code != 200 || len(*calls) != 3 {
				t.Fatal("Actual route did not return the independently stopped service", recorder.Code, len(*calls))
			}
			var result map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil || result["service_outcome_verified"] != true || result["state"] != "inactive" || result["boot_enabled"] != false {
				t.Fatal("Service result was not verified independently", err)
			}
			if mode == "healthy" {
				if result["history_persisted"] != true || result["last_report_persisted"] != true {
					t.Fatal("Healthy record writes did not complete")
				}
				var stored map[string]any
				if err := moduleRead(report, &stored); err != nil || stored["action"] != "stop" {
					t.Fatal("Original route failed to persist its normal report", err)
				}
			} else {
				if result["history_persisted"] != false && result["last_report_persisted"] != false || result["persistence_warning"] == "" {
					t.Fatal("A stopped service was conflated with a durable record")
				}
				now, _ := os.Lstat(originalPath)
				current, _ := os.ReadFile(originalPath)
				if !programQueueSame(info, now) || !bytes.Equal(original, current) {
					t.Fatal("Original damaged or linked evidence was replaced")
				}
			}
		})
	}
}
