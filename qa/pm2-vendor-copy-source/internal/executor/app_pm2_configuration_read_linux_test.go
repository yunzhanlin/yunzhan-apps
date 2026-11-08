//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func pm2ConfigurationGET(s *Service, query string) *httptest.ResponseRecorder {
	m := http.NewServeMux()
	s.pm2ConfigurationReadRoutes(m)
	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest("GET", "/v1/app-modules/pm2-manager/configuration?"+query, nil))
	return w
}
func TestPM2ConfigurationGETDoesNotWaitForMutationOrOpenBrokenLegacyHistory(t *testing.T) {
	s, _, _, record := pm2ConfigFixtureIntent(t)
	if err := moduleWrite(filepath.Join(s.moduleDir("pm2-manager"), "installed.json"), map[string]string{"id": "pm2-manager", "version": "7.0.4-compat6"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"history.json", "last-report.json", "history.sqlite"} {
		if err := os.WriteFile(filepath.Join(s.moduleDir("pm2-manager"), name), []byte("original-invalid-retained-history"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("read-only recovery lookup invoked a system command")
		return "", nil
	}
	before := programQueueTree(t, s.Config.SecurityDir)
	s.mu.Lock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- pm2ConfigurationGET(s, "pm2_operation_id="+record.Intent.ID) }()
	select {
	case w := <-done:
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	case <-time.After(time.Second):
		s.mu.Unlock()
		t.Fatal("read-only recovery lookup waited for global writer")
	}
	s.mu.Unlock()
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SecurityDir)) {
		t.Fatal("recovery read imported, repaired or wrote original history")
	}
}
func TestPM2ConfigurationGETNeverAttestsAnUnsettledTerminalFile(t *testing.T) {
	s, app, _, record := pm2ConfigFixtureIntent(t)
	if err := moduleWrite(filepath.Join(s.moduleDir("pm2-manager"), "installed.json"), map[string]string{"id": "pm2-manager", "version": "7.0.4-compat6"}); err != nil {
		t.Fatal(err)
	}
	lock, err := s.lockPM2Project(app.ID)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.openPM2ConfigStore(false)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.finish(record, "committed"); err != nil {
		t.Fatal(err)
	}
	d.Close()
	if w := pm2ConfigurationGET(s, "pm2_operation_id="+record.Intent.ID); w.Code != 409 {
		t.Fatal("held writer lock produced a terminal read acknowledgement", w.Code)
	}
	lock.Close()
	before := programQueueTree(t, s.Config.SecurityDir)
	if w := pm2ConfigurationGET(s, "pm2_operation_id="+record.Intent.ID); w.Code != 200 {
		t.Fatal("settled original terminal publication not readable", w.Code, w.Body.String())
	}
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SecurityDir)) {
		t.Fatal("terminal acknowledgement wrote a lock or record")
	}
}

func TestPM2ConfigurationRecoveryRemainsObservableWhenOldHistoryCannotBeWritten(t *testing.T) {
	s, app, path, record := pm2ConfigFixtureIntent(t)
	if err := moduleWrite(filepath.Join(s.moduleDir("pm2-manager"), "installed.json"), map[string]string{"id": "pm2-manager", "version": "7.0.4-compat6"}); err != nil {
		t.Fatal(err)
	}
	if err := s.pm2ConfigPublish(app.ID, record.Intent.ID, record.Intent.Before, record.Intent.After); err != nil {
		t.Fatal(err)
	}
	history := filepath.Join(s.moduleDir("pm2-manager"), "history.json")
	original := []byte("original-unverifiable-history-retained")
	if err := os.WriteFile(history, original, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
		calls++
		if name != "/usr/bin/systemctl" {
			t.Fatal(name)
		}
		if args[0] == "disable" {
			return "", nil
		}
		if args[0] == "show" {
			return pm2TestStateText(pm2TestState("inactive", "disabled")), nil
		}
		t.Fatal("recovery attempted a start", args)
		return "", nil
	}
	input := core.AppModuleInput{ResourceID: app.ID, PM2OperationID: record.Intent.ID, ExpectedSHA: record.SHA, Confirm: "RECOVER PM2 " + record.Intent.ID}
	raw, _ := json.Marshal(input)
	mux := http.NewServeMux()
	s.appModuleRoutes(mux)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest("POST", "/v1/app-modules/pm2-manager/recover-configuration", bytes.NewReader(raw)))
	if response.Code != 409 {
		t.Fatal("broken audit should remain an unconfirmed HTTP result", response.Code)
	}
	after, _ := os.ReadFile(path)
	retained, _ := os.ReadFile(history)
	if calls != 2 || !bytes.Equal(after, record.Intent.Before) || !bytes.Equal(original, retained) {
		t.Fatal("recovery was blocked, restarted the app or overwrote old evidence", calls)
	}
	if w := pm2ConfigurationGET(s, "pm2_operation_id="+record.Intent.ID); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("recovered_stopped")) {
		t.Fatal("durable recovery cannot be independently observed", w.Code, w.Body.String())
	}
}

func TestPM2ConfigurationGETRejectsMissingOrUntrustedInstallationAndBadQuery(t *testing.T) {

	s, _, _, _ := pm2ConfigFixtureIntent(t)
	if w := pm2ConfigurationGET(s, ""); w.Code != 409 {
		t.Fatal("uninstalled module allowed recovery inventory", w.Code)
	}
	if w := pm2ConfigurationGET(s, "limit=1&limit=2"); w.Code != 400 {
		t.Fatal("duplicate read query accepted", w.Code)
	}
	if err := moduleWrite(filepath.Join(s.moduleDir("pm2-manager"), "installed.json"), map[string]string{"id": "other-module", "version": "7.0.4-compat6"}); err != nil {
		t.Fatal(err)
	}
	if w := pm2ConfigurationGET(s, ""); w.Code != 409 {
		t.Fatal("foreign installed identity allowed read", w.Code)
	}
}
