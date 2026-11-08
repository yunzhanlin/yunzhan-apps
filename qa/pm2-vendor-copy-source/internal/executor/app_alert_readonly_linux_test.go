//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"local/panel/internal/core"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func moduleAlertReadRequest(s *Service, module string, cursor int64) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	s.moduleAlertRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", fmt.Sprintf("/v1/module-alert-events?module=%s&cursor=%d", module, cursor), nil))
	return w
}

func alertReadFixtureFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := fmt.Sprintf("%v:%d:%d", info.Mode(), info.Size(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += fmt.Sprintf(":%x", sha256.Sum256(raw))
		}
		out[path] = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestModuleAlertReadOnlyKnownEmptyDoesNotCreateLedgerOrWaitForMutation(t *testing.T) {
	s, _, _ := appReliabilityFixture(t)
	if err := moduleWrite(filepath.Join(s.moduleDir("php-code-security"), "installed.json"), map[string]string{"id": "php-code-security"}); err != nil {
		t.Fatal(err)
	}
	before := alertReadFixtureFiles(t, s.Config.SecurityDir)
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Error("alert read invoked a system command")
		return "", nil
	}
	s.mu.Lock()
	done := make(chan error, 1)
	go func() {
		for _, module := range []string{"file-monitor", "website-tamper-proof", "enterprise-tamper-proof", "files-sync", "php-code-security"} {
			for _, cursor := range []int64{-1, 0} {
				w := moduleAlertReadRequest(s, module, cursor)
				var page core.ModuleAlertPage
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Cursor != 0 || len(page.Events) != 0 || page.Gap {
					done <- fmt.Errorf("%s: %d %s", module, w.Code, w.Body.String())
					return
				}
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		s.mu.Unlock()
		<-done
		t.Fatal("unrelated native mutation blocked an alert source")
	}
	if !reflect.DeepEqual(before, alertReadFixtureFiles(t, s.Config.SecurityDir)) {
		t.Fatal("known-empty alert observation created or rewrote a file")
	}
}

func TestModuleAlertReadOnlyExistingLedgerDoesNotWaitOrExposePrivateFields(t *testing.T) {
	s, site, _ := appReliabilityFixture(t)
	if err := s.appendModuleEvent("file-monitor", "check", "manual", core.AppModuleInput{SiteID: site}, map[string]any{"changes": 2}, nil); err != nil {
		t.Fatal(err)
	}
	before := alertReadFixtureFiles(t, s.moduleDir("file-monitor"))
	s.mu.Lock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- moduleAlertReadRequest(s, "file-monitor", 0) }()
	var w *httptest.ResponseRecorder
	select {
	case w = <-done:
		s.mu.Unlock()
	case <-time.After(2 * time.Second):
		s.mu.Unlock()
		<-done
		t.Fatal("committed alert ledger waited for unrelated mutation")
	}
	var page core.ModuleAlertPage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Events) != 1 || page.Cursor != 1 || strings.Contains(w.Body.String(), site) || strings.Contains(w.Body.String(), "resource_id") {
		t.Fatal(w.Code, w.Body.String())
	}
	if !reflect.DeepEqual(before, alertReadFixtureFiles(t, s.moduleDir("file-monitor"))) {
		t.Fatal("alert observation rewrote committed ledger or JSON")
	}
}

func TestModuleAlertReadOnlyRefusesLegacySequenceWithoutCreatingMigration(t *testing.T) {
	s, site, _ := appReliabilityFixture(t)
	event := moduleEvent{ID: core.ID(), Time: core.Now(), Action: "check", Trigger: "manual", Outcome: "succeeded", SiteID: site, Changes: 2}
	if err := s.writeModuleRetrospectiveRecord("file-monitor", "history.json", []moduleEvent{event}); err != nil {
		t.Fatal(err)
	}
	before := alertReadFixtureFiles(t, s.moduleDir("file-monitor"))
	for _, cursor := range []int64{-1, 0, 1} {
		if w := moduleAlertReadRequest(s, "file-monitor", cursor); w.Code != 409 {
			t.Fatal("legacy sequence was invented", w.Code, w.Body.String())
		}
	}
	if !reflect.DeepEqual(before, alertReadFixtureFiles(t, s.moduleDir("file-monitor"))) {
		t.Fatal("alert read imported, rewrote or replaced legacy history")
	}
	// The existing actual writer still migrates old summaries once. Both old
	// and new events then become available through their real durable sequence.
	if err := s.appendModuleEvent("file-monitor", "check", "manual", core.AppModuleInput{SiteID: site}, map[string]any{"changes": 3}, nil); err != nil {
		t.Fatal(err)
	}
	w := moduleAlertReadRequest(s, "file-monitor", 0)
	var page core.ModuleAlertPage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Cursor != 2 || len(page.Events) != 2 || page.Events[0].ID != event.ID {
		t.Fatal("normal writer migration lost old sequence", w.Code, w.Body.String())
	}
}

func TestModuleAlertReadOnlyPreservesPendingSQLTransactionAndOriginalCursor(t *testing.T) {
	s, site, _ := appReliabilityFixture(t)
	if err := s.appendModuleEvent("file-monitor", "check", "manual", core.AppModuleInput{SiteID: site}, nil, nil); err != nil {
		t.Fatal(err)
	}
	db, err := s.openModuleLedger(context.Background(), "file-monitor")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE metadata SET value='2' WHERE key='last-event-sequence'`); err != nil {
		t.Fatal(err)
	}
	before := alertReadFixtureFiles(t, s.moduleDir("file-monitor"))
	w := moduleAlertReadRequest(s, "file-monitor", 1)
	if w.Code != 409 || !reflect.DeepEqual(before, alertReadFixtureFiles(t, s.moduleDir("file-monitor"))) {
		t.Fatal("pending journal was recovered, changed or partially exposed", w.Code, w.Body.String())
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	w = moduleAlertReadRequest(s, "file-monitor", 1)
	if w.Code != 200 {
		t.Fatal("normal original writer rollback did not restore readable state", w.Body.String())
	}
}

func TestModuleAlertReadOnlyExistingEmptyLedgerCannotHideUnmigratedLegacy(t *testing.T) {
	s, site, _ := appReliabilityFixture(t)
	event := moduleEvent{ID: core.ID(), Time: core.Now(), Action: "check", Trigger: "manual", Outcome: "succeeded", SiteID: site, Changes: 2}
	if err := s.writeModuleRetrospectiveRecord("file-monitor", "history.json", []moduleEvent{event}); err != nil {
		t.Fatal(err)
	}
	db, err := s.openModuleLedger(context.Background(), "file-monitor")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	before := alertReadFixtureFiles(t, s.moduleDir("file-monitor"))
	for _, cursor := range []int64{-1, 0} {
		w := moduleAlertReadRequest(s, "file-monitor", cursor)
		if w.Code != 409 || !reflect.DeepEqual(before, alertReadFixtureFiles(t, s.moduleDir("file-monitor"))) {
			t.Fatal("unmigrated old JSON was hidden by a previously created empty database", w.Code, w.Body.String())
		}
	}
	if err := s.appendModuleEvent("file-monitor", "check", "manual", core.AppModuleInput{SiteID: site}, nil, nil); err != nil {
		t.Fatal(err)
	}
	w := moduleAlertReadRequest(s, "file-monitor", 0)
	var page core.ModuleAlertPage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Cursor != 2 || len(page.Events) != 2 || page.Events[0].ID != event.ID {
		t.Fatal("original writer did not migrate the retained old event exactly once", w.Code, w.Body.String())
	}
}

func TestModuleAlertReadOnlyRejectsCorruptIndexedPayloadAndWatermark(t *testing.T) {
	for _, query := range []string{
		`UPDATE metadata SET value='not-a-sequence' WHERE key='last-event-sequence'`,
		`UPDATE metadata SET value='0' WHERE key='last-event-sequence'`,
		`UPDATE module_events SET event_id='00000000000000000000000000000000'`,
		`UPDATE module_events SET created_at=created_at+1`,
		`UPDATE module_events SET payload='{"id":"wrong"}'`,
	} {
		t.Run(query, func(t *testing.T) {
			s, site, _ := appReliabilityFixture(t)
			if err := s.appendModuleEvent("file-monitor", "check", "manual", core.AppModuleInput{SiteID: site}, nil, nil); err != nil {
				t.Fatal(err)
			}
			db, err := s.openModuleLedger(context.Background(), "file-monitor")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(query); err != nil {
				t.Fatal(err)
			}
			db.Close()
			before := alertReadFixtureFiles(t, s.moduleDir("file-monitor"))
			if w := moduleAlertReadRequest(s, "file-monitor", 0); w.Code != 409 || !reflect.DeepEqual(before, alertReadFixtureFiles(t, s.moduleDir("file-monitor"))) {
				t.Fatal("corrupt source was silently accepted or repaired", w.Code, w.Body.String())
			}
		})
	}
}

func TestModuleAlertReadOnlyMaxInt64CaughtUpDoesNotInventGap(t *testing.T) {
	s, _, _ := appReliabilityFixture(t)
	db, err := s.openModuleLedger(context.Background(), "file-monitor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO metadata(key,value) VALUES('last-event-sequence',?)`, fmt.Sprint(int64(math.MaxInt64))); err != nil {
		t.Fatal(err)
	}
	db.Close()
	w := moduleAlertReadRequest(s, "file-monitor", math.MaxInt64)
	var page core.ModuleAlertPage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Cursor != math.MaxInt64 || page.Gap || len(page.Events) != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestModuleAlertReadOnlyRejectsWALHeaderWithoutCreatingSideFiles(t *testing.T) {
	s, _, _ := appReliabilityFixture(t)
	db, err := s.openModuleLedger(context.Background(), "file-monitor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"history.sqlite-wal", "history.sqlite-shm"} {
		if _, err = os.Lstat(filepath.Join(s.moduleDir("file-monitor"), name)); !os.IsNotExist(err) {
			t.Fatal("fixture did not close the original WAL writer", err)
		}
	}
	before := alertReadFixtureFiles(t, s.moduleDir("file-monitor"))
	if w := moduleAlertReadRequest(s, "file-monitor", -1); w.Code != 409 || !reflect.DeepEqual(before, alertReadFixtureFiles(t, s.moduleDir("file-monitor"))) {
		t.Fatal("WAL header opened or created auxiliary files", w.Code, w.Body.String())
	}
}

func TestModuleAlertReadGuardRefusesInstalledRecordReplacementAndUninstall(t *testing.T) {
	s, _, _ := appReliabilityFixture(t)
	for _, remove := range []bool{false, true} {
		guard, installed, err := s.beginModuleAlertRead("file-monitor")
		if err != nil || !installed {
			t.Fatal(err)
		}
		path := filepath.Join(s.moduleDir("file-monitor"), "installed.json")
		if remove {
			err = os.Remove(path)
		} else {
			raw, _ := os.ReadFile(path)
			err = atomicWrite(path, raw, 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
		err = guard.check(context.Background())
		guard.dir.Close()
		if err == nil {
			t.Fatal("replaced or uninstalled record retained an old observation")
		}
	}
}

func TestLoadBalanceAlertReadOnlyCompletesWhileUnrelatedMutationHeld(t *testing.T) {
	s, _ := lbHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	lbAlertNativeInstall(t, s, "1.8.5")
	// Capture after the unchanged WAF file-lock initialization; alert reads
	// may use that same cooperative lock but never wait for the global mutex.
	lbAlertNativeRead(t, s, "", 200)
	before := alertReadFixtureFiles(t, s.moduleDir("load-balance"))
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Error("load-balancer alert source invoked a command")
		return "", nil
	}
	for _, path := range []string{"/v1/load-balance-alert-events", "/v1/load-balance-traffic-alert-events"} {
		mux := http.NewServeMux()
		s.moduleAlertRoutes(mux)
		w := httptest.NewRecorder()
		done := make(chan struct{})
		s.mu.Lock()
		go func() { mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil)); close(done) }()
		select {
		case <-done:
			s.mu.Unlock()
		case <-time.After(2 * time.Second):
			s.mu.Unlock()
			<-done
			t.Fatal("unrelated mutation blocked load-balancer alert source")
		}
		if w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte("private")) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if !reflect.DeepEqual(before, alertReadFixtureFiles(t, s.moduleDir("load-balance"))) {
		t.Fatal("alert source changed configuration, health or traffic history")
	}
}
