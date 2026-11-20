//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func pm2JournalArchiveGET(s *Service, query string) *httptest.ResponseRecorder {
	m := http.NewServeMux()
	s.pm2ConfigurationArchiveReadRoutes(m)
	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest("GET", "/v1/app-modules/pm2-manager/configuration-archives?pm2_installation_id=77777777777777777777777777777777&"+query, nil))
	return w
}
func TestPM2JournalArchiveReadRouteDoesNotCreateHistoryOrReplay(t *testing.T) {
	s, _ := pm2ArchiveActiveFixture(t)
	if err := moduleWrite(filepath.Join(s.moduleDir("pm2-manager"), "installed.json"), map[string]string{"id": "pm2-manager", "version": core.PM2ConfigurationArchiveAppVersion, "installation_id": "77777777777777777777777777777777"}); err != nil {
		t.Fatal(err)
	}
	before := programQueueTree(t, s.Config.SecurityDir)
	w := pm2JournalArchiveGET(s, "limit=32")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var page map[string]any
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || page["archive_eligible"] != true || page["history_or_report_written"] != false {
		t.Fatal("archive preview not complete")
	}
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SecurityDir)) {
		t.Fatal("GET created history, archive directory or replayed work")
	}
	lease, err := s.lockPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	if w := pm2JournalArchiveGET(s, ""); w.Code != 409 {
		t.Fatal("GET attested unsettled archive writer")
	}
	lease.Close()
	if err := os.WriteFile(filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions", "retain-unknown"), []byte("original unknown"), 0600); err != nil {
		t.Fatal(err)
	}
	w = pm2JournalArchiveGET(s, "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page["active_inventory_known"] != false {
		t.Fatal("damaged active journal was falsely empty", w.Code, w.Body.String())
	}
}
func TestPM2JournalArchiveRootDispatchRequiresExactInstalledRevision(t *testing.T) {
	for _, version := range []string{"7.0.4-compat11", "7.0.4-compat12.0", "7.0.4-compat13"} {
		t.Run(version, func(t *testing.T) {
			s, _ := pm2ArchiveActiveFixture(t)
			if err := moduleWrite(filepath.Join(s.moduleDir("pm2-manager"), "installed.json"), map[string]string{"id": "pm2-manager", "version": version}); err != nil {
				t.Fatal(err)
			}
			before := programQueueTree(t, s.Config.SecurityDir)
			if w := pm2JournalArchiveGET(s, ""); w.Code != 409 {
				t.Fatal("old or aliased installation received archive authority", w.Code)
			}
			if _, err := s.runAppModule(context.Background(), "pm2-manager", "archive-configurations", core.AppModuleInput{}); err == nil {
				t.Fatal("direct Root dispatch bypassed exact installed revision")
			}
			if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SecurityDir)) {
				t.Fatal("version refusal changed original evidence")
			}
		})
	}
}
