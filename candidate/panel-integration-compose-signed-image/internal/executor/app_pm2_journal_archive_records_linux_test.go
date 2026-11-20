//go:build linux

package executor

import (
	"encoding/json"
	"local/panel/internal/core"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPM2JournalArchiveHistoricalPageRetainsOriginalSelectionAndRejectsDamage(t *testing.T) {
	s, id, in := pm2ArchiveReadCompleteFixture(t)
	before := programQueueTree(t, s.Config.SecurityDir)
	out, err := s.pm2ConfigurationArchiveRecords(id, core.AppModuleInput{ResourceID: in.ResourceID, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	page := out.(map[string]any)
	if page["archived_original"] != true || page["total"] != 1 || page["archive_operation_id"] != id || page["history_or_report_written"] != false {
		t.Fatal("original historical page lost identity")
	}
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SecurityDir)) {
		t.Fatal("historical page changed evidence")
	}
	path := filepath.Join(s.moduleDir("pm2-manager"), "configuration-archives", "generations", id, in.PM2OperationID+".intent.json")
	damaged := []byte("retained original damaged record")
	if err := os.WriteFile(path, damaged, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pm2ConfigurationArchiveRecords(id, core.AppModuleInput{}); err == nil {
		t.Fatal("damaged original became empty historical page")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(damaged) {
		t.Fatal("damaged original repaired or removed")
	}
}
func TestPM2JournalArchiveHistoricalGETIsBoundedAndDoesNotExposeCiphertext(t *testing.T) {
	s, id, in := pm2ArchiveReadCompleteFixture(t)
	if err := moduleWrite(filepath.Join(s.moduleDir("pm2-manager"), "installed.json"), map[string]string{"id": "pm2-manager", "version": core.PM2ConfigurationArchiveAppVersion, "installation_id": "77777777777777777777777777777777"}); err != nil {
		t.Fatal(err)
	}
	m := http.NewServeMux()
	s.pm2ConfigurationArchiveReadRoutes(m)
	before := programQueueTree(t, s.Config.SecurityDir)
	request := func(query string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		m.ServeHTTP(w, httptest.NewRequest("GET", "/v1/app-modules/pm2-manager/configuration-archives/"+id+"/records?pm2_installation_id=77777777777777777777777777777777&"+query, nil))
		return w
	}
	w := request("pm2_operation_id=" + in.PM2OperationID + "&limit=1&offset=0")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var page map[string]any
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || page["archive_operation_id"] != id || page["archived_original"] != true {
		t.Fatal("wrong historical page identity")
	}
	records := page["configuration_transactions"].([]any)
	if len(records) != 1 {
		t.Fatal("original row missing")
	}
	row := records[0].(map[string]any)
	for _, key := range []string{"before", "after", "environment_cipher", "environment_patch", "password", "token"} {
		if _, exists := row[key]; exists {
			t.Fatal("private configuration exposed", key)
		}
	}
	if w := request("limit=129"); w.Code != 400 {
		t.Fatal("unbounded page accepted", w.Code)
	}
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SecurityDir)) {
		t.Fatal("HTTP page wrote history or replayed")
	}
}
