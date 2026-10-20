//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"local/panel/internal/core"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestModuleAlertFeedPaginationPrivacyRetentionAndMonotonicRestart(t *testing.T) {
	svc, site, _ := appReliabilityFixture(t)
	db, err := svc.openModuleLedger(context.Background(), "file-monitor")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 501; i++ {
		err = insertModuleLedgerEvent(context.Background(), tx, moduleEvent{ID: core.ID(), Time: core.Now(), Action: "check", Trigger: "inotify", Outcome: "succeeded", SiteID: site, Changes: 1, Error: "sensitive-file-name private-secret"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	svc.moduleAlertRoutes(mux)
	read := func(cursor int64, want int) core.ModuleAlertPage {
		t.Helper()
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", fmt.Sprintf("/v1/module-alert-events?module=file-monitor&cursor=%d", cursor), nil))
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "private-secret") || strings.Contains(w.Body.String(), "sensitive-file-name") || strings.Contains(w.Body.String(), site) {
			t.Fatal("feed leaked source evidence")
		}
		var page core.ModuleAlertPage
		if want == 200 && json.Unmarshal(w.Body.Bytes(), &page) != nil {
			t.Fatal(w.Body.String())
		}
		return page
	}
	if p := read(-1, 200); p.Cursor != 501 || len(p.Events) != 0 {
		t.Fatal("initial history replay", p)
	}
	if p := read(0, 200); len(p.Events) != 500 || p.Cursor != 500 || p.Events[0].Sequence != 1 {
		t.Fatal("pagination", p.Cursor, len(p.Events))
	}
	if p := read(500, 200); len(p.Events) != 1 || p.Cursor != 501 {
		t.Fatal(p)
	}
	if _, err = db.Exec("DELETE FROM module_events"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if p := read(500, 200); !p.Gap || p.Cursor != 501 {
		t.Fatal("retention gap was hidden", p)
	}
	restarted := New(svc.Config)
	mux = http.NewServeMux()
	restarted.moduleAlertRoutes(mux)
	if err = restarted.appendModuleEvent("file-monitor", "check", "inotify", core.AppModuleInput{SiteID: site}, map[string]any{"changes_count": 2}, nil); err != nil {
		t.Fatal(err)
	}
	if p := read(501, 200); len(p.Events) != 1 || p.Events[0].Sequence != 502 || p.Cursor != 502 {
		t.Fatal("sequence reused after pruning/restart", p)
	}
	read(503, 409)
	// Replaying an already imported event must not consume another sequence.
	db, err = restarted.openModuleLedger(context.Background(), "file-monitor")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw string
	if err = db.QueryRow("SELECT payload FROM module_events WHERE seq=502").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var event moduleEvent
	_ = json.Unmarshal([]byte(raw), &event)
	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = insertModuleLedgerEvent(context.Background(), tx, event); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if p := read(-1, 200); p.Cursor != 502 {
		t.Fatal("duplicate advanced cursor", p)
	}
}
