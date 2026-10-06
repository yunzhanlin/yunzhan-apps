//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestModuleLedgerImportFullHistoryPaginationFiltersAndPrivacy(t *testing.T) {
	svc, first, second := appReliabilityFixture(t)
	old := moduleEvent{ID: core.ID(), Time: time.Now().AddDate(0, -2, 0).UTC().Format(time.RFC3339), Action: "check", Trigger: "scheduled", Outcome: "succeeded", SiteID: first}
	if err := moduleWrite(filepath.Join(svc.moduleDir("file-monitor"), "history.json"), []moduleEvent{old}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 130; i++ {
		site, plan := first, "plan-first"
		if i%2 == 1 {
			site, plan = second, "plan-second"
		}
		var operationError error
		if i%10 == 0 {
			operationError = errors.New("literal%_marker hidden-password hidden-token")
		}
		input := core.AppModuleInput{SiteID: site, ResourceID: plan, Password: "hidden-password", Token: "hidden-token"}
		if err := svc.appendModuleEvent("file-monitor", "check", "inotify", input, map[string]any{"password": "hidden-result-secret"}, operationError); err != nil {
			t.Fatal(err)
		}
	}
	out, err := svc.moduleHistory("file-monitor", core.AppModuleInput{Offset: 100, Limit: 20})
	if err != nil || out.(map[string]any)["total"] != 131 || len(out.(map[string]any)["history"].([]moduleEvent)) != 20 {
		t.Fatal(out, err)
	}
	out, err = svc.moduleHistory("file-monitor", core.AppModuleInput{SiteID: first, ResourceID: "plan-first"})
	if err != nil || out.(map[string]any)["total"] != 65 {
		t.Fatal(out, err)
	}
	out, err = svc.moduleHistory("file-monitor", core.AppModuleInput{Search: "literal%_marker"})
	if err != nil || out.(map[string]any)["total"] != 13 {
		t.Fatal("search wildcards interpreted as patterns", out, err)
	}
	out, err = svc.moduleHistory("file-monitor", core.AppModuleInput{ToTime: time.Now().AddDate(0, -1, 0).UTC().Format(time.RFC3339)})
	if err != nil || out.(map[string]any)["total"] != 1 || out.(map[string]any)["history"].([]moduleEvent)[0].ID != old.ID {
		t.Fatal("imported history was lost", out, err)
	}
	restarted := New(svc.Config)
	out, err = restarted.moduleHistory("file-monitor", core.AppModuleInput{})
	if err != nil || out.(map[string]any)["total"] != 131 {
		t.Fatal("restart lost history or duplicated legacy import", out, err)
	}
	path := filepath.Join(svc.moduleDir("file-monitor"), "history.sqlite")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("history database not private", info, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(raw), "hidden-password") || strings.Contains(string(raw), "hidden-token") || strings.Contains(string(raw), "hidden-result-secret") {
		t.Fatal("ledger retained request secrets", err)
	}
}

func TestModuleLedgerUnsafePathsAndDamagedDatabasePreserved(t *testing.T) {
	for _, kind := range []string{"database-link", "journal-link", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			svc, _, _ := appReliabilityFixture(t)
			outside := filepath.Join(t.TempDir(), "preserve.txt")
			if err := os.WriteFile(outside, []byte("user-content"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(svc.moduleDir("file-monitor"), "history.sqlite")
			if kind == "journal-link" {
				path += "-journal"
			}
			if kind == "corrupt" {
				if err := os.WriteFile(path, []byte("corrupt-database"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
			if err := svc.appendModuleEvent("file-monitor", "check", "inotify", core.AppModuleInput{}, nil, nil); err == nil {
				t.Fatal("unsafe or damaged history accepted")
			}
			raw, err := os.ReadFile(outside)
			if err != nil || string(raw) != "user-content" {
				t.Fatal("outside data overwritten", err)
			}
			if kind == "corrupt" {
				raw, _ := os.ReadFile(path)
				if string(raw) != "corrupt-database" {
					t.Fatal("damaged evidence overwritten")
				}
			}
		})
	}
}

func TestModuleLedgerRetentionAndRecordCap(t *testing.T) {
	svc, _, _ := appReliabilityFixture(t)
	ctx := context.Background()
	db, err := svc.openModuleLedger(ctx, "file-monitor")
	if err != nil {
		t.Fatal(err)
	}
	stamp := core.Now()
	_, err = db.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100003) INSERT INTO module_events(seq,event_id,created_at,site_id,resource_id,payload) SELECT x,printf('%032x',x),?,'','',printf('{"id":"%032x","time":"%s","action":"check","trigger":"scheduled","outcome":"succeeded"}',x,?) FROM n`, time.Now().Unix(), stamp)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO module_events(event_id,created_at,site_id,resource_id,payload) VALUES(?,0,'','','{}')`, core.ID())
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	out, err := svc.moduleHistory("file-monitor", core.AppModuleInput{Limit: 10})
	if err != nil || out.(map[string]any)["retained_count"].(int) > 100000 || len(out.(map[string]any)["history"].([]moduleEvent)) != 10 {
		t.Fatal(out, err)
	}
	if out.(map[string]any)["retained_count"].(int) < 99999 {
		t.Fatal("record pruning discarded recent retained history", out)
	}
}
