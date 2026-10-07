package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestModuleWorkspacesCoverActualOperations(t *testing.T) {
	for _, def := range AppModules() {
		sections := ModuleWorkspace(def.ID)
		if len(sections) == 0 {
			t.Fatal("missing workspace", def.ID)
		}
		fields, actions, ids := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, field := range def.Fields {
			fields[field.Key] = true
		}
		for _, section := range sections {
			if ids[section.ID] || section.Help == "" || section.Label == "" {
				t.Fatal("invalid section", def.ID, section)
			}
			ids[section.ID] = true
			for _, field := range section.Fields {
				if !fields[field] {
					t.Fatal("unknown workspace field", def.ID, field)
				}
			}
			for _, action := range section.Actions {
				if !ValidAppModuleAction(def.ID, action) {
					t.Fatal("unknown workspace operation", def.ID, action)
				}
				actions[action] = true
			}
		}
		for _, action := range def.Actions {
			if action != "history" && !actions[action] {
				t.Fatal("hidden operation", def.ID, action)
			}
		}
	}
}

func TestModuleInstallationNeverPersistsBusinessCredentials(t *testing.T) {
	for _, value := range []map[string]any{{"password": "secret"}, {"token": "secret"}, {"environment_patch": map[string]any{"API_KEY": "secret"}}} {
		if _, err := validateModuleSettings(value); err == nil {
			t.Fatal("business credential accepted as plaintext installation settings")
		}
	}
	if _, err := validateModuleSettings(map[string]any{"site_id": "owned"}); err != nil {
		t.Fatal(err)
	}
}

func TestModuleHistoryBoundedAndContainsNoSecrets(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 130; i++ {
		if err := s.recordAppModuleEvent("platform-ops", fmt.Sprint(i), "admin", errors.New("secret-token-in-error")); err != nil {
			t.Fatal(err)
		}
	}
	result, err := s.appModuleHistory("platform-ops")
	if err != nil {
		t.Fatal(err)
	}
	rows := result.(map[string]any)["history"].([]map[string]any)
	if len(rows) != 100 || rows[0]["action"] != "129" || rows[99]["action"] != "30" {
		t.Fatal(rows)
	}
	b, _ := json.Marshal(result)
	if strings.Contains(string(b), "secret-token") {
		t.Fatal("history leaked error contents")
	}
}

func TestDailyReportArchiveIsReadOnlyAndValidated(t *testing.T) {
	a := &Server{Store: testStore(t)}
	_, err := a.Store.DB.Exec(`INSERT INTO app_daily_reports VALUES('2026-10-05','{"sites":9}','2026-10-05T01:00:00Z')`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.dailyReportOperation(context.Background(), "archive", AppModuleInput{})
	if err != nil || len(result.(map[string]any)["reports"].([]map[string]any)) != 1 {
		t.Fatal(result, err)
	}
	result, err = a.dailyReportOperation(context.Background(), "report", AppModuleInput{ResourceID: "2026-10-05"})
	if err != nil || result.(map[string]any)["sites"] != float64(9) {
		t.Fatal(result, err)
	}
	for _, day := range []string{"2026-02-30", "../2026-10-05", "2026-10-06"} {
		if _, err = a.dailyReportOperation(context.Background(), "report", AppModuleInput{ResourceID: day}); err == nil {
			t.Fatal("invalid or missing report accepted", day)
		}
	}
}
