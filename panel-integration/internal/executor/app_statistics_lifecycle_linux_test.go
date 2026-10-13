//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"local/panel/internal/core"
)

// These use explicit native-command adapters plus a real Unix HTTP listener and
// private SQLite. They are lifecycle/data evidence, NOT signed-package or
// actual systemd/boot acceptance.
func TestStatisticsIdentityLifecycleUpdatePreservesDataAndRetryIdentity(t *testing.T) {
	s, _, _ := statisticsLogTransactionFixture(t)
	var calls []string
	statisticsLogTestCommands(t, s, "success", &calls)
	base := &Service{Config: s.Config}
	db, err := base.openStatisticsHistorySchema(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO access_rows(site,stamp,ip,path,status,seconds,bot,payload) VALUES(?,0,'','/original',200,0,0,'{}')", core.ID()); err != nil {
		t.Fatal(err)
	}
	db.Close()
	original, err := base.moduleInstalledRecord("website-statistics-v2")
	if err != nil {
		t.Fatal(err)
	}
	if err = base.updateSoftware(context.Background(), "website-statistics-v2", "2.5.0", func(string) {}); err != nil {
		t.Fatal(err)
	}
	current, err := base.moduleInstalledRecord("website-statistics-v2")
	if err != nil || current["version"] != "2.5.0" || current["installed_at"] != original["installed_at"] || !reflect.DeepEqual(current["settings"], original["settings"]) {
		t.Fatal("normal update identity", current, err)
	}
	schema, err := base.statisticsHistorySchemaReadOnly(context.Background())
	if err != nil || schema != 2 {
		t.Fatal("normal history publication", schema, err)
	}
	if status := base.appModuleStatus(context.Background(), "website-statistics-v2"); !status.Installed || !status.Healthy || status.StateUnknown {
		t.Fatal("normal ready status", status)
	}
	beforeConf, _ := os.ReadFile(base.Config.NginxConf)
	beforeManifest, _ := os.ReadFile(filepath.Join(base.moduleDir("website-statistics-v2"), "installed.json"))
	callCount := len(calls)
	if err = base.updateSoftware(context.Background(), "website-statistics-v2", "2.5.0", func(string) {}); err != nil {
		t.Fatal("same version readiness retry", err)
	}
	afterConf, _ := os.ReadFile(base.Config.NginxConf)
	afterManifest, _ := os.ReadFile(filepath.Join(base.moduleDir("website-statistics-v2"), "installed.json"))
	if !bytes.Equal(beforeConf, afterConf) || !bytes.Equal(beforeManifest, afterManifest) || len(calls) != callCount {
		t.Fatal("same-version retry rewrote native identity or record", calls)
	}
	db, err = base.openStatisticsHistory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err = db.QueryRow("SELECT count(*) FROM access_rows WHERE path='/original'").Scan(&count); err != nil || count != 1 {
		t.Fatal("original data lost", err)
	}
	if err = base.updateSoftware(context.Background(), "website-statistics-v2", "2.4.1", func(string) {}); err == nil {
		t.Fatal("downgrade accepted")
	}
}

func TestStatisticsIdentityLifecycleFreshInstallDoesNotOverwriteOrMisreportInvalidStore(t *testing.T) {
	s, _, _ := statisticsLogTransactionFixture(t)
	manifest := filepath.Join(s.moduleDir("website-statistics-v2"), "installed.json")
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	var calls []string
	statisticsLogTestCommands(t, s, "success", &calls)
	base := &Service{Config: s.Config}
	if err := base.appModuleLifecycleVersion(context.Background(), "website-statistics-v2", "install", map[string]any{}, "2.5.0", func(string) {}); err != nil {
		t.Fatal(err)
	}
	if status := base.appModuleStatus(context.Background(), "website-statistics-v2"); !status.Healthy || status.Version != "2.5.0" {
		t.Fatal(status)
	}
	before, _ := os.ReadFile(manifest)
	if err := base.appModuleLifecycleVersion(context.Background(), "website-statistics-v2", "install", map[string]any{"changed": true}, "2.5.0", func(string) {}); err == nil {
		t.Fatal("reinstall overwrote installed app")
	}
	after, _ := os.ReadFile(manifest)
	if !bytes.Equal(before, after) {
		t.Fatal("refused install changed record")
	}
	store := filepath.Join(base.moduleDir("website-statistics-v2"), "access.sqlite")
	if err := os.WriteFile(store, []byte("owned damaged store"), 0600); err != nil {
		t.Fatal(err)
	}
	damaged, _ := os.ReadFile(store)
	if status := base.appModuleStatus(context.Background(), "website-statistics-v2"); !status.Installed || status.Healthy {
		t.Fatal("damaged history reported ready", status)
	}
	if err := base.updateSoftware(context.Background(), "website-statistics-v2", "2.5.0", func(string) {}); err == nil {
		t.Fatal("damaged database accepted for update")
	}
	retained, _ := os.ReadFile(store)
	if !bytes.Equal(damaged, retained) {
		t.Fatal("damaged data overwritten")
	}
}

func TestStatisticsIdentityLifecyclePreflightAndReloadFailureRetainLegacySchema(t *testing.T) {
	for _, mode := range []string{"fail-once", "external-edit", "unsafe-db"} {
		t.Run(mode, func(t *testing.T) {
			s, old, _ := statisticsLogTransactionFixture(t)
			var calls []string
			statisticsLogTestCommands(t, s, mode, &calls)
			base := &Service{Config: s.Config}
			db, err := base.openStatisticsHistorySchema(context.Background(), 1)
			if err != nil {
				t.Fatal(err)
			}
			db.Close()
			store := filepath.Join(base.moduleDir("website-statistics-v2"), "access.sqlite")
			if mode == "unsafe-db" {
				if err = os.Chmod(store, 0644); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(store)
			if err = base.updateSoftware(context.Background(), "website-statistics-v2", "2.5.0", func(string) {}); err == nil {
				t.Fatal("failed preparation reported success")
			}
			manifest, _ := os.ReadFile(filepath.Join(base.moduleDir("website-statistics-v2"), "installed.json"))
			after, _ := os.ReadFile(store)
			if !bytes.Equal(manifest, old) || !bytes.Equal(before, after) {
				t.Fatal("precommit failure changed old app/store")
			}
			if mode == "unsafe-db" && len(calls) != 0 {
				t.Fatal("unsafe store reached native mutation", calls)
			}
		})
	}
}

func TestStatisticsIdentityLifecycleUninstallKeepsHistoryAndRefusesLegacyReinstall(t *testing.T) {
	s, _, _ := statisticsLogTransactionFixture(t)
	var calls []string
	statisticsLogTestCommands(t, s, "success", &calls)
	base := &Service{Config: s.Config}
	if err := base.updateSoftware(context.Background(), "website-statistics-v2", "2.5.0", func(string) {}); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(base.moduleDir("website-statistics-v2"), "access.sqlite")
	before, _ := os.ReadFile(store)
	if err := base.appModuleLifecycle(context.Background(), "website-statistics-v2", "uninstall", nil, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if err := base.appModuleLifecycleVersion(context.Background(), "website-statistics-v2", "install", nil, "2.4.1", func(string) {}); err == nil {
		t.Fatal("legacy install adopted preserved schema2")
	}
	after, _ := os.ReadFile(store)
	if !bytes.Equal(before, after) {
		t.Fatal("uninstall/rejected downgrade changed history")
	}
}

func TestStatisticsIdentityLifecycleUnrecognizedZeroSchemaAndTriggersFreezeWrites(t *testing.T) {
	for _, shape := range []string{"zero-nonempty", "foreign-trigger"} {
		t.Run(shape, func(t *testing.T) {
			s, original, _ := statisticsLogTransactionFixture(t)
			var calls []string
			statisticsLogTestCommands(t, s, "success", &calls)
			base := &Service{Config: s.Config}
			db, err := base.openStatisticsHistorySchema(context.Background(), 1)
			if err != nil {
				t.Fatal(err)
			}
			query := "PRAGMA user_version=0"
			if shape == "foreign-trigger" {
				query = "CREATE TRIGGER owned_unknown AFTER INSERT ON access_rows BEGIN DELETE FROM access_rows; END"
			}
			if _, err = db.Exec(query); err != nil {
				t.Fatal(err)
			}
			db.Close()
			store := filepath.Join(base.moduleDir("website-statistics-v2"), "access.sqlite")
			before, _ := os.ReadFile(store)
			if err = base.updateSoftware(context.Background(), "website-statistics-v2", "2.5.0", func(string) {}); err == nil {
				t.Fatal("unknown structure reached migration")
			}
			after, _ := os.ReadFile(store)
			manifest, _ := os.ReadFile(filepath.Join(base.moduleDir("website-statistics-v2"), "installed.json"))
			if !bytes.Equal(before, after) || !bytes.Equal(original, manifest) || len(calls) != 0 {
				t.Fatal("unknown structure changed data/identity/native config")
			}
		})
	}
}
