//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAppUpdatePreservesSettingsBaselineHistoryAndInstallTime(t *testing.T) {
	svc, _, _ := appReliabilityFixture(t)
	id := "files-sync"
	path := filepath.Join(svc.moduleDir(id), "installed.json")
	// Only documented top-level installation fields are accepted. Custom
	// application state belongs inside settings, not an unclosed manifest.
	before := map[string]any{"id": id, "version": "1.0", "settings": map[string]any{"interval": float64(600), "excludes": []any{"private"}, "custom_state": "keep"}, "installed_at": "2026-01-01T00:00:00Z"}
	if err := moduleWrite(path, before); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"baseline.json", "history.json", "last-report.json", "sync-state.json"} {
		if err := os.WriteFile(filepath.Join(svc.moduleDir(id), file), []byte("user-data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.updateSoftware(context.Background(), id, "99.0.0", func(string) {}); err == nil {
		t.Fatal("missing implementation allowed")
	}
	if _, err := svc.moduleInstalledRecord(id); err != nil {
		t.Fatal("known installed fixture required", err)
	}
	version := core.SoftwareImplementationVersion(id)
	if err := svc.updateSoftware(context.Background(), id, version, func(string) {}); err != nil {
		t.Fatal(err)
	}
	var after map[string]any
	if err := moduleRead(path, &after); err != nil {
		t.Fatal(err)
	}
	if after["version"] != version || after["updated_at"] == "" || after["installed_at"] != before["installed_at"] || !reflect.DeepEqual(after["settings"], before["settings"]) {
		t.Fatal("update erased application state", after)
	}
	for _, file := range []string{"baseline.json", "history.json", "last-report.json", "sync-state.json"} {
		b, err := os.ReadFile(filepath.Join(svc.moduleDir(id), file))
		if err != nil || string(b) != "user-data" {
			t.Fatal("update altered history/baseline", file, err)
		}
	}
	if err := svc.updateSoftware(context.Background(), id, "1.0", func(string) {}); err == nil {
		t.Fatal("downgrade allowed")
	}
	if err := svc.updateSoftware(context.Background(), "task-manager", "1.1.0", func(string) {}); err == nil {
		t.Fatal("uninstalled module marked updated")
	}
}
