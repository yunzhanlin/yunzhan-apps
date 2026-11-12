//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyticsComparisonUnversionedInstallRetainsPreviousCapability(t *testing.T) {
	s := testService(t, func(context.Context, string, ...string) (string, error) {
		t.Fatal("the existing log format should require no external command")
		return "", nil
	})
	if err := os.WriteFile(s.Config.NginxConf, []byte(`"agent":"$http_user_agent"`), 0600); err != nil {
		t.Fatal(err)
	}
	const id = "website-analytics"
	if err := s.appModuleLifecycle(t.Context(), id, "install", nil, func(string) {}); err != nil {
		t.Fatal(err)
	}
	record, err := s.moduleInstalledRecord(id)
	if err != nil || record["version"] != core.AnalyticsQueryContextAppVersion {
		t.Fatalf("legacy installation advanced to a signed-only capability: %v, %v", record, err)
	}
	path := filepath.Join(s.moduleDir(id), "installed.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.appModuleLifecycle(t.Context(), id, "install", nil, func(string) {}); err == nil {
		t.Fatal("reinstalling the application overwrote its verified record")
	}
	current, err := os.ReadFile(path)
	if err != nil || string(current) != string(original) {
		t.Fatal("original installation record was changed", err)
	}
}
