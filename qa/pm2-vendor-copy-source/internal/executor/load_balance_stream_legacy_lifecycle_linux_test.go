//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"local/panel/internal/core"
)

func TestLoadBalanceStreamSelectedLifecycleRefusesBeforeFilesOrCommands(t *testing.T) {
	s := New(Config{SecurityDir: filepath.Join(t.TempDir(), "security")})
	path := filepath.Join(s.moduleDir("load-balance"), "installed.json")
	if err := moduleWrite(path, map[string]any{"id": "load-balance", "version": "1.8.5", "settings": map[string]any{}, "installed_at": core.Now()}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	calls, steps := 0, 0
	s.Config.Run = func(context.Context, string, ...string) (string, error) { calls++; return "", nil }
	for _, version := range []string{"1.9.0", "1.9.0-rc1", "2.0.0"} {
		if err := s.updateSoftware(context.Background(), "load-balance", version, func(string) { steps++ }); err != errLoadBalanceStreamIndependentLifecycle {
			t.Fatal("selected four-layer update reached generic metadata update", version, err)
		}
		for _, action := range []string{"install", "configure", "uninstall"} {
			if err := s.appModuleLifecycleVersion(context.Background(), "load-balance", action, nil, version, func(string) { steps++ }); err != errLoadBalanceStreamIndependentLifecycle {
				t.Fatal("selected four-layer version reached generic lifecycle", version, action, err)
			}
		}
	}
	after, err := os.ReadFile(path)
	newInfo, statErr := os.Lstat(path)
	if err != nil || statErr != nil || string(after) != string(before) || !geoStoreStableInfo(info, newInfo) || calls != 0 || steps != 0 {
		t.Fatal("refusal changed an old record or performed an effect")
	}
}
