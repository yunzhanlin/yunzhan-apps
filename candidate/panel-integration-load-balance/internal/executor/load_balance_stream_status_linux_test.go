//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"local/panel/internal/core"
)

func TestLoadBalanceStreamStatusPrivateRecordsCannotAdoptHostInstallation(t *testing.T) {
	for _, systemRoot := range []string{"/", t.TempDir()} {
		for _, raw := range []string{
			`{"id":"load-balance","version":"1.9.0","installation_id":"0123456789abcdef0123456789abcdef","settings":{}}`,
			`{"id":"load-balance","version":"1.9.0","settings":{}}`,
			`{"id":"load-balance","version":"1.9.0","installation_id":"0123456789abcdef0123456789abcdef","id":"load-balance"}`,
			`{"id":"load-balance","version":"99.0.0","installation_id":"0123456789abcdef0123456789abcdef"}`,
		} {
			calls := 0
			s := New(Config{SystemRoot: systemRoot, SecurityDir: filepath.Join(t.TempDir(), "security"),
				Run: func(context.Context, string, ...string) (string, error) {
					calls++
					return "", errors.New("external effects forbidden in private status fixture")
				}})
			path := filepath.Join(s.moduleDir("load-balance"), "installed.json")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, handled := s.loadBalanceStreamAppStatus(context.Background()); handled {
				t.Fatal("private configured root reached the fixed native host status reader")
			}
			status := s.appModuleStatus(context.Background(), "load-balance")
			if !status.StateUnknown || status.Installed || status.Healthy || status.Version != "" || status.InstallationID != "" || s.moduleInstalled("load-balance") {
				t.Fatal("copied native version/epoch became an installation", status)
			}
			for _, action := range []string{"install", "configure", "uninstall"} {
				if err := s.appModuleLifecycle(context.Background(), "load-balance", action, nil, func(string) {}); err == nil {
					t.Fatal("native status weakened legacy lifecycle refusal", action)
				}
			}
			after, err := os.Lstat(path)
			actual, readErr := os.ReadFile(path)
			if err != nil || readErr != nil || !geoStoreStableInfo(before, after) || string(actual) != raw || calls != 0 {
				t.Fatal("status/refusal mutated the fixture or executed a command")
			}
		}
	}
}

func TestLoadBalanceStreamStatusPreservesGenericLegacyAndAbsence(t *testing.T) {
	s := New(Config{SecurityDir: filepath.Join(t.TempDir(), "security")})
	path := filepath.Join(s.moduleDir("load-balance"), "installed.json")
	for _, version := range []string{"", "1.6.0", "1.8.5"} {
		value := map[string]any{"id": "load-balance", "settings": map[string]any{}, "installed_at": core.Now()}
		if version != "" {
			value["version"] = version
		}
		if err := moduleWrite(path, value); err != nil {
			t.Fatal(err)
		}
		if _, handled := s.loadBalanceStreamAppStatus(context.Background()); handled {
			t.Fatal("legacy record was reinterpreted as a native installation")
		}
		status := s.appModuleStatus(context.Background(), "load-balance")
		want := version
		if want == "" {
			want = "1.0"
		}
		if status.StateUnknown || !status.Installed || status.Version != want || status.InstallationID != "" {
			t.Fatal("legacy known installation/version changed", status)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	status := s.appModuleStatus(context.Background(), "load-balance")
	if status.StateUnknown || status.Installed || status.Healthy || status.Version != "" {
		t.Fatal("known legacy absence changed", status)
	}
}
