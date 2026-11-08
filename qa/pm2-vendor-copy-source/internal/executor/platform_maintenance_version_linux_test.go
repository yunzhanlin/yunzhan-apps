//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestPlatformMaintenanceNativeInstalledInstanceIsNotAReadOnlyVersionOrAlias(t *testing.T) {
	s, _ := moduleRecordFixture(t)
	p := filepath.Join(s.moduleDir("platform-ops"), "installed.json")
	for _, version := range []string{"1.2.0", "1.3", "1.3.0-compat1", core.PlatformMaintenanceAppVersion} {
		for _, instance := range []string{"", "bad", core.ID()} {
			row := map[string]any{"id": "platform-ops", "version": version, "settings": map[string]any{}, "installed_at": core.Now()}
			if instance != "" {
				row["installation_id"] = instance
			}
			if e := moduleWrite(p, row); e != nil {
				t.Fatal(e)
			}
			before, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			info, e := os.Stat(p)
			if e != nil {
				t.Fatal(e)
			}
			got, e := s.platformMaintenanceInstallation()
			pass := version == core.PlatformMaintenanceAppVersion && core.ValidID(instance)
			if (e == nil) != pass || pass && got != instance {
				t.Fatal(version, instance, got, e)
			}
			after, re := os.ReadFile(p)
			current, se := os.Stat(p)
			if re != nil || se != nil || string(before) != string(after) || !os.SameFile(info, current) {
				t.Fatal("identity reader repaired installed record")
			}
		}
	}
	// A real settings save retains the already verified instance. These module
	// lifecycle calls have no Nginx, systemd, app install or external commands.
	instance := core.ID()
	if e := moduleWrite(p, map[string]any{"id": "platform-ops", "version": core.PlatformMaintenanceAppVersion, "installation_id": instance, "settings": map[string]any{}, "installed_at": core.Now()}); e != nil {
		t.Fatal(e)
	}
	if e := s.appModuleLifecycle(context.Background(), "platform-ops", "configure", map[string]any{}, func(string) {}); e != nil {
		t.Fatal(e)
	}
	if current, e := s.platformMaintenanceInstallation(); e != nil || current != instance {
		t.Fatal("settings save changed installation authority", e)
	}
}

func TestPlatformMaintenanceNativeLifecyclePreservesOldSignedSelectionAndCreatesNewInstances(t *testing.T) {
	s, _ := moduleRecordFixture(t)
	p := filepath.Join(s.moduleDir("platform-ops"), "installed.json")
	add := func(string) {}
	// This is an own-directory metadata fixture, not a signed install proof.
	if e := s.appModuleLifecycle(context.Background(), "platform-ops", "install", nil, add); e == nil {
		t.Fatal("unselected legacy install enabled maintenance")
	}
	if e := s.appModuleLifecycleVersion(context.Background(), "platform-ops", "install", nil, "1.2.0", add); e != nil {
		t.Fatal(e)
	}
	legacy, e := s.moduleInstalledRecord("platform-ops")
	if e != nil || legacy["version"] != "1.2.0" || legacy["installation_id"] != nil {
		t.Fatal("old signed selection upgraded", legacy, e)
	}
	before, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.appModuleLifecycleVersion(context.Background(), "platform-ops", "install", nil, core.PlatformMaintenanceAppVersion, add); e == nil {
		t.Fatal("install overwrote existing app")
	}
	if current, e := os.ReadFile(p); e != nil || string(current) != string(before) {
		t.Fatal("rejected install changed legacy record")
	}
	if e := s.updateSoftware(context.Background(), "platform-ops", core.PlatformMaintenanceAppVersion, add); e != nil {
		t.Fatal(e)
	}
	first, e := s.platformMaintenanceInstallation()
	if e != nil {
		t.Fatal(e)
	}
	if e := s.appModuleLifecycle(context.Background(), "platform-ops", "configure", map[string]any{}, add); e != nil {
		t.Fatal(e)
	}
	if current, e := s.platformMaintenanceInstallation(); e != nil || current != first {
		t.Fatal("configure changed original installation")
	}
	if e := s.updateSoftware(context.Background(), "platform-ops", core.PlatformMaintenanceAppVersion, add); e != nil {
		t.Fatal(e)
	}
	if current, e := s.platformMaintenanceInstallation(); e != nil || current != first {
		t.Fatal("same-version repair changed original installation")
	}
	if e := s.appModuleLifecycle(context.Background(), "platform-ops", "uninstall", nil, add); e != nil {
		t.Fatal(e)
	}
	if e := s.appModuleLifecycleVersion(context.Background(), "platform-ops", "install", nil, core.PlatformMaintenanceAppVersion, add); e != nil {
		t.Fatal(e)
	}
	second, e := s.platformMaintenanceInstallation()
	if e != nil || second == first {
		t.Fatal("reinstall revived original instance", e)
	}
}
