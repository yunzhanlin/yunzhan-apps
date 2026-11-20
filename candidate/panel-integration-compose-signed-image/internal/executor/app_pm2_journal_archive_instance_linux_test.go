//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPM2JournalArchiveStatusExportsOnlyVerifiedCurrentInstance(t *testing.T) {
	s, _ := pm2ArchiveActiveFixture(t)
	path := filepath.Join(s.moduleDir("pm2-manager"), "installed.json")
	instance := "77777777777777777777777777777777"
	if err := moduleWrite(path, map[string]string{"id": "pm2-manager", "version": core.PM2ConfigurationArchiveAppVersion, "installation_id": instance}); err != nil {
		t.Fatal(err)
	}
	before := programQueueTree(t, s.Config.SecurityDir)
	status := s.appModuleStatus(context.Background(), "pm2-manager")
	if !status.Installed || status.StateUnknown || status.InstallationID != instance {
		t.Fatal("normal module status omitted current instance", status)
	}
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SecurityDir)) {
		t.Fatal("status lookup changed original installation authority")
	}
	if err := moduleWrite(path, map[string]string{"id": "pm2-manager", "version": core.PM2ConfigurationArchiveAppVersion}); err != nil {
		t.Fatal(err)
	}
	before = programQueueTree(t, s.Config.SecurityDir)
	status = s.appModuleStatus(context.Background(), "pm2-manager")
	if !status.StateUnknown || status.InstallationID != "" {
		t.Fatal("missing current instance was invented or adopted")
	}
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SecurityDir)) {
		t.Fatal("unknown installation instance was repaired by read")
	}
}
func TestPM2JournalArchiveRootRejectsStaleInstanceAfterReplacement(t *testing.T) {
	s, _ := pm2ArchiveActiveFixture(t)
	path := filepath.Join(s.moduleDir("pm2-manager"), "installed.json")
	current := "88888888888888888888888888888888"
	if err := moduleWrite(path, map[string]string{"id": "pm2-manager", "version": core.PM2ConfigurationArchiveAppVersion, "installation_id": current}); err != nil {
		t.Fatal(err)
	}
	before := programQueueTree(t, s.Config.SecurityDir)
	if w := pm2JournalArchiveGET(s, ""); w.Code != 409 {
		t.Fatal("old instance read new installation", w.Code)
	}
	in := core.AppModuleInput{PM2InstallationID: "77777777777777777777777777777777", PM2OperationID: core.ID(), ExpectedSHA: core.Hash("original"), Confirm: "ARCHIVE PM2 CONFIGURATIONS " + core.Hash("original")}
	if _, err := s.runAppModule(context.Background(), "pm2-manager", "archive-configurations", in); err == nil {
		t.Fatal("Root adopted delayed archive request after installation replacement")
	}
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SecurityDir)) {
		t.Fatal("stale instance refusal changed original data")
	}
	if err := s.pm2ConfigurationArchiveVersion(current); err != nil {
		t.Fatal("exact current authority refused", err)
	}
}

func TestPM2JournalArchiveInstallationFieldNeverAuthorizesOlderOrOtherModules(t *testing.T) {
	for _, kind := range []string{"old-PM2", "future-alias", "other-module", "invalid-current-id"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := pm2ArchiveActiveFixture(t)
			id := "pm2-manager"
			version := core.PM2ConfigurationArchiveAppVersion
			instance := "77777777777777777777777777777777"
			switch kind {
			case "old-PM2":
				version = core.PM2RootVendorAppVersion
			case "future-alias":
				version += ".0"
			case "other-module":
				id = "nfs-manager"
				version = core.SoftwareImplementationVersion(id)
			case "invalid-current-id":
				instance = "broken"
			}
			path := filepath.Join(s.moduleDir(id), "installed.json")
			if err := moduleWrite(path, map[string]string{"id": id, "version": version, "installation_id": instance}); err != nil {
				t.Fatal(err)
			}
			before := programQueueTree(t, s.Config.SecurityDir)
			if _, err := s.moduleInstalledRecord(id); err == nil {
				t.Fatal("unrelated or invalid installation authority was adopted", kind)
			}
			if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SecurityDir)) {
				t.Fatal("rejected installation record was changed")
			}
		})
	}
}
