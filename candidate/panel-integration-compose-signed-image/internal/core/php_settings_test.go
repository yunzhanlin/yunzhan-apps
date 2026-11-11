package core

import (
	"encoding/json"
	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
	"strings"
	"testing"
)

func TestPHPProcessPolicyApplicationVersions(t *testing.T) {
	const id = "php-code-security"
	if SoftwareImplementationVersion(id) != appcatalog.PHPProcessPolicyVersion {
		t.Fatal("compiled PHP code security version does not match its policy handler")
	}
	for _, version := range []string{"1.3.0", appcatalog.PHPProcessPolicyVersion} {
		if err := ValidateSoftwareInstallVersion(id, version); err != nil {
			t.Fatal(version, err)
		}
	}
	for _, version := range []string{"1.3.1-compat1", "01.3.1", "1.3.2"} {
		if ValidateSoftwareInstallVersion(id, version) == nil {
			t.Fatal("unreviewed PHP code security version accepted", version)
		}
	}
	s := testStore(t)
	for _, action := range []string{"install", "update"} {
		if _, err := s.queueSoftwareAction(id, action, nil, appcatalog.PHPProcessPolicyVersion, ID(), "admin"); err == nil {
			t.Fatal("new PHP code security package bypassed the signed store", action)
		}
	}
}

func TestPHPSettingsValidationAndLegacyIdentity(t *testing.T) {
	s := Site{ID: ID(), PHPVersionID: "php-8.4.25", Settings: DefaultSiteSettings(SiteSettings{})}
	original := s.ID + "-" + s.PHPVersionID
	if PHPInstanceID(s) != original {
		t.Fatal("legacy instance changed")
	}
	b, _ := json.Marshal(s.Settings)
	if strings.Contains(string(b), `"php"`) {
		t.Fatal("unset PHP mutated old JSON")
	}
	defaults := DefaultPHPSettings()
	if e := ValidatePHPSettings(&defaults); e != nil {
		t.Fatal(e)
	}
	s.Settings.PHP = &defaults
	first := PHPInstanceID(s)
	if first == original || len("/run/panel-php-"+first+"/fpm.sock") >= 108 {
		t.Fatal("invalid socket identity", first)
	}
	defaults.BlockProcessFunctions = true
	if first == PHPInstanceID(s) {
		t.Fatal("process-function policy did not receive a distinct FPM identity")
	}
	defaults.BlockProcessFunctions = false
	if first != PHPInstanceID(s) {
		t.Fatal("disabled policy changed an existing FPM identity")
	}
	defaults.MemoryMB = 256
	if first == PHPInstanceID(s) {
		t.Fatal("configuration retained candidate identity")
	}
	for _, alter := range []func(*PHPSettings){func(x *PHPSettings) { x.MemoryMB = 4 }, func(x *PHPSettings) { x.UploadMB = 513 }, func(x *PHPSettings) { x.PostMB = 1 }, func(x *PHPSettings) { x.Timezone = "UTC\ninclude=/etc/passwd" }, func(x *PHPSettings) { x.Timezone = "Asia/NotAPlace" }, func(x *PHPSettings) { x.MaxChildren = 33 }} {
		x := DefaultPHPSettings()
		alter(&x)
		if e := ValidatePHPSettings(&x); e == nil {
			t.Fatal("invalid PHP settings accepted", x)
		}
	}
}
func TestPHPConfigurationBindingCommitsOnlyWithSettings(t *testing.T) {
	s := testStore(t)
	r, _ := runtimecatalog.Find("php-8.4.25")
	s.RecordInstallation(r, "arm64")
	s.CreateSite("PHP settings", "php-settings", ID(), "admin", r.ID)
	j, e := s.NextJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Finish(j, "running", "", nil); e != nil {
		t.Fatal(e)
	}
	site, _ := s.Site(j.SiteID)
	old := site.RuntimeInstanceID
	settings := site.Settings
	options := DefaultPHPSettings()
	options.MemoryMB = 256
	settings.PHP = &options
	_, e = s.QueueSiteSettings(site.ID, settings, site.SettingsRevision, Hash("config"), ID(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	j, e = s.NextJob()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Finish(j, "running", "", nil); e != nil {
		t.Fatal(e)
	}
	site, _ = s.Site(site.ID)
	if site.RuntimeInstanceID == old || site.RuntimeInstanceID != PHPInstanceID(site) || site.Settings.PHP.MemoryMB != 256 {
		t.Fatal("configured binding not committed", site)
	}
	options.MemoryMB = 512
	settings.PHP = &options
	s.QueueSiteSettings(site.ID, settings, site.SettingsRevision, Hash("config2"), ID(), "admin")
	j, _ = s.NextJob()
	s.Finish(j, "running", "candidate rejected", nil)
	retained, _ := s.Site(site.ID)
	if retained.RuntimeInstanceID != site.RuntimeInstanceID || retained.Settings.PHP.MemoryMB != 256 {
		t.Fatal("failed candidate changed stored binding")
	}
}
