package core

import (
	"encoding/json"
	"local/panel/internal/runtimecatalog"
	"testing"
)

func TestExtensionQueueProtectsPHPAndKeepsPayload(t *testing.T) {
	s := testStore(t)
	r, _ := runtimecatalog.Find("php-8.4.25")
	ext := runtimecatalog.Extensions[0]
	if _, e := s.QueuePHPExtension(r.ID, ext.ID, ID(), "admin"); e == nil {
		t.Fatal("uninstalled PHP accepted")
	}
	if e := s.RecordInstallation(r, "arm64"); e != nil {
		t.Fatal(e)
	}
	key := ID()
	id, e := s.QueuePHPExtension(r.ID, ext.ID, key, "admin")
	if e != nil {
		t.Fatal(e)
	}
	if repeat, e := s.QueuePHPExtension(r.ID, ext.ID, key, "admin"); e != nil || repeat != id {
		t.Fatal("idempotency", e)
	}
	if _, e = s.QueueRuntimeLifecycle(r.ID, "retire", ID(), "admin"); e == nil {
		t.Fatal("extension build did not protect PHP")
	}
	j, e := s.NextRuntimeJob()
	if e != nil {
		t.Fatal(e)
	}
	var payload ExtensionJobPayload
	if e = json.Unmarshal([]byte(j.Payload), &payload); e != nil || payload.ExtensionID != ext.ID || j.Kind != "install_php_extension" {
		t.Fatal("extension task payload lost", j, e)
	}
	if e = s.FinishRuntime(j, "build failed", nil); e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueRuntimeLifecycle(r.ID, "retire", ID(), "admin"); e != nil {
		t.Fatal(e)
	}
	if e = s.RetryRuntime(id, "admin"); e == nil {
		t.Fatal("extension retry raced with retirement")
	}
}

func TestExtensionSelectionRequiresExactPHPInstallation(t *testing.T) {
	s := testStore(t)
	r, _ := runtimecatalog.Find("php-8.4.25")
	target, _ := runtimecatalog.Find("php-8.5.10")
	for _, v := range []runtimecatalog.Release{r, target} {
		if e := s.RecordInstallation(v, "arm64"); e != nil {
			t.Fatal(e)
		}
	}
	_, e := s.CreateSite("extension selection", "extension-selection", ID(), "admin", r.ID)
	if e != nil {
		t.Fatal(e)
	}
	j, _ := s.NextJob()
	if e = s.Finish(j, "running", "", nil); e != nil {
		t.Fatal(e)
	}
	site, _ := s.Site(j.SiteID)
	settings := site.Settings
	options := DefaultPHPSettings()
	options.Extensions = []string{"redis-6.3.0"}
	settings.PHP = &options
	if _, e = s.QueueSiteSettings(site.ID, settings, site.SettingsRevision, Hash("config"), ID(), "admin"); e == nil {
		t.Fatal("uninstalled extension enabled")
	}
	evidence := ExtensionInstallation{ReleaseID: r.ID, ExtensionID: "redis-6.3.0", Version: "6.3.0", Architecture: "arm64", ABI: "no-debug-non-zts-20240924", ModuleSHA: Hash("module"), InstalledAt: Now()}
	if e = s.RecordPHPExtension(evidence); e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueSiteSettings(site.ID, settings, site.SettingsRevision, Hash("config"), ID(), "admin"); e != nil {
		t.Fatal(e)
	}
	j, _ = s.NextJob()
	if e = s.Finish(j, "running", "", nil); e != nil {
		t.Fatal(e)
	}
	site, _ = s.Site(site.ID)
	if _, e = s.QueuePHP(site.ID, target.ID, "admin"); e == nil {
		t.Fatal("extension crossed PHP version without separate installation")
	}
	evidence.ReleaseID = target.ID
	evidence.ABI = "no-debug-non-zts-20250925"
	if e = s.RecordPHPExtension(evidence); e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueuePHP(site.ID, target.ID, "admin"); e != nil {
		t.Fatal(e)
	}
	j, _ = s.NextJob()
	if e = s.Finish(j, "running", "candidate rejected", nil); e != nil {
		t.Fatal(e)
	}
	after, _ := s.Site(site.ID)
	if after.PHPVersionID != r.ID || after.RuntimeInstanceID != site.RuntimeInstanceID {
		t.Fatal("failed target changed binding")
	}
}
func TestExtensionSettingsPreserveLegacyJSON(t *testing.T) {
	p := DefaultPHPSettings()
	before, _ := json.Marshal(p)
	if string(before) != `{"memory_mb":128,"max_execution_seconds":60,"upload_mb":2,"post_mb":8,"timezone":"UTC","display_errors":false,"max_children":3,"max_requests":500}` {
		t.Fatal("M5 configuration identity changed", string(before))
	}
	for _, ids := range [][]string{{"../../evil.so"}, {"redis-6.3.0", "redis-6.3.0"}, {"redis-99"}} {
		p.Extensions = ids
		if ValidatePHPSettings(&p) == nil {
			t.Fatal("invalid extension accepted", ids)
		}
	}
}
