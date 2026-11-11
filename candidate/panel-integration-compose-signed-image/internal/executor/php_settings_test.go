package executor

import (
	"encoding/json"
	"local/panel/internal/core"
	"strings"
	"testing"
)

func TestPHPConfigurationChangesCandidateWithoutChangingLegacyHealth(t *testing.T) {
	site := core.Site{ID: core.ID(), Domain: "params.localhost", PHPVersionID: "php-8.4.25", Settings: core.DefaultSiteSettings(core.SiteSettings{})}
	before := siteHealthBody(site)
	legacy, _ := json.Marshal(struct {
		Settings core.SiteSettings
		PHP      string
	}{site.Settings, site.PHPVersionID})
	if before != "panel:"+site.ID+":"+core.Hash(string(legacy)) {
		t.Fatal("legacy health contract changed")
	}
	old := phpPoolConfiguration(site, "/srv/panel/sites/"+site.ID)
	if !strings.Contains(old, "pm.max_children = 3\n") || !strings.Contains(old, "php_admin_flag[display_errors] = off\n") {
		t.Fatal("legacy FPM defaults changed")
	}
	options := core.DefaultPHPSettings()
	options.MemoryMB = 256
	options.Timezone = "Asia/Shanghai"
	options.MaxChildren = 5
	options.BlockProcessFunctions = true
	site.Settings.PHP = &options
	configured := phpPoolConfiguration(site, "/srv/panel/sites/"+site.ID)
	for _, part := range []string{"-cfg-", "pm.max_children = 5\n", "php_admin_value[memory_limit] = 256M", "php_admin_value[date.timezone] = Asia/Shanghai"} {
		if !strings.Contains(configured, part) {
			t.Fatal("missing configured FPM directive", part)
		}
	}
	if siteHealthBody(site) == before {
		t.Fatal("PHP parameters do not alter ingress verification")
	}
	if !strings.Contains(phpProbeScript(site), "ini_get('memory_limit')") || !strings.Contains(phpProbeExpected(site), "|256M|60|2M|8M|Asia/Shanghai|0") {
		t.Fatal("candidate probe does not check configured values")
	}
	if !strings.Contains(configured, "php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec\n") ||
		!strings.Contains(phpProbeScript(site), "function_exists($name)") ||
		!strings.Contains(phpProbeExpected(site), "|Asia/Shanghai|0|1") {
		t.Fatal("the PHP worker must prove the configured functions are unavailable")
	}
}
