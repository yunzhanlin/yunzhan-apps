package executor

import (
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"strings"
)

func phpSessionProgressGuarded(r runtimecatalog.Release) bool {
	return r.Family == "php" && strings.HasPrefix(r.Version, "8.")
}

func phpProbeScript(site core.Site) string {
	code := "<?php header('Content-Type: text/plain'); echo PHP_VERSION;"
	for _, pair := range core.PHPIniValues(site.Settings.PHP) {
		switch pair[0] {
		case "display_errors":
			code += " echo '|', filter_var(ini_get('display_errors'), FILTER_VALIDATE_BOOL) ? '1' : '0';"
		case "disable_functions":
			required := strings.ReplaceAll(pair[1], ",", "','")
			code += " $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));"
			code += " $protected = true; foreach (array('" + required + "') as $name) {"
			code += " if (function_exists($name) || !in_array($name, $disabled, true)) { $protected = false; break; } }"
			code += " echo '|', $protected ? '1' : '0';"
		default:
			code += " echo '|', ini_get('" + pair[0] + "');"
		}
	}
	if r, ok := runtimecatalog.Find(site.PHPVersionID); ok && phpSessionProgressGuarded(r) {
		code += " echo '|', filter_var(ini_get('session.upload_progress.enabled'), FILTER_VALIDATE_BOOL) ? '1' : '0';"
	}
	if site.Settings.PHP != nil {
		for _, id := range site.Settings.PHP.Extensions {
			ext, _ := runtimecatalog.FindExtension(id)
			code += " echo '|', phpversion('" + ext.Name + "');"
		}
	}
	return code
}
func phpProbeExpected(site core.Site) string {
	expected := phpVersion(site.PHPVersionID)
	for _, pair := range core.PHPIniValues(site.Settings.PHP) {
		value := pair[1]
		if pair[0] == "disable_functions" {
			value = "1"
		}
		expected += "|" + value
	}
	if r, ok := runtimecatalog.Find(site.PHPVersionID); ok && phpSessionProgressGuarded(r) {
		expected += "|0"
	}
	if site.Settings.PHP != nil {
		for _, id := range site.Settings.PHP.Extensions {
			ext, _ := runtimecatalog.FindExtension(id)
			expected += "|" + ext.Version
		}
	}
	return expected
}
func phpPoolConfiguration(site core.Site, dir string) string {
	// The unset form stays byte-for-byte compatible with existing pools.
	settings := core.DefaultPHPSettings()
	if site.Settings.PHP != nil {
		settings = *site.Settings.PHP
	}
	pool := fmt.Sprintf("[global]\nerror_log = syslog\nsyslog.ident = panel-php\ndaemonize = no\n[site]\nuser = ps%s\ngroup = ps%s\nlisten = /run/panel-php-%s/fpm.sock\nlisten.owner = www-data\nlisten.group = www-data\nlisten.mode = 0660\npm = ondemand\npm.max_children = %d\npm.process_idle_timeout = 10s\npm.max_requests = %d\nclear_env = yes\ncatch_workers_output = yes\nsecurity.limit_extensions = .php\nchdir = %s/public\nphp_admin_value[open_basedir] = %s/public:%s/private:/tmp\nphp_admin_value[session.save_path] = %s/private\nphp_admin_flag[log_errors] = on\nphp_admin_flag[display_errors] = off\n", site.ID[:24], site.ID[:24], core.PHPInstanceID(site), settings.MaxChildren, settings.MaxRequests, dir, dir, dir, dir)
	if site.Settings.PHP != nil {
		pool = strings.TrimSuffix(pool, "php_admin_flag[display_errors] = off\n")
		for _, pair := range core.PHPIniValues(site.Settings.PHP) {
			pool += fmt.Sprintf("php_admin_value[%s] = %s\n", pair[0], pair[1])
		}
	}
	if site.Settings.PHP != nil && len(site.Settings.PHP.Extensions) > 0 {
		pool += "; startup extensions: " + strings.Join(site.Settings.PHP.Extensions, ", ") + "\n"
	}
	return pool
}
