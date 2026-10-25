package executor

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func statisticsNginxTestConfig(format string) []byte {
	return []byte("# untouched startup\nuser www-data;\nevents {}\nhttp {\n" + statisticsNginxPathMap + "\n" + statisticsNginxRefererMap + "\nlog_format panel_site escape=json '" + format + "';\nserver {listen 127.0.0.1:19101; location / {return 200 'OWN';}}\n}\n")
}
func TestStatisticsNginxTokenSpanPreservesOtherDirectivesAndIsIdempotent(t *testing.T) {
	original := statisticsNginxTestConfig(statisticsNginxLegacyFormat)
	// These real comments and unrelated strings must not be selected as code.
	original = bytes.Replace(original, []byte("http {"), []byte("# log_format panel_site escape=json 'fake';\nhttp {\nmap $host $panel_unrelated { default 'log_format panel_site; { } # agent'; }"), 1)
	updated, changed, e := statisticsRequestIDNginxConfig(original)
	want := bytes.Replace(original, []byte("'"+statisticsNginxLegacyFormat+"'"), []byte("'"+statisticsNginxRequestFormat+"'"), 1)
	if e != nil || !changed || !bytes.Equal(updated, want) {
		t.Fatal("non-target configuration changed", e)
	}
	next, changed, e := statisticsRequestIDNginxConfig(updated)
	if e != nil || changed || !bytes.Equal(next, updated) {
		t.Fatal("same format replay changed bytes", e)
	}
	crlf := bytes.ReplaceAll(statisticsNginxTestConfig(statisticsNginxLegacyFormat), []byte("\n"), []byte("\r\n"))
	if out, _, e := statisticsRequestIDNginxConfig(crlf); e != nil || bytes.Count(out, []byte("\r\n")) != bytes.Count(crlf, []byte("\r\n")) {
		t.Fatal("CRLF preservation", e)
	}
}
func TestStatisticsNginxCustomDuplicateQuotedAndPrivacyDriftAreClosed(t *testing.T) {
	source := string(statisticsNginxTestConfig(statisticsNginxLegacyFormat))
	for name, raw := range map[string]string{
		"comment-only":        strings.Replace(source, "log_format panel_site", "#log_format panel_site", 1),
		"duplicate":           strings.Replace(source, "log_format panel_site", "log_format panel_site escape=json '"+statisticsNginxLegacyFormat+"'; log_format panel_site", 1),
		"custom-path":         strings.Replace(source, "\"path\":\"$panel_log_path\"", "\"path\":\"$request_uri\"", 1),
		"custom-id":           strings.Replace(source, statisticsNginxLegacyFormat, strings.Replace(statisticsNginxRequestFormat, "$request_id", "$http_x_request_id", 1), 1),
		"privacy-map-drift":   strings.Replace(source, "default $uri", "default $request_uri", 1),
		"privacy-map-missing": strings.Replace(source, statisticsNginxRefererMap, "", 1),
		"nested":              strings.Replace(source, "log_format panel_site", "server { log_format panel_site", 1) + "}",
		"unterminated":        source[:len(source)-3],
		"nul":                 source + "\x00",
		"string-only":         "events {} http { set $unrelated 'log_format panel_site escape=json fake;'; }",
	} {
		t.Run(name, func(t *testing.T) {
			if out, changed, e := statisticsRequestIDNginxConfig([]byte(raw)); !errors.Is(e, errStatisticsNginxCustom) || changed || out != nil {
				t.Fatal("custom/malformed format adopted", name, e)
			}
		})
	}
}
