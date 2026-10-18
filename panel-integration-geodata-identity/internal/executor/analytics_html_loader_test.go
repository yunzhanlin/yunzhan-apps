package executor

import (
	"strings"
	"testing"
)

func TestAnalyticsHTMLLoaderOwnershipContextAndLargeMain(t *testing.T) {
	id := strings.Repeat("a", 32)
	original := strings.Repeat("# many sites are included elsewhere\n", 2000) + "events {}\nhttp {\n}\n"
	on, err := renderAnalyticsHTMLLoader(original, id, true)
	if err != nil || verifyAnalyticsHTMLLoader(on, id) != nil {
		t.Fatal("large main loader", err)
	}
	again, err := renderAnalyticsHTMLLoader(on, id, true)
	if err != nil || again != on {
		t.Fatal("not idempotent", err)
	}
	waf, err := renderWAFBodyLoader(on, strings.Repeat("b", 32), true)
	if err != nil || verifyAnalyticsHTMLLoader(waf, id) != nil {
		t.Fatal("independent global modules conflict", err)
	}
	off, err := renderAnalyticsHTMLLoader(on, "", false)
	if err != nil || off != original {
		t.Fatal("disable changed administrator bytes", err)
	}
	for _, bad := range []string{
		on + on, strings.Replace(on, analyticsHTMLLoaderEnd, "", 1),
		strings.Replace(on, "load_module ", "# edited\nload_module ", 1),
		"http {\n" + on + "}\n", "# unterminated comment " + on,
		"error_log \"unterminated" + on, "} \n" + on,
		"load_module /custom/ngx_http_js_module.so;\n" + on,
	} {
		if verifyAnalyticsHTMLLoader(bad, id) == nil {
			t.Fatal("invalid loader accepted")
		}
	}
	if verifyAnalyticsHTMLLoader(on, strings.Repeat("c", 32)) == nil {
		t.Fatal("other engine accepted")
	}
	for _, good := range []string{"# braces { }\n", "error_log \"quoted { and }\";\n", "events {}\n", "error_log 'escaped \\' { and }';\n"} {
		if verifyAnalyticsHTMLLoader(good+on, id) != nil {
			t.Fatal("quoted/commented braces changed context", good)
		}
	}
}

func TestAnalyticsHTMLHealthMountOwnedContextAndRemoval(t *testing.T) {
	original := "# original main\nevents {}\nhttp {\n  include /etc/nginx/sites-enabled/*;\n}\n"
	on, err := renderAnalyticsHTMLHealthMount(original, true)
	if err != nil || strings.Count(on, analyticsHTMLHealthInclude) != 1 {
		t.Fatal(on, err)
	}
	again, err := renderAnalyticsHTMLHealthMount(on, true)
	if err != nil || again != on {
		t.Fatal("not idempotent", err)
	}
	off, err := renderAnalyticsHTMLHealthMount(on, false)
	if err != nil || off != original {
		t.Fatal("original administrator text changed", err)
	}
	for _, bad := range []string{on + on, strings.Replace(on, analyticsHTMLHealthEnd, "", 1), strings.Replace(on, analyticsHTMLHealthInclude, "  include /arbitrary.conf;\n", 1), "# http {\n}\n", "http {\nserver {\n" + analyticsHTMLHealthBegin + analyticsHTMLHealthInclude + analyticsHTMLHealthEnd + "}\n}\n", "include /etc/panel/analytics-html/health.conf;\n" + original} {
		if _, err := renderAnalyticsHTMLHealthMount(bad, true); err == nil {
			t.Fatal("unowned/nested mount accepted")
		}
	}
	configuration, err := analyticsHTMLHealthConfiguration(strings.Repeat("a", 32))
	if err != nil || !strings.Contains(configuration, "listen unix:"+analyticsHTMLHealthSocket) || strings.Contains(configuration, "listen 0.0.0.0") || !strings.Contains(configuration, "js_content analytics_html.health;") {
		t.Fatal("health not actual/private", err)
	}
}
