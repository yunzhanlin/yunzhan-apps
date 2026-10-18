package executor

import "testing"

func TestAnalyticsHTMLSourcesAreFixedAndSeparateFromWAF(t *testing.T) {
	sources, ok := analyticsHTMLSources("1.24.0")
	if !ok || len(sources) != 3 {
		t.Fatal("fixed sources missing")
	}
	for _, source := range sources {
		if !reviewedAnalyticsHTMLSource(source) {
			t.Fatal("fixed source rejected")
		}
		if source.Name != "nginx-build" && reviewedWAFEngineSource(source) {
			t.Fatal("analytics expanded WAF source authority")
		}
		for _, changed := range []wafEngineSource{
			{source.Name, source.Version, "https://evil.invalid/source", source.SHA256, source.Verification},
			{source.Name, source.Version, source.URL, "0000000000000000000000000000000000000000000000000000000000000000", source.Verification},
			{source.Name, "latest", source.URL, source.SHA256, source.Verification},
		} {
			if reviewedAnalyticsHTMLSource(changed) {
				t.Fatal("unreviewed source granted download authority")
			}
		}
	}
	for _, version := range []string{"1.18.0", "latest", "1.24.0;evil"} {
		if _, ok := analyticsHTMLSources(version); ok {
			t.Fatal("unreviewed binary version accepted")
		}
	}
}
