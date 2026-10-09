//go:build linux

package executor

import (
	"context"
	"net/url"
	"path/filepath"
	"testing"
)

func TestAnalyticsHTMLSourceTLSAndRedirectBoundaries(t *testing.T) {
	sources, _ := analyticsHTMLSources("1.24.0")
	for _, source := range sources {
		u, _ := url.Parse(source.URL)
		if !analyticsHTMLSourceRedirectAllowed(u, 0) {
			t.Fatal("official fixed source denied")
		}
	}
	for _, raw := range []string{"http://nginx.org/download/nginx-1.24.0.tar.gz", "https://nginx.org:443/download/nginx-1.24.0.tar.gz", "https://user:secret@github.com/nginx/njs/releases/download/1.0.1/njs-1.0.1.tar.gz", "https://codeload.github.com/bellard/quickjs/tar.gz/main", "https://github.com/evil/njs/releases/download/1.0.1/njs-1.0.1.tar.gz", "https://nginx.org.evil.invalid/download/nginx-1.24.0.tar.gz", "https://codeload.github.com/bellard/quickjs/tar.gz/535a7c250ff4a577ec36c3e103daab6dadeea650?override=1"} {
		u, _ := url.Parse(raw)
		if analyticsHTMLSourceRedirectAllowed(u, 0) {
			t.Fatal("unreviewed redirect accepted")
		}
	}
	u, _ := url.Parse(sources[0].URL)
	if analyticsHTMLSourceRedirectAllowed(u, 4) {
		t.Fatal("unbounded redirects")
	}
	bad := sources[0]
	bad.URL = "https://127.0.0.1/arbitrary"
	if err := downloadAnalyticsHTMLSource(context.Background(), bad, filepath.Join(t.TempDir(), "archive")); err == nil {
		t.Fatal("unreviewed URL reached transport")
	}
}
