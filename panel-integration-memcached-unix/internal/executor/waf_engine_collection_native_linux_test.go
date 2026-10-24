//go:build linux

package executor

import (
	"os"
	"testing"
)

func TestNginxWAFCompilerNativeCollectionRetainsStableReapingWitness(t *testing.T) {
	if os.Getenv("PANEL_QA_NGINX_WAF_COLLECTION_NATIVE") != "1" {
		t.Skip("explicit private dedicated Nginx compiler service required")
	}
	nativeCompilerCollectionFixtureKind(t, nativeNginxWAFCompilerAuthority)
}

func TestAnalyticsHTMLCompilerNativeCollectionRetainsStableReapingWitness(t *testing.T) {
	if os.Getenv("PANEL_QA_ANALYTICS_HTML_COLLECTION_NATIVE") != "1" {
		t.Skip("explicit private dedicated Analytics HTML compiler service required")
	}
	nativeCompilerCollectionFixtureKind(t, nativeAnalyticsHTMLCompilerAuthority)
}
