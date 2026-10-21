//go:build linux

package executor

import (
	"context"
	"os"
	"testing"

	"local/panel/internal/core"
)

// The runner creates one malformed owned metadata fixture per private unit.
// Test root has panel's primary group, not permission to repair foreign state.
func TestApacheBodyMetadataRefusalPrecedesFirstCacheLeaf(t *testing.T) {
	if os.Getenv("PANEL_QA_APACHE_BODY_METADATA_REFUSAL") != "1" {
		t.Skip("explicit actual Linux private malformed metadata fixture required")
	}
	if os.Geteuid() != 0 || os.Getegid() == 0 {
		t.Fatal("confined root with panel primary group required")
	}
	before, err := verifyApacheBodyCacheQuota()
	if err != nil || before.AvailableBytes != apacheBodyCacheBytes || before.AvailableNodes != apacheBodyCacheInodes-1 {
		t.Fatal("actual fresh secure hard-limit cache required", before, err)
	}
	policy := core.DefaultWAFBodyPolicy()
	policy.Mode = "block"
	cfg := core.DefaultApacheWAFConfig()
	cfg.Body = &core.WAFBodyConfig{EngineJobID: apacheBodyConfigEngine, Sites: []core.WAFBodySitePolicy{{SiteID: apacheBodyConfigSiteA, Policy: policy}}}
	s := New(Config{SystemRoot: "/", SitesDir: "/srv/panel/sites"})
	if err := s.prepareApacheBodyStorage(context.Background(), cfg); err == nil {
		t.Fatal("foreign event directory or log was accepted")
	}
	entries, err := os.ReadDir(apacheBodyTemporary)
	if err != nil || len(entries) != 0 {
		t.Fatal("metadata refusal happened after creating cache leaves", err, len(entries))
	}
	after, err := verifyApacheBodyCacheQuota()
	if err != nil || before != after {
		t.Fatal("metadata refusal changed cache capacity/state", before, after, err)
	}
}
