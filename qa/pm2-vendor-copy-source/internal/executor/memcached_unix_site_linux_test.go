//go:build linux

package executor

import (
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestMemcachedUnixSiteOwnershipNeedsExactRootPHPIdentityNotNameOrLabel(t *testing.T) {
	site := core.Site{ID: strings.Repeat("a", 32), PHPVersionID: "php-8.4.27", Status: "running"}
	site.RuntimeInstanceID = core.PHPInstanceID(site)
	if !memcachedUnixSiteBindingMatches(site, site) {
		t.Fatal("exact installed PHP identity refused")
	}
	for _, change := range []struct {
		name  string
		apply func(*core.Site)
	}{
		{"different-full-id", func(s *core.Site) { s.ID = strings.Repeat("a", 24) + strings.Repeat("b", 8) }},
		{"archived", func(s *core.Site) { s.Status = "archived" }},
		{"provisioning", func(s *core.Site) { s.Status = "provisioning" }},
		{"static", func(s *core.Site) { s.PHPVersionID = "" }},
		{"foreign-release", func(s *core.Site) { s.PHPVersionID = "php-8.3.36" }},
		{"foreign-instance", func(s *core.Site) { s.RuntimeInstanceID = "foreign" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			current := site
			change.apply(&current)
			if memcachedUnixSiteBindingMatches(site, current) {
				t.Fatal("borrowed Root site account ownership")
			}
		})
	}
	stopped := site
	stopped.Status = "stopped"
	if !memcachedUnixSiteBindingMatches(site, stopped) {
		t.Fatal("explicit stopped website lost its still-owned account")
	}
}
