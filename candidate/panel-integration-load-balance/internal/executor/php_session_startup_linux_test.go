//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"slices"
	"testing"
)

func TestPHPStartupProtectionAppliesWithUnsetAndConfiguredSettings(t *testing.T) {
	settings := core.DefaultPHPSettings()
	for _, release := range runtimecatalog.PHPReleases() {
		for _, options := range []*core.PHPSettings{nil, &settings} {
			args, err := phpExtensionArgs(context.Background(), release, options)
			if err != nil || !slices.Equal(args, []string{"-d", "session.upload_progress.enabled=0"}) {
				t.Fatalf("%s startup args with settings %#v: %q, %v", release.ID, options, args, err)
			}
		}
	}
	invalid := core.DefaultPHPSettings()
	invalid.MemoryMB = -1
	if args, err := phpExtensionArgs(context.Background(), runtimecatalog.PHP[0], &invalid); err == nil || args != nil {
		t.Fatalf("startup policy bypassed invalid settings: %q %v", args, err)
	}
	args, err := phpExtensionArgs(context.Background(), runtimecatalog.Release{Family: "php", Version: "5.2.17"}, nil)
	if err != nil || len(args) != 0 {
		t.Fatalf("unsupported legacy runtime received unverified ini args: %q %v", args, err)
	}
}
