//go:build linux

package executor

import (
	"context"
	"local/panel/internal/runtimecatalog"
	"testing"
)

func TestPHPSecuritySourceGuardDeniesAffectedAndAlteredDownloadsBeforeNetwork(t *testing.T) {
	for _, r := range runtimecatalog.PHP {
		calls := 0
		e := downloadRuntimeSourceWith(context.Background(), r, "must-not-create", func(context.Context, string, string, string, sourceDownloadLimits) error { calls++; return nil })
		if e == nil || calls != 0 {
			t.Fatal(r.ID, e, calls)
		}
	}
	for _, r := range runtimecatalog.PHPSecurity20261021 {
		calls := 0
		e := downloadRuntimeSourceWith(context.Background(), r, "no-file-in-model", func(_ context.Context, url, digest, dst string, _ sourceDownloadLimits) error {
			calls++
			if url != r.URL || digest != r.SHA256 {
				t.Fatal("source replaced")
			}
			return nil
		})
		if e != nil || calls != 1 {
			t.Fatal(r.ID, e, calls)
		}
		r.URL = "https://example.invalid/source.tar.gz"
		e = downloadRuntimeSourceWith(context.Background(), r, "must-not-create", func(context.Context, string, string, string, sourceDownloadLimits) error { calls++; return nil })
		if e == nil || calls != 1 {
			t.Fatal("identity bypass", e, calls)
		}
	}
}
