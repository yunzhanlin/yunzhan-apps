//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func moduleTestBind(t *testing.T, source, target string) {
	t.Helper()
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("requires a Linux mount-capable test host")
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(target, 0); err != nil {
			t.Error(err)
		}
	})
}

func TestAppModuleFilesRejectNestedBindMounts(t *testing.T) {
	svc, site, target := appReliabilityFixture(t)
	ctx := context.Background()
	public := filepath.Join(svc.Config.SitesDir, site, "public")
	external := t.TempDir()
	externalFile := filepath.Join(external, "secret.php")
	nested := filepath.Join(public, "mounted")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(externalFile, []byte("<?php eval('external secret');"), 0600); err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, svc, site, "index.php", "<?php echo 'owned';")
	fixtureWrite(t, svc, site, "file.php", "<?php echo 'ordinary';")
	in := core.AppModuleInput{SiteID: site, AutoRestore: true, Realtime: true}
	if _, err := svc.moduleIntegrity(ctx, "enterprise-tamper-proof", "baseline", in); err != nil {
		t.Fatal(err)
	}
	baseline := filepath.Join(svc.moduleDir("enterprise-tamper-proof"), "baselines", site, "baseline.json")
	before, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatal(err)
	}
	moduleTestBind(t, external, nested)
	moduleTestBind(t, externalFile, filepath.Join(public, "file.php"))
	var a, b unix.Stat_t
	if err := unix.Stat(public, &a); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(nested, &b); err != nil || a.Dev != b.Dev {
		t.Fatalf("native fixture must cover a same-device bind: %v", err)
	}
	f, err := svc.openFiles(site)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, path := range []string{"file.php", "mounted/secret.php", "mounted/sub/written.php"} {
		if _, err := readModuleFile(f, path); !errors.Is(err, unix.EXDEV) {
			t.Fatalf("guarded read of %s: %v", path, err)
		}
		if err := moduleWriteSiteFile(f, path, []byte("changed"), 0644); !errors.Is(err, unix.EXDEV) {
			t.Fatalf("guarded write of %s: %v", path, err)
		}
	}
	if _, err := svc.moduleIntegrity(ctx, "enterprise-tamper-proof", "check", in); !errors.Is(err, unix.EXDEV) {
		t.Fatalf("mixed tree accepted for automatic restore: %v", err)
	}
	if _, err := svc.moduleIntegrity(ctx, "enterprise-tamper-proof", "baseline", in); !errors.Is(err, unix.EXDEV) {
		t.Fatalf("mixed tree replaced baseline: %v", err)
	}
	if raw, err := os.ReadFile(baseline); err != nil || string(raw) != string(before) {
		t.Fatal("mount refusal changed the original signed baseline", err)
	}
	if _, err := svc.modulePHPScan(ctx, site); !errors.Is(err, unix.EXDEV) {
		t.Fatalf("PHP scan followed mounted files: %v", err)
	}
	if _, err := svc.moduleSync(ctx, core.AppModuleInput{SiteID: site, TargetSiteID: target}, false); !errors.Is(err, unix.EXDEV) {
		t.Fatalf("sync accepted mounted source: %v", err)
	}
	if _, err := svc.moduleSync(ctx, core.AppModuleInput{SiteID: target, TargetSiteID: site}, false); !errors.Is(err, unix.EXDEV) {
		t.Fatalf("sync accepted mounted destination: %v", err)
	}
	w := realtimeManualWatcher(t, svc, 4096)
	state := &integrityWatchSite{Watches: map[int]bool{}}
	w.Sites[site] = state
	if err := w.watchTree(ctx, site, state, f); !errors.Is(err, unix.EXDEV) || len(state.Watches) != 1 {
		t.Fatalf("realtime watcher crossed a mount or missed the owned root: %v, %d", err, len(state.Watches))
	}
	safe := core.AppModuleInput{SiteID: site, TargetSiteID: target, Excludes: []string{"mounted", "file.php"}}
	if _, err := svc.moduleSync(ctx, safe, false); err != nil || fixtureRead(t, svc, target, "index.php") != "<?php echo 'owned';" {
		t.Fatal("explicit exclusions should allow owned files to sync", err)
	}
	for _, path := range []string{filepath.Join(external, "sub"), filepath.Join(svc.Config.SitesDir, target, "public", "file.php")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unexpected external or copied entry", path, err)
		}
	}
	if raw, err := os.ReadFile(externalFile); err != nil || !strings.Contains(string(raw), "external secret") {
		t.Fatal("original external bytes lost", err)
	}
}

func TestAppModuleFilesDedicatedPublicMountRemainsUsable(t *testing.T) {
	svc, id, _ := appReliabilityFixture(t)
	public := filepath.Join(svc.Config.SitesDir, id, "public")
	owned := t.TempDir()
	moduleTestBind(t, owned, public)
	f, err := svc.openFiles(id)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := moduleWriteSiteFile(f, "sub/owned.php", []byte("local site data"), 0600); err != nil {
		t.Fatal(err)
	}
	result, partial, err := scanModuleFiles(context.Background(), f, nil, nil)
	if err != nil || partial || len(result) != 1 || result["sub/owned.php"].SHA != core.Hash("local site data") {
		t.Fatalf("dedicated public mount rejected: %v, %t, %v", result, partial, err)
	}
}
