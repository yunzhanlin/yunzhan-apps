package core

import (
	"local/panel/internal/appcatalog"
	"testing"
)

func TestRegistryCompatibilityMatrix(t *testing.T) {
	for _, platform := range []string{"debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"} {
		for _, arch := range []string{"amd64", "arm64"} {
			for _, app := range []appcatalog.CatalogItem{
				{Stage: "ready", Provider: "runtime", Target: "docker-auto"},
				{Stage: "ready", Provider: "runtime", Target: "php-8.4.25"},
				{Stage: "ready", Provider: "panel-module", Target: "task-manager"},
				{Stage: "ready", Provider: "compose", Target: "memcached-cache"},
			} {
				if ok, why := registrySupportOn(app, platform, arch); !ok {
					t.Fatalf("%s/%s/%s: %s", platform, arch, app.Target, why)
				}
			}
			app := appcatalog.CatalogItem{Stage: "ready", Provider: "compose", Target: "php-legacy-74"}
			if ok, _ := registrySupportOn(app, platform, arch); ok != (arch == "amd64") {
				t.Fatalf("legacy PHP must not use implicit ARM emulation")
			}
		}
	}
	if ok, _ := registrySupportOn(appcatalog.CatalogItem{Stage: "ready", Provider: "panel-module", Target: "task-manager"}, "", "amd64"); ok {
		t.Fatal("unreviewed OS accepted")
	}
	manifest := appcatalog.Manifest{Compatibility: appcatalog.Compatibility{OS: []string{"ubuntu-24.04", "debian-13"}, Architectures: []string{"arm64"}}}
	if err := appCompatibleOn(manifest, "ubuntu-24.04", "arm64"); err != nil {
		t.Fatal(err)
	}
	if err := appCompatibleOn(manifest, "ubuntu-24.04", "amd64"); err == nil {
		t.Fatal("signed architecture restriction bypassed")
	}
	if err := appCompatibleOn(manifest, "ubuntu-22.04", "arm64"); err == nil {
		t.Fatal("signed OS restriction bypassed")
	}
}

func TestRegistryIntrusion111UsesPublishedSignedOSScope(t *testing.T) {
	item := appcatalog.CatalogItem{
		ID: "anti-intrusion", Target: "intrusion-prevention", Provider: "panel-module", Stage: "ready",
		Version: "1.1.1", SHA256: "6d612505ac72ec97fdafdbc0eb8dae999df296e5203bb47058f799dd2aa6f01e",
	}
	manifest := appcatalog.Manifest{
		Compatibility: appcatalog.Compatibility{
			OS:            []string{"debian-13", "ubuntu-22.04", "ubuntu-24.04"},
			Architectures: []string{"amd64", "arm64"},
		},
	}
	for _, platform := range []string{"debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"} {
		for _, arch := range []string{"amd64", "arm64"} {
			want := appCompatibleOn(manifest, platform, arch) == nil
			ok, detail := registrySupportOn(item, platform, arch)
			if ok != want || !want && detail == "" {
				t.Fatalf("%s/%s: catalogue support=%t detail=%q, signed support=%t", platform, arch, ok, detail, want)
			}
		}
	}
}

func TestRegistryNginxWAF260UsesPublishedSignedOSScope(t *testing.T) {
	item := appcatalog.CatalogItem{
		ID: "nginx-waf", Target: "nginx-waf", Provider: "panel-module", Stage: "ready",
		Version: "2.6.0", SHA256: "465bd0775b41e8d7dd8d02de9497294a815a7467e919786fcae719791314c9f2",
	}
	manifest := appcatalog.Manifest{
		Compatibility: appcatalog.Compatibility{
			OS:            []string{"debian-13", "ubuntu-24.04"},
			Architectures: []string{"amd64", "arm64"},
		},
	}
	for _, platform := range []string{"debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"} {
		for _, arch := range []string{"amd64", "arm64"} {
			want := appCompatibleOn(manifest, platform, arch) == nil
			ok, detail := registrySupportOn(item, platform, arch)
			if ok != want || !want && detail == "" {
				t.Fatalf("%s/%s: catalogue support=%t detail=%q, signed support=%t", platform, arch, ok, detail, want)
			}
		}
	}
}
