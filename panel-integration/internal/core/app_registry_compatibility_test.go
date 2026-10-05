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
