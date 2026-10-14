//go:build linux

package core

import (
	"context"
	"encoding/json"
	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"runtime"
	"testing"
)

// Actual status-builder/HTTP decoder fixtures, not installed update evidence.
func TestDiskUsageRegistryStatusDistinguishesLegacyLatestAndMissingVersions(t *testing.T) {
	item := appcatalog.CatalogItem{ID: "disk-analysis", Version: DiskAnalysisAppVersion, Provider: "panel-module", Target: "disk-analysis", Stage: "ready"}
	for _, version := range []string{"1.0", "1.2.0", DiskAnalysisAppVersion, ""} {
		t.Run(version, func(t *testing.T) {
			executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/runtimes":
					json.NewEncoder(w).Encode(map[string]any{"installed": []any{}})
				case "/v1/software":
					json.NewEncoder(w).Encode([]SoftwareAppStatus{{ID: "disk-analysis", Installed: true, Healthy: true, Version: version}})
				case "/v1/docker/projects":
					json.NewEncoder(w).Encode(map[string]any{"projects": []any{}})
				default:
					t.Errorf("unexpected fixture probe: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			a := &Server{Store: testStore(t), Executor: executor}
			rows := a.appRegistryStatuses(context.Background(), appcatalog.Catalog{Apps: []appcatalog.CatalogItem{item}})
			if len(rows) != 1 || !rows[0].Installed || !rows[0].StateKnown || rows[0].InstalledVersion != version {
				t.Fatal("actual software version probe lost or replaced", rows)
			}
			row := rows[0]
			wantUpdate := version == "1.0" || version == "1.2.0"
			if row.UpdateAvailable != wantUpdate || row.VersionKnown != (version != "") {
				t.Fatal("legacy, latest and missing versions conflated", row)
			}
			supported, _ := registrySupportOn(item, runtimecatalog.HostPlatform(), runtime.GOARCH)
			if row.UpdateSupported != (wantUpdate && supported) {
				t.Fatal("real implemented update availability was blocked or fabricated", row)
			}
			if wantUpdate && supported && row.UpdateKind != "module" {
				t.Fatal("genuine1.3 handler was still advertised as requiring another panel upgrade", row)
			}
		})
	}
}

func TestDiskUsageRegistryPlatformGateKeepsFixedVersionAndArchitectureBoundaries(t *testing.T) {
	item := appcatalog.CatalogItem{ID: "disk-analysis", Version: DiskAnalysisAppVersion, Provider: "panel-module", Target: "disk-analysis", Stage: "ready"}
	for _, osName := range []string{"debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"} {
		for _, arch := range []string{"amd64", "arm64"} {
			if ok, reason := registrySupportOn(item, osName, arch); !ok {
				t.Errorf("implemented fixed version policy refused %s/%s: %s", osName, arch, reason)
			}
		}
	}
	for _, version := range []string{"1.3", "1.3.0-compat1", "1.4.0"} {
		bad := item
		bad.Version = version
		if ok, _ := registrySupportOn(bad, "debian-13", "amd64"); ok {
			t.Errorf("unimplemented registry alias accepted: %s", version)
		}
	}
	for _, target := range [][2]string{{"darwin-26", "arm64"}, {"debian-13", "386"}, {"ubuntu-20.04", "amd64"}} {
		if ok, _ := registrySupportOn(item, target[0], target[1]); ok {
			t.Errorf("unsupported platform accepted: %v", target)
		}
	}
}
