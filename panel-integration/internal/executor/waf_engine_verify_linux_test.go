//go:build linux

package executor

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func wafFixtureReadyRecord() wafEngineBuildRecord {
	id := core.ID()
	nginx, _ := wafNginxBuildSource("1.24.0")
	sourceSHA := map[string]string{}
	for _, source := range append(wafEngineSources(), nginx) {
		sourceSHA[source.Name] = source.SHA256
	}
	return wafEngineBuildRecord{Format: 1, JobID: id, State: "ready", Architecture: runtime.GOARCH, Engine: wafBodyEngineVersion, Connector: wafBodyConnectorVersion, CRS: wafBodyCRSVersion, NginxVersion: "1.24.0", NginxBinary: "/usr/sbin/nginx", NginxSHA: strings.Repeat("a", 64), ModuleSHA: strings.Repeat("b", 64), LibrarySHA: strings.Repeat("c", 64), TreeSHA: strings.Repeat("d", 64), Prefix: filepath.Join(wafNativeEngines, id), SourceSHA: sourceSHA, AssetSHA: wafEngineAssetPins(), StartedAt: "2026-10-07T00:00:00Z", FinishedAt: "2026-10-07T01:00:00Z", ABIValidated: true, Steps: []core.Step{{Time: "2026-10-07T01:00:00Z", Message: "built without site activation"}}}
}

func TestWAFReadyRecordBindsCompleteSourceProgramAndNginxIdentity(t *testing.T) {
	if err := wafBuildRecordContract(wafFixtureReadyRecord()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*wafEngineBuildRecord){
		"job":                func(v *wafEngineBuildRecord) { v.JobID = "../evil" },
		"format":             func(v *wafEngineBuildRecord) { v.Format = 2 },
		"failed":             func(v *wafEngineBuildRecord) { v.State = "failed" },
		"partial":            func(v *wafEngineBuildRecord) { v.State = "building" },
		"error":              func(v *wafEngineBuildRecord) { v.Error = "build failed" },
		"not-abi-tested":     func(v *wafEngineBuildRecord) { v.ABIValidated = false },
		"wrong-architecture": func(v *wafEngineBuildRecord) { v.Architecture = "other" },
		"engine":             func(v *wafEngineBuildRecord) { v.Engine = "unpatched" },
		"connector":          func(v *wafEngineBuildRecord) { v.Connector = "unpatched" },
		"crs":                func(v *wafEngineBuildRecord) { v.CRS = "main" },
		"program-path":       func(v *wafEngineBuildRecord) { v.Prefix = "/tmp/arbitrary" },
		"nginx-path":         func(v *wafEngineBuildRecord) { v.NginxBinary = "/usr/bin/env" },
		"nginx-version":      func(v *wafEngineBuildRecord) { v.NginxVersion = "unknown" },
		"missing-source":     func(v *wafEngineBuildRecord) { delete(v.SourceSHA, "modsecurity") },
		"extra-source":       func(v *wafEngineBuildRecord) { v.SourceSHA["remote-plugin"] = "arbitrary" },
		"wrong-source":       func(v *wafEngineBuildRecord) { v.SourceSHA["modsecurity"] = strings.Repeat("0", 64) },
		"missing-license":    func(v *wafEngineBuildRecord) { delete(v.AssetSHA, "modsecurity-libinjection-COPYING") },
		"altered-patch": func(v *wafEngineBuildRecord) {
			v.AssetSHA["modsecurity-metadata-only-logs.patch"] = strings.Repeat("0", 64)
		},
		"missing-digest":  func(v *wafEngineBuildRecord) { v.TreeSHA = "" },
		"upper-digest":    func(v *wafEngineBuildRecord) { v.ModuleSHA = strings.Repeat("B", 64) },
		"unfinished":      func(v *wafEngineBuildRecord) { v.FinishedAt = "" },
		"wrong-time":      func(v *wafEngineBuildRecord) { v.FinishedAt = "2026-10-06T00:00:00Z" },
		"no-audit":        func(v *wafEngineBuildRecord) { v.Steps = nil },
		"unbounded-audit": func(v *wafEngineBuildRecord) { v.Steps = make([]core.Step, 33) },
	} {
		t.Run(name, func(t *testing.T) {
			v := wafFixtureReadyRecord()
			mutate(&v)
			if err := wafBuildRecordContract(v); err == nil {
				t.Fatal("invalid ready record trusted")
			}
		})
	}
	s := nativeWAFService()
	if s.Config.SitesDir != "/srv/panel/sites" || s.Config.NginxBin != "/usr/sbin/nginx" || s.Config.SystemRoot != "/" {
		t.Fatal("worker omitted real Nginx-selection paths")
	}
}
