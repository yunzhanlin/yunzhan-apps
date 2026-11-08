package executor

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func apacheBodyFixtureRecord() apacheBodyBuildRecord {
	id := core.ID()
	sources := map[string]string{}
	for _, source := range apacheBodyReleaseSources() {
		sources[source.Name] = source.SHA256
	}
	labels := []string{}
	steps := []core.Step{}
	plan, _ := apacheBodyNativeBuildPlan(apacheBodyPaths(id))
	for _, command := range plan {
		labels = append(labels, command.Label)
		steps = append(steps, core.Step{Time: "2026-10-11T00:30:00Z", Message: command.Label})
	}
	return apacheBodyBuildRecord{Format: 1, JobID: id, State: "ready", Architecture: runtime.GOARCH, Engine: apacheBodyEngineVersion, YAJL: apacheBodyYAJLVersion, CRS: wafBodyCRSVersion, ApacheVersion: "2.4.68", ApacheBinary: "/opt/panel/runtimes/apache/2.4.68/bin/httpd", ApacheSHA: strings.Repeat("a", 64), Prefix: filepath.Join(apacheBodyEngines, id), ModuleSHA: strings.Repeat("b", 64), TreeSHA: strings.Repeat("c", 64), SourceSHA: sources, AssetSHA: apacheBodyReleaseAssetPins(), StartedAt: "2026-10-11T00:00:00Z", FinishedAt: "2026-10-11T01:00:00Z", CompletedBuildSteps: labels, Steps: steps, ABIValidated: true, HardeningValidated: true, CompilerCollected: true, CompilerCollection: apacheBodyCompilerCollectionContract}
}

func TestApacheBodyReadyRecordClosedIndependentAuthority(t *testing.T) {
	if err := apacheBodyRecordContract(apacheBodyFixtureRecord()); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*apacheBodyBuildRecord){
		"format":         func(v *apacheBodyBuildRecord) { v.Format++ },
		"id":             func(v *apacheBodyBuildRecord) { v.JobID = "../nginx" },
		"partial":        func(v *apacheBodyBuildRecord) { v.State = "building" },
		"failed":         func(v *apacheBodyBuildRecord) { v.State = "failed" },
		"error":          func(v *apacheBodyBuildRecord) { v.Error = "incomplete" },
		"architecture":   func(v *apacheBodyBuildRecord) { v.Architecture = "other" },
		"v3-engine":      func(v *apacheBodyBuildRecord) { v.Engine = wafBodyEngineVersion },
		"system-yajl":    func(v *apacheBodyBuildRecord) { v.YAJL = "2.1.0" },
		"crs":            func(v *apacheBodyBuildRecord) { v.CRS = "latest" },
		"apache-version": func(v *apacheBodyBuildRecord) { v.ApacheVersion = "2.4.67" },
		"apache-binary":  func(v *apacheBodyBuildRecord) { v.ApacheBinary = "/usr/sbin/apache2" },
		"prefix":         func(v *apacheBodyBuildRecord) { v.Prefix = "/tmp/module" },
		"nginx-prefix": func(v *apacheBodyBuildRecord) {
			v.Prefix = filepath.Join("/opt/panel/app-modules/nginx-waf/engines", v.JobID)
		},
		"missing-program-sha": func(v *apacheBodyBuildRecord) { v.ApacheSHA = "" },
		"short-module-sha":    func(v *apacheBodyBuildRecord) { v.ModuleSHA = "a" },
		"upper-tree-sha":      func(v *apacheBodyBuildRecord) { v.TreeSHA = strings.Repeat("A", 64) },
		"nonhex-module":       func(v *apacheBodyBuildRecord) { v.ModuleSHA = strings.Repeat("z", 64) },
		"missing-source":      func(v *apacheBodyBuildRecord) { delete(v.SourceSHA, "apache-yajl") },
		"changed-source":      func(v *apacheBodyBuildRecord) { v.SourceSHA["apache-modsecurity"] = strings.Repeat("a", 64) },
		"extra-source":        func(v *apacheBodyBuildRecord) { v.SourceSHA["modsecurity-nginx"] = "caller" },
		"missing-crs-source":  func(v *apacheBodyBuildRecord) { delete(v.SourceSHA, "owasp-crs") },
		"extra-asset":         func(v *apacheBodyBuildRecord) { v.AssetSHA["plugin"] = "caller" },
		"missing-license":     func(v *apacheBodyBuildRecord) { delete(v.AssetSHA, "apache-body-libinjection-COPYING") },
		"missing-crs-license": func(v *apacheBodyBuildRecord) { delete(v.AssetSHA, "modsecurity-crs-LICENSE") },
		"changed-cve": func(v *apacheBodyBuildRecord) {
			v.AssetSHA["apache-body-yajl-CVE-2023-33460.patch"] = strings.Repeat("a", 64)
		},
		"no-build-steps":     func(v *apacheBodyBuildRecord) { v.CompletedBuildSteps = nil },
		"missing-build-step": func(v *apacheBodyBuildRecord) { v.CompletedBuildSteps = v.CompletedBuildSteps[1:] },
		"reordered-steps": func(v *apacheBodyBuildRecord) {
			v.CompletedBuildSteps[0], v.CompletedBuildSteps[1] = v.CompletedBuildSteps[1], v.CompletedBuildSteps[0]
		},
		"extra-build-step": func(v *apacheBodyBuildRecord) {
			v.CompletedBuildSteps = append(v.CompletedBuildSteps, "caller command")
		},
		"missing-start":           func(v *apacheBodyBuildRecord) { v.StartedAt = "" },
		"missing-finish":          func(v *apacheBodyBuildRecord) { v.FinishedAt = "" },
		"finish-before-start":     func(v *apacheBodyBuildRecord) { v.FinishedAt = "2026-10-10T00:00:00Z" },
		"timeout":                 func(v *apacheBodyBuildRecord) { v.FinishedAt = "2026-10-11T04:00:01Z" },
		"no-audit":                func(v *apacheBodyBuildRecord) { v.Steps = nil },
		"unbounded-audit":         func(v *apacheBodyBuildRecord) { v.Steps = make([]core.Step, 49) },
		"audit-empty":             func(v *apacheBodyBuildRecord) { v.Steps[0].Message = "" },
		"audit-long":              func(v *apacheBodyBuildRecord) { v.Steps[0].Message = strings.Repeat("a", 513) },
		"audit-nul":               func(v *apacheBodyBuildRecord) { v.Steps[0].Message += "\x00" },
		"audit-before":            func(v *apacheBodyBuildRecord) { v.Steps[0].Time = "2026-10-10T00:30:00Z" },
		"audit-after":             func(v *apacheBodyBuildRecord) { v.Steps[0].Time = "2026-10-11T01:30:00Z" },
		"audit-reordered":         func(v *apacheBodyBuildRecord) { v.Steps[1].Time = "2026-10-11T00:29:59Z" },
		"no-abi":                  func(v *apacheBodyBuildRecord) { v.ABIValidated = false },
		"no-hardening":            func(v *apacheBodyBuildRecord) { v.HardeningValidated = false },
		"compiler-alive":          func(v *apacheBodyBuildRecord) { v.CompilerCollected = false },
		"missing-collection":      func(v *apacheBodyBuildRecord) { v.CompilerCollection = "" },
		"group-only-collection":   func(v *apacheBodyBuildRecord) { v.CompilerCollection = "process_group_only" },
		"exit-only-v1-collection": func(v *apacheBodyBuildRecord) { v.CompilerCollection = "dedicated_cgroup_v2_pidfd_reaped_v1" },
		"activated":               func(v *apacheBodyBuildRecord) { v.ProductionUsed = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v := apacheBodyFixtureRecord()
			mutate(&v)
			if err := apacheBodyRecordContract(v); err == nil {
				t.Fatal("invalid ready record trusted")
			}
		})
	}
}

func TestApacheBodyReleaseIncludesEveryReviewedLicenseWithoutNginxConnector(t *testing.T) {
	if len(apacheBodyReleaseSources()) != 3 || len(apacheBodyReleaseAssetPins()) != 13 {
		t.Fatal("independent sources or complete redistribution resources changed")
	}
	for name := range apacheBodyReleaseAssetPins() {
		if _, err := verifiedApacheBodyReleaseAsset(name); err != nil {
			t.Fatal(name, err)
		}
	}
	for _, source := range apacheBodyReleaseSources() {
		if source.Name == "modsecurity-nginx" || source.Name == "modsecurity" {
			t.Fatal("v3/Nginx source admitted into Apache producer")
		}
	}
	if _, err := verifiedApacheBodyReleaseAsset("modsecurity-nginx-LICENSE"); err == nil {
		t.Fatal("unrelated asset accepted")
	}
}

func TestApacheBodyRetainedAuthorityNeverGrantsCurrentActivation(t *testing.T) {
	legacy := func() apacheBodyBuildRecord {
		v := apacheBodyFixtureRecord()
		v.Engine = "2.9.15-yz4"
		v.CompilerCollection = ""
		v.AssetSHA["apache-body-metadata-only.patch"] = "f5d505b5e281a42f23ad49c32c5c9e2c778a84b041308d06b286a6cb927623f1"
		return v
	}
	if err := apacheBodyRetainedRecordContract(legacy()); err != nil {
		t.Fatal("exact previous reviewed authority lost", err)
	}
	if apacheBodyRecordContract(legacy()) == nil || apacheBodyRetainedRecordContract(apacheBodyFixtureRecord()) == nil {
		t.Fatal("historical inspection and current activation authorities overlap")
	}
	groupOnly := apacheBodyFixtureRecord()
	groupOnly.CompilerCollection = ""
	if apacheBodyRecordContract(groupOnly) == nil || apacheBodyRetainedRecordContract(groupOnly) != nil {
		t.Fatal("previous YZ5 group-only record was promoted or discarded")
	}
	v1 := apacheBodyFixtureRecord()
	v1.CompilerCollection = "dedicated_cgroup_v2_pidfd_reaped_v1"
	if apacheBodyRecordContract(v1) == nil || apacheBodyRetainedRecordContract(v1) != nil {
		t.Fatal("pre-reap-witness YZ5 record was promoted or discarded")
	}
	v1.Engine = "2.9.15-yz4"
	if apacheBodyRetainedRecordContract(v1) == nil {
		t.Fatal("v1 contract falsely attached to YZ4")
	}
	for name, change := range map[string]func(*apacheBodyBuildRecord){
		"new-label-old-patch": func(v *apacheBodyBuildRecord) { v.Engine = apacheBodyEngineVersion },
		"older-unreviewed":    func(v *apacheBodyBuildRecord) { v.Engine = "2.9.15-yz3" },
		"new-patch-old-label": func(v *apacheBodyBuildRecord) {
			v.AssetSHA["apache-body-metadata-only.patch"] = apacheBodyReleaseAssetPins()["apache-body-metadata-only.patch"]
		},
		"wrong-runtime": func(v *apacheBodyBuildRecord) { v.ApacheVersion = "2.4.67" },
		"foreign-tree":  func(v *apacheBodyBuildRecord) { v.Prefix += "-foreign" },
		"short-sha":     func(v *apacheBodyBuildRecord) { v.TreeSHA = "a" },
		"missing-license": func(v *apacheBodyBuildRecord) {
			delete(v.AssetSHA, "apache-body-yajl-COPYING")
		},
		"changed-source": func(v *apacheBodyBuildRecord) { v.SourceSHA["apache-yajl"] = strings.Repeat("a", 64) },
		"missing-step":   func(v *apacheBodyBuildRecord) { v.CompletedBuildSteps = v.CompletedBuildSteps[1:] },
		"not-ready":      func(v *apacheBodyBuildRecord) { v.State = "building" },
		"with-error":     func(v *apacheBodyBuildRecord) { v.Error = "unfinished" },
		"no-hardening":   func(v *apacheBodyBuildRecord) { v.HardeningValidated = false },
		"compiler-live":  func(v *apacheBodyBuildRecord) { v.CompilerCollected = false },
		"no-abi":         func(v *apacheBodyBuildRecord) { v.ABIValidated = false },
		"loaded":         func(v *apacheBodyBuildRecord) { v.ProductionUsed = true },
		"audit-time":     func(v *apacheBodyBuildRecord) { v.Steps[0].Time = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			v := legacy()
			change(&v)
			if apacheBodyRetainedRecordContract(v) == nil || apacheBodyRecordContract(v) == nil {
				t.Fatal("mixed, changed or unfinished authority accepted")
			}
		})
	}
}
