package executor

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func apacheCCFixtureRecord() apacheBodyBuildRecord {
	v := apacheBodyFixtureRecord()
	v.Format, v.CCEngine, v.CCModuleSHA, v.CCABIValidated = 2, apacheCCEngineVersion, strings.Repeat("d", 64), true
	v.AssetSHA = apacheBodyReleaseAssetPinsForFormat(2)
	plan, _ := apacheBodyBuildPlanForFormat(apacheBodyPaths(v.JobID), 2)
	v.CompletedBuildSteps = append(v.CompletedBuildSteps, plan[len(plan)-1].Label)
	v.Steps = append(v.Steps, core.Step{Time: "2026-10-11T00:30:00Z", Message: plan[len(plan)-1].Label})
	return v
}

func TestApacheCCReadyRecordCannotAdoptOldOrPartialAuthority(t *testing.T) {
	if err := apacheBodyRecordContract(apacheBodyFixtureRecord()); err != nil {
		t.Fatal("unchanged body-only authority", err)
	}
	if err := apacheBodyRecordContract(apacheCCFixtureRecord()); err != nil {
		t.Fatal("complete native CC authority", err)
	}
	mutations := map[string]func(*apacheBodyBuildRecord){
		"body-only-format-with-CC-fields": func(v *apacheBodyBuildRecord) { v.Format = 1 },
		"format3-cannot-adopt-format2":    func(v *apacheBodyBuildRecord) { v.Format = 3 },
		"missing-engine":                  func(v *apacheBodyBuildRecord) { v.CCEngine = "" },
		"different-engine":                func(v *apacheBodyBuildRecord) { v.CCEngine = "1.1.0" },
		"missing-ABI":                     func(v *apacheBodyBuildRecord) { v.CCABIValidated = false },
		"missing-module":                  func(v *apacheBodyBuildRecord) { v.CCModuleSHA = "" },
		"extra-source":                    func(v *apacheBodyBuildRecord) { v.SourceSHA["other"] = strings.Repeat("a", 64) },
		"missing-CC-source":               func(v *apacheBodyBuildRecord) { delete(v.AssetSHA, "apache-cc-module.c") },
		"changed-core-source":             func(v *apacheBodyBuildRecord) { v.AssetSHA["apache-cc-core.h"] = strings.Repeat("a", 64) },
		"missing-CC-license":              func(v *apacheBodyBuildRecord) { delete(v.AssetSHA, "apache-cc-LICENSE") },
		"missing-last-build-step": func(v *apacheBodyBuildRecord) {
			v.CompletedBuildSteps = v.CompletedBuildSteps[:len(v.CompletedBuildSteps)-1]
		},
		"historical-cgroup-witness": func(v *apacheBodyBuildRecord) { v.CompilerCollection = "dedicated_cgroup_v2_pidfd_reaped_v1" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v := apacheCCFixtureRecord()
			mutate(&v)
			if apacheBodyRecordContract(v) == nil {
				t.Fatal("incomplete CC authority accepted")
			}
		})
	}
	v := apacheCCFixtureRecord()
	v.CompilerCollection = ""
	if apacheBodyRetainedRecordContract(v) == nil {
		t.Fatal("CC record borrowed an older inspection contract")
	}
}

func TestApacheCCSealedSourceAndClosedCompilerPlan(t *testing.T) {
	for name := range apacheCCAssetPins() {
		b, err := verifiedApacheCCAsset(name)
		if err != nil || len(b) == 0 {
			t.Fatal(name, err)
		}
	}
	if _, err := verifiedApacheCCAsset("../../caller.c"); err == nil {
		t.Fatal("unreviewed source accepted")
	}
	paths := apacheBodyPaths(strings.Repeat("a", 32))
	old, err := apacheBodyNativeBuildPlan(paths)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := apacheBodyBuildPlanForFormat(paths, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != len(old)+1 || !reflect.DeepEqual(plan[:len(old)], old) {
		t.Fatal("CC changed an original body-only compiler step")
	}
	for i, c := range plan {
		if err := validateApacheBodyCCBuildCommand(paths, i, c); err != nil {
			t.Fatal(err)
		}
	}
	last := plan[len(plan)-1]
	last.Arguments = append(append([]string{}, last.Arguments...), "-Wl,-rpath,/tmp/caller")
	if validateApacheBodyCCBuildCommand(paths, len(plan)-1, last) == nil {
		t.Fatal("caller linker flags accepted")
	}
	if validateApacheBodyBuildCommand(paths, len(old), plan[len(plan)-1]) == nil {
		t.Fatal("body-only plan authorized CC by label")
	}
	module, err := os.ReadFile("assets/apache-cc-module.c")
	if err != nil || !strings.Contains(string(module), `#define YZ_CC_ENGINE "`+apacheCCEngineVersion+`"`) {
		t.Fatal("native module identity differs from ready-record authority")
	}
}
