package executor

import (
	"reflect"
	"testing"
)

func apacheCCRotationFixtureRecord() apacheBodyBuildRecord {
	v := apacheCCFixtureRecord()
	v.Format, v.CCEngine = 3, apacheCCRotationEngineVersion
	v.AssetSHA = apacheBodyReleaseAssetPinsForFormat(3)
	plan, _ := apacheBodyBuildPlanForFormat(apacheBodyPaths(v.JobID), 3)
	v.CompletedBuildSteps[len(v.CompletedBuildSteps)-1] = plan[len(plan)-1].Label
	v.Steps[len(v.Steps)-1].Message = plan[len(plan)-1].Label
	return v
}

func TestApacheCCRotationRecordKeepsOriginalFormatsAndRequiresIndependentEvidence(t *testing.T) {
	for _, v := range []apacheBodyBuildRecord{apacheBodyFixtureRecord(), apacheCCFixtureRecord(), apacheCCRotationFixtureRecord()} {
		if err := apacheBodyRecordContract(v); err != nil {
			t.Fatalf("format %d: %v", v.Format, err)
		}
	}
	for name, mutate := range map[string]func(*apacheBodyBuildRecord){
		"old-engine": func(v *apacheBodyBuildRecord) { v.CCEngine = apacheCCEngineVersion },
		"old-format": func(v *apacheBodyBuildRecord) { v.Format = 2 },
		"old-resources": func(v *apacheBodyBuildRecord) {
			v.AssetSHA = apacheBodyReleaseAssetPinsForFormat(2)
		},
		"old-completed-compiler-step": func(v *apacheBodyBuildRecord) {
			old := apacheCCFixtureRecord()
			v.CompletedBuildSteps = old.CompletedBuildSteps
		},
		"missing-independent-ABI": func(v *apacheBodyBuildRecord) { v.CCABIValidated = false },
		"missing-writer-proof": func(v *apacheBodyBuildRecord) {
			delete(v.AssetSHA, "apache-cc-log-v2.h")
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := apacheCCRotationFixtureRecord()
			mutate(&v)
			if apacheBodyRecordContract(v) == nil {
				t.Fatal("mixed or incomplete rotation identity accepted")
			}
		})
	}
	old := apacheCCFixtureRecord()
	old.Format, old.CCEngine = 3, apacheCCRotationEngineVersion
	if apacheBodyRecordContract(old) == nil {
		t.Fatal("old sealed record relabelled as a safe rotation writer")
	}
}

func TestApacheCCRotationBuildAuthorityCannotCrossFormats(t *testing.T) {
	paths := apacheBodyPaths(apacheCCFixtureRecord().JobID)
	old, err := apacheBodyBuildPlanForFormat(paths, 2)
	if err != nil {
		t.Fatal(err)
	}
	next, err := apacheBodyBuildPlanForFormat(paths, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(old[:len(old)-1], next[:len(next)-1]) {
		t.Fatal("rotation changed the original body-only compiler steps")
	}
	last := len(next) - 1
	if validateApacheBodyCCBuildCommandForFormat(paths, 3, last, next[last]) != nil ||
		validateApacheBodyCCBuildCommandForFormat(paths, 2, last, next[last]) == nil ||
		validateApacheBodyCCBuildCommandForFormat(paths, 3, last, old[last]) == nil {
		t.Fatal("compiler authority crossed the original and rotation-safe identities")
	}
	for name := range apacheCCRotationAssetPins() {
		if b, err := verifiedApacheCCAsset(name); err != nil || len(b) == 0 {
			t.Fatal("missing pinned rotation source", name, err)
		}
	}
	if apacheCCEngineForFormat(4) != "" || apacheCCFormatHasModule(4) {
		t.Fatal("future format acquired current authority")
	}
}
