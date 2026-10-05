//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func appReliabilityFixture(t *testing.T) (*Service, string, string) {
	t.Helper()
	base := t.TempDir()
	svc := New(Config{SitesDir: filepath.Join(base, "sites"), SecurityDir: filepath.Join(base, "security")})
	ids := []string{core.ID(), core.ID()}
	for _, id := range ids {
		dir := filepath.Join(svc.Config.SitesDir, id)
		if err := os.MkdirAll(filepath.Join(dir, "public"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".panel-site.json"), []byte(`{"id":"`+id+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"files-sync", "file-monitor", "website-tamper-proof", "enterprise-tamper-proof"} {
		if err := moduleWrite(filepath.Join(svc.moduleDir(id), "installed.json"), map[string]string{"id": id}); err != nil {
			t.Fatal(err)
		}
	}
	return svc, ids[0], ids[1]
}
func fixtureWrite(t *testing.T, s *Service, site, path, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(s.Config.SitesDir, site, "public", path), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
func fixtureRead(t *testing.T, s *Service, site, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.Config.SitesDir, site, "public", path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAppReliabilityWriteGuardsKeepChangedTargets(t *testing.T) {
	svc, source, _ := appReliabilityFixture(t)
	f, err := svc.openFiles(source)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fixtureWrite(t, svc, source, "keep.txt", "user-new")
	old := moduleFile{SHA: core.Hash("old"), Size: 3, Mode: 0644}
	if err := moduleWriteSiteFileGuarded(f, "keep.txt", []byte("replacement"), 0644, &old, true); err == nil {
		t.Fatal("changed file overwritten")
	}
	if err := moduleWriteSiteFileGuarded(f, "keep.txt", []byte("replacement"), 0644, nil, true); err == nil {
		t.Fatal("newly appeared target overwritten")
	}
	if fixtureRead(t, svc, source, "keep.txt") != "user-new" {
		t.Fatal("user data lost")
	}
	old = moduleFile{SHA: core.Hash("user-new"), Size: 8, Mode: 0600}
	if err := moduleWriteSiteFileGuarded(f, "keep.txt", []byte("replacement"), 0644, &old, true); err == nil {
		t.Fatal("permission change ignored")
	}
	if err := moduleWriteSiteFileGuarded(f, "new.txt", []byte("new"), 0644, nil, true); err != nil {
		t.Fatal(err)
	}
}
func TestAppReliabilitySyncCheckpointAndConflictSafety(t *testing.T) {
	svc, source, target := appReliabilityFixture(t)
	input := core.AppModuleInput{SiteID: source, TargetSiteID: target}
	fixtureWrite(t, svc, source, "copy.txt", "one")
	fixtureWrite(t, svc, source, "conflict.txt", "source")
	fixtureWrite(t, svc, target, "conflict.txt", "user")
	if _, err := svc.moduleSync(context.Background(), input, false); err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, svc, source, "copy.txt", "two")
	if _, err := svc.moduleSync(context.Background(), input, false); err != nil {
		t.Fatal(err)
	}
	if fixtureRead(t, svc, target, "copy.txt") != "two" || fixtureRead(t, svc, target, "conflict.txt") != "user" {
		t.Fatal("incremental sync or conflict protection failed")
	}
	fixtureWrite(t, svc, target, "copy.txt", "external")
	fixtureWrite(t, svc, source, "copy.txt", "three")
	out, err := svc.moduleSync(context.Background(), input, false)
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["conflicts_count"] != 2 || fixtureRead(t, svc, target, "copy.txt") != "external" {
		t.Fatal(out)
	}
	checkpoint := filepath.Join(svc.moduleDir("files-sync"), source+"-"+target+".json")
	if err = os.WriteFile(checkpoint, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.moduleSync(context.Background(), input, false); err == nil {
		t.Fatal("corrupt checkpoint accepted")
	}
}
func TestAppReliabilitySyncPlanLifecycleRevisionAndRestart(t *testing.T) {
	svc, source, target := appReliabilityFixture(t)
	input := core.AppModuleInput{SiteID: source, TargetSiteID: target, ResourceID: "qa-plan", Interval: 60, Enabled: true}
	fixtureWrite(t, svc, source, "copy.txt", "one")
	if _, err := svc.moduleSyncPlans(context.Background(), "schedule", input); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.moduleSyncPlans(context.Background(), "schedule", input); err == nil {
		t.Fatal("stale configuration overwritten")
	}
	if _, err := svc.moduleSyncPlans(context.Background(), "run-plan", input); err != nil {
		t.Fatal(err)
	}
	if fixtureRead(t, svc, target, "copy.txt") != "one" {
		t.Fatal("manual planned execution failed")
	}
	restarted := New(svc.Config)
	var plan moduleSyncPlan
	if err := moduleRead(restarted.syncPlanPath(input.ResourceID), &plan); err != nil {
		t.Fatal(err)
	}
	plan.NextRunAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if err := moduleWrite(restarted.syncPlanPath(plan.ID), plan); err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, svc, source, "copy.txt", "two")
	restarted.runDueSyncPlans(time.Now().UTC())
	if fixtureRead(t, svc, target, "copy.txt") != "two" {
		t.Fatal("scheduled execution did not resume after restart")
	}
	input.ExpectedRevision = 1
	if _, err := restarted.moduleSyncPlans(context.Background(), "pause-plan", input); err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, svc, source, "copy.txt", "three")
	restarted.runDueSyncPlans(time.Now().Add(24 * time.Hour))
	if fixtureRead(t, svc, target, "copy.txt") != "two" {
		t.Fatal("paused plan ran")
	}
	input.ExpectedRevision = 2
	if _, err := restarted.moduleSyncPlans(context.Background(), "resume-plan", input); err != nil {
		t.Fatal(err)
	}
	input.ExpectedRevision = 3
	if _, err := restarted.moduleSyncPlans(context.Background(), "remove-plan", input); err != nil {
		t.Fatal(err)
	}
	if fixtureRead(t, svc, target, "copy.txt") != "two" {
		t.Fatal("removing plan deleted files")
	}
}
func TestAppReliabilityInterruptedAndFailedPlansStopSafely(t *testing.T) {
	svc, source, target := appReliabilityFixture(t)
	input := core.AppModuleInput{SiteID: source, TargetSiteID: target, ResourceID: "qa-fail", Interval: 60, Enabled: true}
	if _, err := svc.moduleSyncPlans(context.Background(), "schedule", input); err != nil {
		t.Fatal(err)
	}
	var plan moduleSyncPlan
	moduleRead(svc.syncPlanPath(input.ResourceID), &plan)
	plan.LastState = "running"
	moduleWrite(svc.syncPlanPath(plan.ID), plan)
	svc.recoverSyncPlans()
	moduleRead(svc.syncPlanPath(plan.ID), &plan)
	if plan.Enabled || plan.LastState != "interrupted" {
		t.Fatal(plan)
	}
	if err := os.Rename(filepath.Join(svc.Config.SitesDir, target), filepath.Join(svc.Config.SitesDir, target+"-archived")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := svc.executeSyncPlan(context.Background(), &plan, "manual", time.Now().UTC()); err == nil {
			t.Fatal("missing target accepted")
		}
	}
	if plan.Enabled || plan.LastState != "paused-error" || plan.FailureCount != 3 {
		t.Fatal(plan)
	}
	for _, interval := range []int{0, 59, 86401} {
		input.Interval = interval
		input.ResourceID = "qa-invalid"
		if _, err := svc.moduleSyncPlans(context.Background(), "schedule", input); err == nil {
			t.Fatal("invalid interval accepted", interval)
		}
	}
}
func TestAppReliabilityIntegrityPoliciesPauseResumeAndSignature(t *testing.T) {
	svc, site, _ := appReliabilityFixture(t)
	fixtureWrite(t, svc, site, "keep.txt", "original")
	input := core.AppModuleInput{SiteID: site, AutoRestore: true, Interval: 60}
	if _, err := svc.moduleIntegrity(context.Background(), "enterprise-tamper-proof", "baseline", input); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.moduleIntegrityControl("enterprise-tamper-proof", "pause", input); err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, svc, site, "keep.txt", "edited")
	svc.runDueIntegrity(time.Now().Add(time.Hour))
	if fixtureRead(t, svc, site, "keep.txt") != "edited" {
		t.Fatal("paused protection restored file")
	}
	if _, err := svc.moduleIntegrityControl("enterprise-tamper-proof", "resume", input); err != nil {
		t.Fatal(err)
	}
	svc.runDueIntegrity(time.Now().Add(time.Hour))
	if fixtureRead(t, svc, site, "keep.txt") != "original" {
		t.Fatal("resumed signed protection failed")
	}
	path := filepath.Join(svc.moduleDir("enterprise-tamper-proof"), "baselines", site, "baseline.json")
	var base moduleBaseline
	moduleRead(path, &base)
	base.Signature = "bad"
	moduleWrite(path, base)
	if _, err := svc.moduleIntegrityControl("enterprise-tamper-proof", "resume", input); err == nil {
		t.Fatal("invalid signed baseline resumed")
	}
	fixtureWrite(t, svc, site, "keep.txt", "user-preserved")
	for i := 0; i < 3; i++ {
		svc.runDueIntegrity(time.Now().Add(time.Duration(i+1) * 24 * time.Hour))
	}
	policy, err := svc.readIntegrityPolicy("enterprise-tamper-proof", site)
	if err != nil || policy.Enabled || policy.LastState != "paused-error" || fixtureRead(t, svc, site, "keep.txt") != "user-preserved" {
		t.Fatal(policy, err)
	}
}
func TestAppReliabilityHistoryBoundsPrivacyAndCorruption(t *testing.T) {
	svc, source, _ := appReliabilityFixture(t)
	input := core.AppModuleInput{SiteID: source, ResourceID: "qa-history", Password: "never-record-password", Token: "never-record-token"}
	for i := 0; i < 120; i++ {
		if err := svc.appendModuleEvent("files-sync", "sync", "manual", input, map[string]any{"token": "never-record-result-token", "copied_count": 2}, nil); err != nil {
			t.Fatal(err)
		}
	}
	out, err := svc.moduleHistory("files-sync", input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.(map[string]any)["history"].([]moduleEvent)) != 100 {
		t.Fatal("history count not bounded")
	}
	path := filepath.Join(svc.moduleDir("files-sync"), "history.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 384<<10 || strings.Contains(string(raw), "never-record") {
		t.Fatal("history leaked secrets or exceeded budget")
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := svc.appendModuleEvent("files-sync", "sync", "manual", input, nil, errors.New("failed")); err == nil {
		t.Fatal("corrupt history overwritten")
	}
	raw, _ = os.ReadFile(path)
	if string(raw) != "corrupt" {
		t.Fatal("corruption evidence lost")
	}
	report := syncReport(false, make([]string, 1000), []string{}, "checkpoint")
	encoded, _ := json.Marshal(report)
	if len(encoded) > 1<<20 || report["copied_count"] != 1000 || report["report_limited"] != true {
		t.Fatal("bounded report lost complete counts")
	}
}
func TestAppReliabilityBadKeysAndOversizedRecordsArePreserved(t *testing.T) {
	svc, _, _ := appReliabilityFixture(t)
	_, err := svc.moduleBaselineKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(svc.Config.SecurityDir, "modules", "integrity-key")
	os.WriteFile(path, []byte("corrupt-key"), 0600)
	if _, err := svc.moduleBaselineKey(); err == nil {
		t.Fatal("bad key replaced")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "corrupt-key" {
		t.Fatal("key evidence lost")
	}
	record := filepath.Join(svc.moduleDir("files-sync"), "qa.json")
	if err := moduleWrite(record, map[string]string{"keep": "original"}); err != nil {
		t.Fatal(err)
	}
	if err := moduleWrite(record, strings.Repeat("x", 4<<20)); err == nil {
		t.Fatal("oversized metadata saved")
	}
	var old map[string]string
	if err := moduleRead(record, &old); err != nil || old["keep"] != "original" {
		t.Fatal("oversized write destroyed previous metadata", err)
	}
}

func TestAppReliabilityPermissionOnlySyncAndHistoryFailure(t *testing.T) {
	svc, source, target := appReliabilityFixture(t)
	input := core.AppModuleInput{SiteID: source, TargetSiteID: target, ResourceID: "qa-permissions", Interval: 60, Enabled: true}
	fixtureWrite(t, svc, source, "mode.txt", "same-content")
	if _, err := svc.moduleSyncPlans(context.Background(), "schedule", input); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.moduleSyncPlans(context.Background(), "run-plan", input); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(svc.Config.SitesDir, source, "public", "mode.txt")
	targetPath := filepath.Join(svc.Config.SitesDir, target, "public", "mode.txt")
	if err := os.Chmod(sourcePath, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.moduleSync(context.Background(), input, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(targetPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("source permission not propagated", err)
	}
	if err = os.Chmod(targetPath, 0640); err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, svc, source, "mode.txt", "new-content")
	out, err := svc.moduleSync(context.Background(), input, false)
	if err != nil || out.(map[string]any)["conflicts_count"] != 1 || fixtureRead(t, svc, target, "mode.txt") != "same-content" {
		t.Fatal("target permission change overwritten", out, err)
	}
	history := filepath.Join(svc.moduleDir("files-sync"), "history.json")
	if err = os.WriteFile(history, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, svc, source, "new.txt", "actual-write")
	if _, err = svc.moduleSyncPlans(context.Background(), "run-plan", input); err == nil {
		t.Fatal("history failure reported success")
	}
	var plan moduleSyncPlan
	if err = moduleRead(svc.syncPlanPath(input.ResourceID), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Enabled || plan.LastState != "paused-error" || fixtureRead(t, svc, target, "new.txt") != "actual-write" {
		t.Fatal("history failure not paused or partial execution hidden", plan)
	}
	plan.Enabled = true
	plan.NextRunAt = time.Now().UTC().Format(time.RFC3339)
	plan.LastState = "running"
	if err = moduleWrite(svc.syncPlanPath(plan.ID), plan); err != nil {
		t.Fatal(err)
	}
	svc.recoverSyncPlans()
	if !svc.moduleAutoBlocked["files-sync/"+plan.ID] {
		t.Fatal("failed recovery history did not block automation")
	}
	out, err = svc.moduleSyncPlans(context.Background(), "run", input)
	if err != nil || out.(map[string]any)["plans"].([]moduleSyncPlan)[0].Enabled {
		t.Fatal("blocked automation shown enabled", out, err)
	}
}

func TestAppReliabilityPlanIdentityMismatchRejectsAllMutations(t *testing.T) {
	svc, source, target := appReliabilityFixture(t)
	input := core.AppModuleInput{SiteID: source, TargetSiteID: target, ResourceID: "qa-identity", Interval: 60, Enabled: true}
	if _, err := svc.moduleSyncPlans(context.Background(), "schedule", input); err != nil {
		t.Fatal(err)
	}
	var plan moduleSyncPlan
	if err := moduleRead(svc.syncPlanPath(input.ResourceID), &plan); err != nil {
		t.Fatal(err)
	}
	plan.ID = "qa-other"
	if err := moduleWrite(svc.syncPlanPath(input.ResourceID), plan); err != nil {
		t.Fatal(err)
	}
	input.ExpectedRevision = plan.Revision
	for _, action := range []string{"run-plan", "schedule", "pause-plan", "resume-plan", "remove-plan"} {
		if _, err := svc.moduleSyncPlans(context.Background(), action, input); err == nil {
			t.Fatal("wrong plan identity accepted", action)
		}
	}
	if _, err := os.Stat(svc.syncPlanPath(input.ResourceID)); err != nil {
		t.Fatal("corrupt plan was removed", err)
	}
}
