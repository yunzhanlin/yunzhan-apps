//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Native probes exercise the same bounded production runner with changed-UID
// descendants in both the inherited group and a new session. This is not a
// caller-supplied command API or source-compilation receipt.
func TestApacheBodyCompilerCancellationCollectsChangedUIDGrandchildren(t *testing.T) {
	if os.Getenv("PANEL_QA_APACHE_BODY_WORKER") != "1" {
		t.Skip("explicit private native Apache worker required")
	}
	nativeCompilerCollectionFixture(t, true)
}

func TestApacheBodyProductionWorkerNativeSealedBuildAndReadOnlyVerification(t *testing.T) {
	if os.Getenv("PANEL_QA_APACHE_BODY_WORKER") != "1" {
		t.Skip("explicit private native Apache worker required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("restricted root fixture required")
	}
	// The runner binds new private directories to every fixed namespace. No
	// normal installed application, account, package or site is modified.
	id := os.Getenv("PANEL_QA_APACHE_BODY_WORKER_JOB")
	if !core.ValidID(id) {
		t.Fatal("runner must stage the exact private request before read-only unit start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	if err := runApacheBodyBuildContext(ctx, id); err != nil {
		t.Fatal("retained failed task", id, err)
	}
	if err := verifyApacheBodyBuildContext(ctx, id); err != nil {
		t.Fatal(err)
	}
	record, err := readApacheBodyBuildRecord(id)
	if err != nil || apacheBodyRecordContract(record) != nil {
		t.Fatal("sealed ready record", err)
	}
	if record.ProductionUsed {
		t.Fatal("build silently activated application")
	}
	before, err := os.ReadFile(filepath.Join(apacheBodyJobs, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyApacheBodyBuild(id); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(apacheBodyJobs, id+".json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("read-only verification wrote evidence", err)
	}
	if err := runApacheBodyBuildContext(ctx, id); err == nil {
		t.Fatal("completed job identity was reused")
	}
	after, _ = os.ReadFile(filepath.Join(apacheBodyJobs, id+".json"))
	if string(before) != string(after) {
		t.Fatal("duplicate build changed existing evidence")
	}
	module := filepath.Join(record.Prefix, "apache/mod_security2.so")
	b, err := os.ReadFile(module)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module, append(append([]byte{}, b...), 'x'), 0644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyApacheBodyBuild(id); err == nil {
		t.Fatal("changed actual module was trusted")
	}
	if err := os.WriteFile(module, b, 0644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyApacheBodyBuild(id); err != nil {
		t.Fatal("restored private fixture differs", err)
	}
	canceled := os.Getenv("PANEL_QA_APACHE_BODY_CANCELED_JOB")
	if !core.ValidID(canceled) || canceled == id {
		t.Fatal("runner must stage a distinct canceled private request")
	}
	if err := runApacheBodyBuildContext(ctx, canceled); err == nil {
		t.Fatal("canceled task was started")
	}
	if _, err := os.Lstat(filepath.Join(apacheBodyJobs, canceled+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled task created a build record", err)
	}
	if err := runApacheBodyBuildContext(ctx, core.ID()); err == nil {
		t.Fatal("unrequested task started")
	}
	proof := map[string]any{"worker_fixture_passed": true, "record": record, "read_only_verified": true, "duplicate_preserved": true, "changed_module_rejected": true, "canceled_before_start_rejected": true, "application_installed": false, "site_activated": false, "commercial_feature_parity_complete": false}
	data, _ := json.MarshalIndent(proof, "", "  ")
	if err := atomicWrite(filepath.Join(apacheBodyCache, "native-worker-proof.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("NATIVE_APACHE_WORKER_PROOF", id, record.ModuleSHA, record.TreeSHA)
}
