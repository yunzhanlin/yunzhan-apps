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

	"local/panel/internal/runtimecatalog"
)

// Historical 768 MiB failures are retained independently. The new worker must
// fail before a source script, compiler, log or partial runtime is created.
func TestRuntimeCompilerNativePHPRejectsObsolete768MiBBeforeCommand(t *testing.T) {
	if os.Getenv("PANEL_QA_RUNTIME_PHP_GC_NATIVE") != "1" {
		t.Skip("explicit original768MiB isolated negative kernel case required")
	}
	r, found := runtimecatalog.Find(os.Getenv("PANEL_QA_RUNTIME_PHP_GC_RELEASE"))
	selected, bindErr := runtimePHPCompilerNeedsMemoryAdmission(r)
	identity := nativeRuntimeCompilerIdentity(t)
	if !found || bindErr != nil || !selected || os.Geteuid() != 0 || identity["CapEff"] != "00000000000000e5" || identity["CapBnd"] != "00000000000000e5" || identity["NoNewPrivs"] != "1" {
		t.Fatal("negative native authority/source identity changed", bindErr, identity)
	}
	text, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := decodeRuntimeCompilerCgroup(string(text))
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"memory.max": "805306368\n", "memory.high": "805306368\n", "memory.swap.max": "0\n", "pids.max": "512\n"} {
		raw, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", scope, key))
		if err != nil || string(raw) != want {
			t.Fatal("not the exact obsolete768MiB isolated kernel case", key, string(raw), err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx, err = withRuntimePHPCompilerGC(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	const fixture = "/run/panel-runtime-collection24amv"
	log := filepath.Join(fixture, "obsolete-768-build.log")
	if _, err := os.Lstat(log); !os.IsNotExist(err) {
		t.Fatal("never reuse an old negative case", err)
	}
	err = buildCommand(ctx, fixture, log, "/usr/bin/false")
	if !errors.Is(err, errRuntimePHPCompilerMemoryKernel) {
		t.Fatal("obsolete768MiB kernel was not rejected before command/log", err)
	}
	if _, err := os.Lstat(log); !os.IsNotExist(err) {
		t.Fatal("admission created a build log/command boundary", err)
	}
	if empty, err := compilerHasNoChildren(); err != nil || !empty {
		t.Fatal("negative case unexpectedly spawned a child", err)
	}
	raw, err := json.MarshalIndent(map[string]any{"passed": true, "obsolete768MiB_rejected": true, "release": r.ID, "compiler_or_source_script_invoked": false, "build_log_created": false, "installed_runtime": false, "all50_commercial": false}, "", "  ")
	if err != nil || atomicWrite(filepath.Join(fixture, "obsolete-768MiB-rejected.json"), raw, 0600) != nil {
		t.Fatal("could not retain native negative proof", err)
	}
}
