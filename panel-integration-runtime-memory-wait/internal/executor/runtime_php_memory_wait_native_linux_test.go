//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"local/panel/internal/runtimecatalog"
)

// An isolated actual-kernel component, not an application installation or a
// claim that host pressure was manufactured. The typed temporary-shortage
// fixture only exercises the production loop/timer; all admission successes
// additionally come from independently re-reading the real kernel policy.
func TestRuntimeCompilerNativePHPMemoryWaitKernelAndFiniteTimer(t *testing.T) {
	if os.Getenv("PANEL_QA_RUNTIME_PHP_WAIT_NATIVE") != "1" {
		t.Skip("explicit new private Root kernel memory-wait component required")
	}
	base := os.Getenv("PANEL_QA_RUNTIME_PHP_WAIT_ROOT")
	mode := os.Getenv("PANEL_QA_RUNTIME_PHP_WAIT_MODE")
	if !regexp.MustCompile(`^/var/lib/panel-executor/php-memory-wait24bmpn\.[a-f0-9]{32}$`).MatchString(base) || mode != "one-gib" && mode != "obsolete-768m" {
		t.Fatal("not a new fixed private native case")
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if os.Geteuid() != 0 || identity["CapEff"] != "00000000000000e5" || identity["CapBnd"] != "00000000000000e5" || identity["NoNewPrivs"] != "1" || os.Getenv("GOMEMLIMIT") != "128MiB" {
		t.Fatal("native Root supervisor identity changed", identity)
	}
	if empty, err := compilerHasNoChildren(); err != nil || !empty {
		t.Fatal("component must not have a source script/compiler child", err)
	}
	r, ok := runtimecatalog.Find("php-8.2.35")
	if !ok {
		t.Fatal("fixed complete official release absent")
	}
	groupRaw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	group, err := decodeRuntimeCompilerCgroup(string(groupRaw))
	if err != nil {
		t.Fatal(err)
	}
	width := "1073741824\n"
	if mode == "obsolete-768m" {
		width = "805306368\n"
	}
	for name, want := range map[string]string{"memory.max": width, "memory.high": width, "memory.swap.max": "0\n", "pids.max": "512\n"} {
		raw, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", group, name))
		if err != nil || string(raw) != want {
			t.Fatal("actual finite kernel policy changed", name, err)
		}
	}
	readEvents := func() map[string]uint64 {
		raw, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", group, "memory.events"))
		if err != nil {
			t.Fatal(err)
		}
		values, err := runtimePHPCompilerEventsForNativeTest(raw)
		if err != nil {
			t.Fatal(err)
		}
		return values
	}
	before := readEvents()
	if err := runtimePHPCompilerNoOOMForNativeTest(before, before); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	proof := map[string]any{"ok": false, "mode": mode, "component_only": true, "actual_host_pressure_not_injected": true, "compiler_or_command_or_runtime_publication": false, "all50_commercial": false}
	if mode == "obsolete-768m" {
		err := waitRuntimePHPWorkerMemory(ctx, r)
		if !errors.Is(err, errRuntimePHPCompilerMemoryKernel) || ctx.Err() != nil {
			t.Fatal("obsolete actual768MiB policy did not fail immediately", err)
		}
		proof["actual_obsolete_kernel_rejected_without_wait_or_command"] = true
	} else {
		if err := waitRuntimePHPWorkerMemory(ctx, r); err != nil {
			t.Fatal("actual original full memory admission", err)
		}
		calls := 0
		started := time.Now()
		err := awaitRuntimePHPCompilerMemory(ctx, r, func() error {
			calls++
			if err := admitRuntimePHPWorkerMemory(r); err != nil {
				return err
			}
			if calls == 1 {
				return &runtimePHPCompilerMemoryShortage{"explicit transient-only model, not manufactured kernel pressure"}
			}
			return nil
		}, runtimePHPCompilerMemoryDelay)
		elapsed := time.Since(started)
		if err != nil || calls != 2 || elapsed < runtimePHPCompilerMemoryPoll || ctx.Err() != nil {
			t.Fatal("real finite timer and fresh original kernel admissions", err, calls, elapsed)
		}
		cancelled, stop := context.WithCancel(ctx)
		stop()
		if err := waitRuntimePHPWorkerMemory(cancelled, r); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled original worker admitted", err)
		}
		proof["actual_full_kernel_parent_and_host_admissions"] = calls + 1
		proof["real_timer_elapsed_nanoseconds"] = elapsed.Nanoseconds()
		proof["typed_transient_fixture_not_actual_host_pressure"] = true
		proof["original_cancelled_context_refused"] = true
	}
	after := readEvents()
	if err := runtimePHPCompilerNoOOMForNativeTest(before, after); err != nil {
		t.Fatal("memory events changed or reset", err)
	}
	if empty, err := compilerHasNoChildren(); err != nil || !empty {
		t.Fatal("unexpected surviving compiler or source child", err)
	}
	proof["ok"] = true
	proof["events_before"] = before
	proof["events_after"] = after
	proof["no_children_before_and_after"] = true
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, mode+"-kernel-proof.json")
	f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("never overwrite or replay original native proof", err)
	}
	if _, err = f.Write(append(raw, '\n')); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}
