//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRuntimeCompilerIdentityArgumentsClosed(t *testing.T) {
	args := []string{"--flag=literal", "$(not-a-shell)", "a b"}
	want := append([]string{"-u", "panel-build", "--", "/usr/bin/setpriv", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", "/private/source/configure"}, args...)
	if got := runtimeBuildIdentityArgs("/private/source/configure", args...); !reflect.DeepEqual(got, want) {
		t.Fatal("native compiler identity boundary changed", got)
	}
	if !reflect.DeepEqual(args, []string{"--flag=literal", "$(not-a-shell)", "a b"}) {
		t.Fatal("builder changed caller arguments")
	}
}

func nativeRuntimeCompilerIdentity(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok {
			values[key] = strings.TrimSpace(value)
		}
	}
	return values
}

func TestRuntimeCompilerNativeChildClearedIdentity(t *testing.T) {
	if os.Getenv("PANEL_QA_NATIVE_RUNTIME_CHILD") != "1" {
		t.Skip("private re-executed native compiler child only")
	}
	build, err := user.Lookup("panel-build")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(build.Uid)
	if err != nil || uid <= 0 || os.Geteuid() != uid || os.Getuid() != uid {
		t.Fatal("actual native compiler did not change UID", uid, err)
	}
	values := nativeRuntimeCompilerIdentity(t)
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if value, err := strconv.ParseUint(values[key], 16, 64); err != nil || value != 0 {
			t.Fatal("actual compiler capability set not cleared", key, values[key], err)
		}
	}
	if values["NoNewPrivs"] != "1" || values["CapBnd"] != "00000000000000e5" {
		t.Fatal("actual native fixture confinement changed", values)
	}
	encoded, _ := json.Marshal(map[string]any{"uid": uid, "identity": values})
	t.Log("NATIVE_RUNTIME_COMPILER_CLEARED", string(encoded))
}

func TestRuntimeCompilerNativeInheritedCapabilityBoundary(t *testing.T) {
	if os.Getenv("PANEL_QA_NATIVE_RUNTIME_COMPILER") != "1" {
		t.Skip("explicit Root E5 private native runtime compiler fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture supervisor must use confined Root")
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if identity["CapInh"] != "00000000000000e5" || identity["CapEff"] != "00000000000000e5" || identity["CapBnd"] != "00000000000000e5" || identity["NoNewPrivs"] != "1" {
		t.Fatal("fixture must actually supply inherited E5, not an unprivileged imitation", identity)
	}
	const fixture = "/run/panel-runtime-compiler24als"
	build, err := user.Lookup("panel-build")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(build.Uid)
	gid, _ := strconv.Atoi(build.Gid)
	work := filepath.Join(fixture, "work")
	if err := os.Mkdir(work, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(work, uid, gid); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	logPath := filepath.Join(fixture, "actual-builder.log")
	if err := buildCommand(ctx, work, logPath, "/usr/bin/env", "PANEL_QA_NATIVE_RUNTIME_CHILD=1", executable, "-test.v", "-test.count=1", "-test.run=^TestRuntimeCompilerNativeChildClearedIdentity$"); err != nil {
		output, _ := os.ReadFile(logPath)
		t.Fatal(err, string(output))
	}
	output, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(output), "NATIVE_RUNTIME_COMPILER_CLEARED") || strings.Contains(string(output), "--- SKIP:") {
		t.Fatal("actual changed-UID builder proof missing", err, string(output))
	}
	proof, _ := json.MarshalIndent(map[string]any{"passed": true, "actual_build_command_executed": true, "supervisor_identity": identity, "compiler_uid": uid, "all_compiler_inherited_permitted_effective_ambient_sets_zero": true, "original_runtime_installed": false, "application_installed": false}, "", "  ")
	if err := atomicWrite(filepath.Join(fixture, "proof.json"), proof, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("NATIVE_RUNTIME_COMPILER_BOUNDARY_PROOF", uid)
}
