//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Explicit private native fixture only. Preserves all inputs, compiler outputs
// and logs, including failed attempts. This is not an application installation
// or a successful signed release/UI/whole-50 acceptance claim.
func TestApacheBodyNativePinnedPatchedCompiler(t *testing.T) {
	if os.Getenv("PANEL_QA_APACHE_BODY_NATIVE") != "1" {
		t.Skip("explicit isolated native Apache body compiler fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture requires restricted root worker to drop compiler identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp("/run/panel-apache-body24adu", "build-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	paths := apacheBodyBuildPaths{filepath.Join(root, "work"), filepath.Join(root, "prefix"), filepath.Join(root, "assets"), "/opt/panel/runtimes/apache/2.4.68"}
	for _, p := range []string{paths.Work, paths.Prefix, paths.Assets, filepath.Join(paths.Prefix, "lib"), filepath.Join(paths.Prefix, "include"), filepath.Join(paths.Prefix, "include/yajl")} {
		if err = os.Mkdir(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range apacheBodySources() {
		archive := filepath.Join("/run/panel-apache-body-inputs24adu", source.Name+".tar.gz")
		destination := "modsecurity"
		if source.Name == "apache-yajl" {
			destination = "yajl"
		}
		if err = extractApacheBodySource(ctx, source, archive, filepath.Join(paths.Work, destination)); err != nil {
			t.Fatal("fixed source preflight", source.Name, err)
		}
	}
	for name := range apacheBodyAssetPins() {
		b, err := verifiedApacheBodyAsset(name)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(paths.Assets, name), b, 0644); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(filepath.Join(paths.Assets, name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Chmod(paths.Assets, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"yajl_common.h", "yajl_parse.h", "yajl_gen.h", "yajl_tree.h"} {
		b, err := os.ReadFile(filepath.Join(paths.Work, "yajl/yajl-2.1.0/src/api", name))
		if err != nil || len(b) > 64<<10 {
			t.Fatal("reviewed JSON public header", name, err)
		}
		if err = os.WriteFile(filepath.Join(paths.Prefix, "include/yajl", name), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(filepath.Join(paths.Prefix, "include/yajl/yajl_version.h"), []byte(apacheBodyYAJLVersionHeader), 0644); err != nil {
		t.Fatal(err)
	}
	build, err := user.Lookup("panel-build")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(build.Uid)
	if err != nil || uid == 0 {
		t.Fatal("build user must be non-root")
	}
	gid, err := strconv.Atoi(build.Gid)
	if err != nil || gid == 0 {
		t.Fatal("build group must be non-root")
	}
	for _, p := range []string{paths.Work, paths.Prefix} {
		if err = filepath.WalkDir(p, func(name string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.Type()&os.ModeSymlink != 0 {
				return os.Lchown(name, uid, gid)
			}
			if d.IsDir() {
				if err := os.Chmod(name, 0755); err != nil {
					return err
				}
			}
			return os.Chown(name, uid, gid)
		}); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := apacheBodyNativeBuildPlan(paths)
	if err != nil {
		t.Fatal(err)
	}
	for i, command := range plan {
		t.Log("FIXED_STEP", i, command.Label)
		if err = runApacheBodyNativeBuildCommand(ctx, paths, i, command, filepath.Join(root, "build.log"), paths.Work); err != nil {
			t.Fatal("preserved build root", root, err)
		}
	}
	makefile, err := os.ReadFile(filepath.Join(paths.Work, "modsecurity/modsecurity-v2.9.15/apache2/Makefile"))
	if err != nil || !strings.Contains(string(makefile), "-DWITH_YAJL") || !strings.Contains(string(makefile), filepath.Join(paths.Prefix, "lib/libyajl.a")) {
		t.Fatal("JSON must be compiled in and linked to exact private static dependency", err)
	}
	// Do not declare a compiler-owned writable DSO ready. The compiler process
	// groups have exited; take back ownership and remove their write access
	// before the existing root-owned SHA verifier or any native load probe.
	for _, p := range []string{paths.Work, paths.Prefix} {
		if err = sealWAFNativeTree(p, uid); err != nil {
			t.Fatal("failed to seal private compiler output", err)
		}
	}
	module := filepath.Join(paths.Work, "modsecurity/modsecurity-v2.9.15/apache2/.libs/mod_security2.so")
	digest, err := wafNativeFileSHA(ctx, module, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	dynamic, err := exec.CommandContext(ctx, "/usr/bin/readelf", "-W", "-d", module).CombinedOutput()
	if err != nil {
		t.Fatal("actual ELF dynamic evidence", err)
	}
	headers, err := exec.CommandContext(ctx, "/usr/bin/readelf", "-W", "-l", module).CombinedOutput()
	if err != nil {
		t.Fatal("actual ELF program headers", err)
	}
	symbols, err := exec.CommandContext(ctx, "/usr/bin/readelf", "-W", "-s", module).CombinedOutput()
	if err != nil {
		t.Fatal("actual ELF stack protection evidence", err)
	}
	if err := verifyApacheBodyELFHardening(string(dynamic), string(headers), string(symbols)); err != nil {
		t.Fatal("native compiler flags did not produce a hardened module", err)
	}
	inputs := map[string]string{}
	for _, source := range apacheBodySources() {
		inputs[source.Name] = source.SHA256
	}
	manifest := map[string]any{"compiler_fixture_passed": true, "module": module, "module_sha256": digest, "engine_version": apacheBodyEngineVersion, "yajl_version": apacheBodyYAJLVersion, "input_sha256": inputs, "assets": apacheBodyAssetPins(), "commercial_feature_parity_complete": false, "apache_loaded": false, "body_detection_verified": false}
	manifest["elf_hardening_verified"] = true
	b, _ := json.MarshalIndent(manifest, "", "  ")
	if err = os.WriteFile(filepath.Join(root, "compiler-proof.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(b)
	t.Log("NATIVE_COMPILER_PROOF", root, "module_sha256="+digest, "proof_sha256="+hex.EncodeToString(hash[:]))
}
