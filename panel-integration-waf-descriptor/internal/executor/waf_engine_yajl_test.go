package executor

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestNginxPrivateYAJLPlanIsExactAndDoesNotExpandHTMLAuthority(t *testing.T) {
	work, prefix, assets := "/private/work", "/private/prefix", "/private/assets"
	plan, err := wafNativeBuildPlan(work, prefix, assets, "1.24.0")
	if err != nil || len(plan) != 23 {
		t.Fatal("private complete build plan", err)
	}
	for index, command := range plan {
		if err := validateNginxWAFSourceBuildCommand(work, prefix, assets, "1.24.0", index, command); err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(*wafBuildCommand){
			func(v *wafBuildCommand) { v.Program = "/bin/sh" },
			func(v *wafBuildCommand) { v.Directory = "/private/other-work" },
			func(v *wafBuildCommand) {
				v.Arguments = append(append([]string{}, v.Arguments...), "unreviewed-argument")
			},
			func(v *wafBuildCommand) { v.Environment = []string{"LD_PRELOAD=/private/evil"} },
		} {
			changed := command
			mutate(&changed)
			if err := validateNginxWAFSourceBuildCommand(work, prefix, assets, "1.24.0", index, changed); err == nil {
				t.Fatal("altered source command accepted", index)
			}
		}
		if command.Program == "/usr/bin/cc" || command.Program == "/usr/bin/ar" || command.Program == "/usr/bin/touch" {
			if err := validateWAFBuildCommand(command); err == nil {
				t.Fatal("HTML/shared validator expanded to Nginx-only compiler command", command.Program)
			}
		}
	}
	for _, index := range []int{-1, len(plan), len(plan) + 100} {
		if err := validateNginxWAFSourceBuildCommand(work, prefix, assets, "1.24.0", index, plan[0]); err == nil {
			t.Fatal("wrong plan index accepted", index)
		}
	}
	for _, arg := range plan[18].Arguments {
		if arg == "--with-yajl=yes" || arg == "--with-yajl=/usr" {
			t.Fatal("system YAJL selected")
		}
	}
	if !strings.Contains(strings.Join(plan[18].Arguments, "\n"), "--with-yajl="+prefix) {
		t.Fatal("missing private prefix binding")
	}
}

func TestNginxPrivateYAJLRequiredPatchesLicensesAndVersionAreIndependentlyPinned(t *testing.T) {
	if wafBodyYAJLVersion != "2.1.0-debian5-yz1" || wafBodyEngineVersion != "3.0.17-yz4" {
		t.Fatal("missing private parser revision")
	}
	for _, name := range []string{"apache-body-yajl-CVE-2017-16516.patch", "apache-body-yajl-CVE-2022-24795.patch", "apache-body-yajl-CVE-2023-33460.patch", "apache-body-yajl-COPYING", "apache-body-yajl-debian-copyright", "modsecurity-private-yajl.patch"} {
		data, err := verifiedWAFEngineAsset(name)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != wafEngineAssetPins()[name] {
			t.Fatal("missing independent source/patch/license pin", name, err)
		}
	}
	if _, err := verifiedWAFEngineAsset("apache-body-private-yajl.patch"); err == nil {
		t.Fatal("Apache-specific patch authority silently shared with Nginx")
	}
	patch, _ := verifiedWAFEngineAsset("modsecurity-private-yajl.patch")
	for _, needle := range []string{"--- a/configure", "--- a/build/yajl.m4", "YAJL_LDADD=\"$with_yajl/lib/libyajl.a\"", "pinned private static YAJL is missing", "YAJL_VERSION=\"" + wafBodyYAJLVersion + "\"", "pid_t child = fork ();", "waitpid (child, &status, 0)", "errno != EINTR", "WIFEXITED (status)", "WEXITSTATUS (status) != 0"} {
		if !strings.Contains(string(patch), needle) {
			t.Fatal("private static-only generated/source contract incomplete", needle)
		}
	}
}

func TestNginxPrivateYAJLDynamicTagsRejectSystemParserAndRPATH(t *testing.T) {
	valid := "Dynamic section at offset 0x1234 contains 12 entries:\n  0x0000000000000001 (NEEDED) Shared library: [libc.so.6]\n"
	if err := validateNginxPrivateYAJLDynamicTags(valid); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "readelf failed", "Dynamic section only", valid + " (NEEDED) Shared library: [libyajl.so.2]\n", valid + " (RPATH) Library rpath: [/private/changed]\n", valid + " (RUNPATH) Library runpath: [/private/changed]\n", valid + "\x00", valid + "\r", valid + strings.Repeat(" ", 64<<10)} {
		if err := validateNginxPrivateYAJLDynamicTags(value); err == nil {
			t.Fatal("incomplete or replaceable private parser accepted")
		}
	}
}
