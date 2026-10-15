package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestApacheBodyPinnedIndependentSourceAuthority(t *testing.T) {
	sources := apacheBodySources()
	if len(sources) != 2 || len(wafEngineSources()) != 4 {
		t.Fatal("Apache source authority expanded an existing Nginx list")
	}
	// Both engines may reuse the exact reviewed upstream YAJL bytes, but a
	// shared digest must never grant the other engine's source authority.
	nginxYAJL := wafEngineSources()[3]
	apacheYAJL := sources[1]
	if nginxYAJL.Name != "nginx-yajl" || apacheYAJL.Name != "apache-yajl" || nginxYAJL.URL != apacheYAJL.URL || nginxYAJL.SHA256 != apacheYAJL.SHA256 || nginxYAJL == apacheYAJL {
		t.Fatal("shared YAJL bytes must retain independently reviewed source identities")
	}
	for _, source := range sources {
		if !reviewedApacheBodySource(source) || reviewedWAFEngineSource(source) {
			t.Fatal("source authority is not independent", source.Name)
		}
		for _, field := range []string{"name", "version", "url", "sha", "verification"} {
			changed := source
			switch field {
			case "name":
				changed.Name += "-other"
			case "version":
				changed.Version += "-other"
			case "url":
				changed.URL += "?token=not-allowed"
			case "sha":
				changed.SHA256 = strings.Repeat("0", 64)
			case "verification":
				changed.Verification = "caller says approved"
			}
			if reviewedApacheBodySource(changed) {
				t.Fatal("mutated source accepted", field)
			}
		}
	}
	for _, source := range wafEngineSources() {
		if reviewedApacheBodySource(source) {
			t.Fatal("v3 connector/engine cannot silently select Apache")
		}
	}
}

func TestApacheBodyAllAssetsDigestAndCompleteLicenseNotices(t *testing.T) {
	if len(apacheBodyAssetPins()) != 12 {
		t.Fatal("unexpected asset set")
	}
	entries, err := apacheBodyAssets.ReadDir("assets")
	if err != nil || len(entries) != 12 {
		t.Fatal("untracked embedded Apache asset", len(entries), err)
	}
	for name, pin := range apacheBodyAssetPins() {
		b, err := verifiedApacheBodyAsset(name)
		if err != nil || len(b) == 0 {
			t.Fatal(name, err)
		}
		digest := sha256.Sum256(b)
		if hex.EncodeToString(digest[:]) != pin {
			t.Fatal("asset changed", name)
		}
	}
	for _, name := range []string{"../../README", "apache-body-unreviewed.patch", "modsecurity-LICENSE"} {
		if _, err := verifiedApacheBodyAsset(name); err == nil {
			t.Fatal("unknown resource accepted", name)
		}
	}
	checks := map[string][]string{
		"apache-body-modsecurity-LICENSE":   {"Apache License", "END OF TERMS AND CONDITIONS"},
		"apache-body-libinjection-COPYING":  {"2017-2024", "All rights reserved.", "3. Neither", "THIS SOFTWARE IS PROVIDED"},
		"apache-body-yajl-COPYING":          {"2007-2014", "Permission to use", "THE SOFTWARE IS PROVIDED"},
		"apache-body-yajl-debian-copyright": {"Florian Forster", "John Stamp", "License: ISC"},
		"apache-body-metadata-only.patch":   {"Yunzhan modification 2026-10-11", "O_NOFOLLOW", "LOCK_EX | LOCK_NB", "st.st_nlink == 1", "st.st_uid == geteuid()", "32 * 1024 * 1024 - length"},
		"apache-body-parser-limits.patch":   {"Yunzhan modification 2026-10-11", "depth includes the root object", "is_enabled != MODSEC_DETECTION_ONLY", "msr->msc_reqbody_error = 1;", "phase == PHASE_REQUEST_HEADERS", "keepalive = AP_CONN_CLOSE"},
		"apache-body-pcre2-no-rpath.patch":  {"Yunzhan modification 2026-10-11", "--- a/apache2/Makefile.am", "--- a/apache2/Makefile.in", "never a DSO RPATH"},
	}
	for name, needles := range checks {
		b, _ := verifiedApacheBodyAsset(name)
		for _, needle := range needles {
			if !strings.Contains(string(b), needle) {
				t.Fatal("missing fixed notice/privacy guard", name, needle)
			}
		}
	}
}

func TestApacheBodyBuildPlanFixedStaticPatchedJSONAndNoSystemInstall(t *testing.T) {
	p := apacheBodyBuildPaths{"/private/work", "/private/prefix", "/private/assets", "/private/apache"}
	plan, err := apacheBodyNativeBuildPlan(p)
	if err != nil || len(plan) != 20 {
		t.Fatal(len(plan), err)
	}
	cc, patch, ar, configure, make, touch := 0, 0, 0, 0, 0, 0
	for i, command := range plan {
		if err := validateApacheBodyBuildCommand(p, i, command); err != nil {
			t.Fatal(i, err)
		}
		if len(command.Environment) != 0 {
			t.Fatal("caller environment override")
		}
		switch command.Program {
		case "/usr/bin/cc":
			cc++
		case "/usr/bin/patch":
			patch++
		case "/usr/bin/ar":
			ar++
		case "/usr/bin/touch":
			touch++
			if !reflect.DeepEqual(command.Arguments, []string{"-r", "/private/work/modsecurity/modsecurity-v2.9.15/aclocal.m4", "/private/work/modsecurity/modsecurity-v2.9.15/build/find_yajl.m4", "/private/work/modsecurity/modsecurity-v2.9.15/apache2/Makefile.am"}) {
				t.Fatal("generation ordering must not change arbitrary timestamps")
			}
		case "./configure":
			configure++
			for _, needle := range []string{"--with-yajl=/private/prefix", "--with-pcre2=/usr/bin/pcre2-config", "--disable-mlogc", "--with-curl=no", "--disable-htaccess-config"} {
				if !strings.Contains(strings.Join(command.Arguments, " "), needle) {
					t.Fatal("unsafe/incomplete fixed feature selection", needle)
				}
			}
		case "/usr/bin/make":
			make++
			if !reflect.DeepEqual(command.Arguments, []string{"-j1", "-C", "apache2"}) {
				t.Fatal("must not install/replace Apache or build in parallel")
			}
		default:
			t.Fatal("non-fixed executable", command.Program)
		}
		changed := command
		changed.Arguments = append(append([]string{}, command.Arguments...), "--caller-option")
		if validateApacheBodyBuildCommand(p, i, changed) == nil {
			t.Fatal("compiler argument was not compared to exact plan")
		}
		changed = command
		changed.Environment = []string{"LD_PRELOAD=/tmp/other.so"}
		if validateApacheBodyBuildCommand(p, i, changed) == nil {
			t.Fatal("environment override accepted")
		}
		changed = command
		changed.Directory = "/elsewhere"
		if validateApacheBodyBuildCommand(p, i, changed) == nil {
			t.Fatal("alternate source directory accepted")
		}
	}
	if cc != 9 || patch != 7 || ar != 1 || configure != 1 || make != 1 || touch != 1 {
		t.Fatal("incomplete fixed native plan", cc, patch, ar, configure, make, touch)
	}
	if validateWAFBuildCommand(plan[3]) == nil {
		t.Fatal("Apache cc runner must not broaden existing Nginx authority")
	}
	if validateApacheBodyBuildCommand(p, -1, plan[0]) == nil || validateApacheBodyBuildCommand(p, len(plan), plan[0]) == nil {
		t.Fatal("invalid plan index accepted")
	}
	for _, bad := range []apacheBodyBuildPaths{
		{"/private/work", "/private/work/output", "/private/assets", "/private/apache"},
		{"/private/work", "/private/prefix", "/private/assets", "/private/assets"},
		{"/private/work", "/private/prefix", "/private/prefix/assets", "/private/apache"},
		{"/private/work;id", "/private/prefix", "/private/assets", "/private/apache"},
		{"/private/work", "/private/prefix", "/private/assets", "/private/apache\nLoadModule"},
		{"/", "/private/prefix", "/private/assets", "/private/apache"},
	} {
		if _, err := apacheBodyNativeBuildPlan(bad); err == nil {
			t.Fatal("overlapping or injectable build roots accepted", bad)
		}
	}
}
