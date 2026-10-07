package executor

import (
	"reflect"
	"strings"
	"testing"
)

func TestWAFNativeBuildPlanIsPinnedNonPrivilegedAndSeparated(t *testing.T) {
	for _, version := range []string{"1.24.0", "1.26.3", "1.30.4", "1.31.5"} {
		plan, err := wafNativeBuildPlan("/var/cache/panel-build/waf-0123/work", "/opt/panel/app-modules/nginx-waf/engines/0123", "/var/cache/panel-build/waf-0123/assets", version)
		if err != nil || len(plan) != 8 {
			t.Fatal("incomplete native build plan", err)
		}
		for _, command := range plan {
			if err := validateWAFBuildCommand(command); err != nil {
				t.Fatal(err)
			}
			for _, arg := range command.Arguments {
				if strings.Contains(arg, "--with-curl=yes") || arg == "-j8" || arg == "sudo" {
					t.Fatal("unsafe compiler argument", arg)
				}
			}
		}
		if !reflect.DeepEqual(plan[4].Arguments, []string{"-j2"}) || !reflect.DeepEqual(plan[7].Arguments, []string{"-j2", "modules"}) {
			t.Fatal("CPU cap or no-Nginx-install boundary lost")
		}
		if !strings.Contains(plan[6].Directory, "nginx-"+version) || len(plan[6].Environment) != 2 {
			t.Fatal("module source/version/library binding lost")
		}
		again, _ := wafNativeBuildPlan("/var/cache/panel-build/waf-0123/work", "/opt/panel/app-modules/nginx-waf/engines/0123", "/var/cache/panel-build/waf-0123/assets", version)
		if !reflect.DeepEqual(plan, again) {
			t.Fatal("build plan not deterministic")
		}
	}
}

func TestWAFNativeBuildPlanRejectsInjectionAndUnsafeEnvironment(t *testing.T) {
	for _, path := range []string{"/", "relative", "/var/cache/../etc", "/var/cache//waf", "/var/cache/waf;evil", "/var/cache/waf\n", "/var/cache/$PATH", "/var/cache/\"waf"} {
		for field := 0; field < 3; field++ {
			paths := []string{"/var/cache/waf/work", "/opt/panel/waf/engine", "/var/cache/waf/assets"}
			paths[field] = path
			if _, err := wafNativeBuildPlan(paths[0], paths[1], paths[2], "1.24.0"); err == nil {
				t.Fatal("accepted injected path", field, path)
			}
		}
	}
	for _, version := range []string{"1.24.0\nrun", "1.24.0 (Ubuntu)", "1.99.0", ""} {
		if _, err := wafNativeBuildPlan("/var/cache/waf/work", "/opt/panel/waf/engine", "/var/cache/waf/assets", version); err == nil {
			t.Fatal("unreviewed version", version)
		}
	}
	for _, pair := range [][2]string{{"/opt/panel/waf/engine", "/opt/panel/waf/engine"}, {"/opt/panel/waf", "/opt/panel/waf/engine"}, {"/opt/panel/waf/engine/work", "/opt/panel/waf/engine"}} {
		if _, err := wafNativeBuildPlan(pair[0], pair[1], "/var/cache/waf/assets", "1.24.0"); err == nil {
			t.Fatal("work/prefix overlap")
		}
	}
	for _, program := range []string{"/bin/sh", "/bin/bash", "/usr/bin/sudo", "/tmp/make", "make"} {
		if err := validateWAFBuildCommand(wafBuildCommand{Directory: "/var/cache/waf/work", Program: program}); err == nil {
			t.Fatal("arbitrary program", program)
		}
	}
	for _, env := range []string{"PATH=/tmp", "LD_PRELOAD=/tmp/evil", "HOME=/root", "MAKEFLAGS=-j99", "MODSECURITY_LIB=/tmp/../etc", "MODSECURITY_LIB=/tmp/evil\nPATH=/tmp"} {
		if err := validateWAFBuildCommand(wafBuildCommand{Directory: "/var/cache/waf/work", Program: "/usr/bin/make", Environment: []string{env}}); err == nil {
			t.Fatal("unsafe environment", env)
		}
	}
}
