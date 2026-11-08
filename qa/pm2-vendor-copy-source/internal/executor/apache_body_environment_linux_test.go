//go:build linux

package executor

import (
	"reflect"
	"testing"
)

func TestApacheBodyNativeEnvironmentClosedHardeningAndLegacyIsolation(t *testing.T) {
	legacy := []string{"PATH=/usr/bin:/bin", "HOME=/private/work", "LANG=C", "LC_ALL=C", "CFLAGS=-O2 -g0", "CXXFLAGS=-O2 -g0", "MAKEFLAGS="}
	if !reflect.DeepEqual(nativeBuildEnvironment("/private/work", nil, false), legacy) {
		t.Fatal("Apache hardening changed existing Nginx compiler environment")
	}
	apache := append(append([]string{}, legacy...), "LDFLAGS=-Wl,-z,relro,-z,now")
	apache[4] = "CFLAGS=-O2 -g0 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fno-common"
	apache[5] = "CXXFLAGS=-O2 -g0 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fno-common"
	if !reflect.DeepEqual(nativeBuildEnvironment("/private/work", nil, true), apache) {
		t.Fatal("fixed compiler/linker hardening changed")
	}
	p := apacheBodyBuildPaths{"/private/work", "/private/prefix", "/private/assets", "/private/apache"}
	plan, err := apacheBodyNativeBuildPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	for i, command := range plan {
		command.Environment = []string{"CFLAGS=-fno-stack-protector"}
		if validateApacheBodyBuildCommand(p, i, command) == nil {
			t.Fatal("caller disabled compiler hardening")
		}
	}
}
