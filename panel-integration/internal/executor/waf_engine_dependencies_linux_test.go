//go:build linux

package executor

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestWAFBuildDependenciesMatchReviewedNginxWithoutMutatingBase(t *testing.T) {
	base := append([]string{}, wafBuildDependencies...)
	legacy := wafBuildDependenciesForNginx("1.18.0")
	if len(legacy) != len(base)+1 || legacy[len(base)] != "libpcre3-dev" || !reflect.DeepEqual(legacy[:len(base)], base) {
		t.Fatal("1.18 PCRE1 dependency not closed and version specific", legacy)
	}
	legacy[0] = "changed-private-copy"
	if !reflect.DeepEqual(wafBuildDependencies, base) {
		t.Fatal("dependency selection changed shared base")
	}
	for _, version := range []string{"1.24.0", "1.26.3", "1.30.4", "1.31.5", "unknown;injected"} {
		if !reflect.DeepEqual(wafBuildDependenciesForNginx(version), base) {
			t.Fatal("unknown version selected arbitrary packages", version)
		}
	}
}

func TestWAFDedicatedDependencyProcessInitializesManagedNginxSelection(t *testing.T) {
	s := appDependencyService("nginx-waf")
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" || s.Config.ConfDir != "/etc/panel/sites-enabled" || s.Config.StateDir != "/var/lib/panel-executor" || s.Config.NginxBin != "/usr/sbin/nginx" {
		t.Fatal("dedicated dependency process lacks actual managed Nginx selection", s.Config)
	}
	for _, id := range []string{"pure-ftpd", "nfs-manager", "pm2-manager"} {
		other := appDependencyService(id)
		if other.Config.SitesDir != "" || other.Config.NginxBin != "" {
			t.Fatal("WAF selection changed unrelated dependency constructors", id)
		}
	}
}

func TestWAFBuildPackageStatusRequiresEveryExactInstalledPackage(t *testing.T) {
	packages := wafBuildDependenciesForNginx("1.18.0")
	var complete strings.Builder
	for _, name := range packages {
		complete.WriteString(name + "\tinstall ok installed\n")
	}
	for _, tc := range []struct {
		name, output string
		ready        bool
	}{
		{"complete", complete.String(), true},
		{"missing-PCRE1", strings.ReplaceAll(complete.String(), "libpcre3-dev\tinstall ok installed\n", ""), false},
		{"not-installed", strings.ReplaceAll(complete.String(), "libpcre3-dev\tinstall ok installed", "libpcre3-dev\tunknown ok not-installed"), false},
		{"duplicate", complete.String() + "libpcre3-dev\tinstall ok installed\n", false},
		{"extra", complete.String() + "foreign-package\tinstall ok installed\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testService(t, func(_ context.Context, name string, args ...string) (string, error) {
				if name != "/usr/bin/dpkg-query" || !reflect.DeepEqual(args, append([]string{"-W", "-f=${Package}\t${Status}\n"}, packages...)) {
					t.Fatal("not a fixed read-only package query", name, args)
				}
				return tc.output, nil
			})
			if s.wafBuildPackagesReady(packages) != tc.ready {
				t.Fatal("unsafe package readiness inference")
			}
		})
	}
}

func TestWAFDependencyReadinessUsesActualNginxNotBasePackagesAlone(t *testing.T) {
	for _, tc := range []struct {
		output       string
		pcre1, ready bool
	}{
		{"nginx version: nginx/1.18.0 (Ubuntu)\n", false, false},
		{"nginx version: nginx/1.18.0 (Ubuntu)\n", true, true},
		{"nginx version: nginx/1.24.0 (Ubuntu)\n", false, true},
		{"unverifiable output", true, false},
	} {
		s := testService(t, func(_ context.Context, name string, args ...string) (string, error) {
			if name == "/usr/sbin/nginx" && reflect.DeepEqual(args, []string{"-v"}) {
				return tc.output, nil
			}
			if name != "/usr/bin/dpkg-query" {
				t.Fatal("dependency readiness attempted a mutation", name, args)
			}
			var b strings.Builder
			for _, p := range args[2:] {
				if p == "libpcre3-dev" && !tc.pcre1 {
					continue
				}
				b.WriteString(p + "\tinstall ok installed\n")
			}
			return b.String(), nil
		})
		if s.appDependencyReady("nginx-waf") != tc.ready {
			t.Fatal("legacy PCRE1 missing/unverifiable Nginx incorrectly ready", tc)
		}
	}
}
