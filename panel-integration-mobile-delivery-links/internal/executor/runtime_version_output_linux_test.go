//go:build linux

package executor

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/runtimecatalog"
)

var runtimeVersionInstalledQA = flag.Bool("runtime-version-read-installed-qa", false, "explicit read-only QA version commands against original installed fixed runtimes; never install, change or repair them")
var runtimeVersionRequiredQA = flag.String("runtime-version-required-native-qa", "nginx-1.30.6", "explicit fixed allowlist programme required by the native QA host; test binary only")

func TestRuntimeVersionOutputExactTokensAndReviewedDockerSuffix(t *testing.T) {
	for _, tc := range []struct{ family, version, id, output string }{
		{"nginx", "1.30.6", "nginx-1.30.6", "nginx version: nginx/1.30.6\n"},
		{"apache", "2.4.68", "apache-2.4.68", "Server version: Apache/2.4.68 (Unix)\nServer built: Oct 21 2026 00:00:00\n"},
		{"mysql", "8.4.11", "mysql-8.4.11", "mysql  Ver 8.4.11 for Linux on aarch64 (MySQL Community Server - GPL)\n"},
		{"mariadb", "11.4.13", "mariadb-11.4.13", "mariadb  Ver 15.1 Distrib 11.4.13-MariaDB, for Linux (x86_64) using readline\n"},
		{"mariadb", "11.8.9", "mariadb-11.8.9", "mariadb from 11.8.9-MariaDB, client 15.2 for Linux (x86_64) using EditLine wrapper\n"},
		{"redis", "8.2.1", "redis-8.2.1", "Redis server v=8.2.1 sha=00000000:0 malloc=jemalloc bits=64 build=fixed\n"},
		{"php", "8.5.10", "php-8.5.10", "8.5.10"},
		{"node", "24.14.0", "node-24.14.0", "v24.14.0\n"},
		{"docker", "26.1.5", "docker-debian-26.1.5", "26.1.5+dfsg1\n"},
		{"docker", "29.8.2", "docker-ce-29.8.2-noble", "29.8.2\n"},
	} {
		t.Run(tc.id+"/"+tc.version, func(t *testing.T) {
			r := runtimecatalog.Release{ID: tc.id, Family: tc.family, Version: tc.version}
			if !runtimeVersionOutputMatches(r, tc.output) {
				t.Fatal("reviewed exact programme token rejected", tc.output)
			}
			if tc.family == "mysql" || tc.family == "mariadb" {
				absolute := strings.Replace(tc.output, tc.family, r.CLI(), 1)
				if !runtimeVersionOutputMatches(r, absolute) {
					t.Fatal("exact reviewed absolute CLI form rejected", absolute)
				}
				for _, path := range []string{"/tmp/" + tc.family, r.CLI() + "-foreign", "./" + tc.family} {
					if runtimeVersionOutputMatches(r, strings.Replace(tc.output, tc.family, path, 1)) {
						t.Fatal("foreign executable path borrowed a reviewed programme identity", path)
					}
				}
			}
			for name, raw := range map[string]string{
				"prefix-version":        strings.ReplaceAll(tc.output, tc.version, tc.version+"0"),
				"foreign-suffix":        strings.ReplaceAll(tc.output, tc.version, tc.version+"-foreign"),
				"diagnostic-only":       "Could not run programme; expected " + tc.output,
				"second-unrelated-line": tc.output + "\nunknown result",
				"nul":                   tc.output + "\x00", "CR": tc.output + "\r", "oversized": tc.output + strings.Repeat(" ", 32769),
			} {
				if tc.family == "apache" && name == "second-unrelated-line" {
					continue // Apache -v has a separate build metadata line.
				}
				if runtimeVersionOutputMatches(r, raw) {
					t.Fatal("non-exact or ambiguous output accepted", name)
				}
			}
		})
	}
	for _, v := range []string{"26.1.5", "26.1.50+dfsg1", "26.1.5+other", "26.1.5+dfsg10"} {
		if runtimeVersionOutputMatches(runtimecatalog.Release{ID: "docker-debian-26.1.5", Family: "docker", Version: "26.1.5"}, v) {
			t.Fatal("Debian engine borrowed unreviewed suffix", v)
		}
	}
	if runtimeVersionOutputMatches(runtimecatalog.Release{ID: "docker-unknown", Family: "docker", Version: "26.1.5"}, "26.1.5") {
		t.Fatal("unknown Docker target accepted")
	}
	if runtimeVersionOutputMatches(runtimecatalog.Release{Family: "unknown", Version: "1.0"}, "1.0") {
		t.Fatal("unknown programme family accepted")
	}
	redis := runtimecatalog.Release{Family: "redis", Version: "8.2.1"}
	if runtimeVersionOutputMatches(redis, "Redis server v=8.2.1 v=8.2.1") {
		t.Fatal("duplicate version tokens accepted")
	}
}

func TestRuntimeExistingCacheRequiresActualProbeAndKeepsFailureWithoutRebuild(t *testing.T) {
	r, ok := runtimecatalog.Find("nginx-1.30.6")
	if !ok {
		t.Fatal("reviewed release missing")
	}
	for _, tc := range []struct {
		name                  string
		loadError, probeError error
		cancelled, exists     bool
		calls                 int
	}{
		{"not-installed", os.ErrNotExist, nil, false, false, 0},
		{"incomplete-prefix-stays-with-original-refusal", errors.New("manifest invalid"), nil, false, false, 0},
		{"verified-cache", nil, nil, false, true, 1},
		{"wrong-program-version", nil, errors.New("not exact"), false, true, 1},
		{"unexecutable-program", nil, syscall.ENOEXEC, false, true, 1},
		{"cancelled", nil, nil, true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			calls := 0
			load := func(id string) (RuntimeManifest, error) {
				if id != r.ID {
					t.Fatal("target changed")
				}
				return RuntimeManifest{Release: r}, tc.loadError
			}
			probe := func(observed context.Context, release runtimecatalog.Release) error {
				calls++
				if observed != ctx || !reflect.DeepEqual(release, r) {
					t.Fatal("original context or target replaced")
				}
				return tc.probeError
			}
			present, err := verifyExistingRuntime(ctx, r, load, probe)
			if present != tc.exists || calls != tc.calls || ((err != nil) != (tc.probeError != nil || tc.cancelled)) {
				t.Fatal(present, calls, err)
			}
			if tc.probeError != nil && !errors.Is(err, tc.probeError) {
				t.Fatal("original failure hidden", err)
			}
		})
	}
	if present, err := verifyExistingRuntime(context.Background(), r, nil, nil); !present || err == nil {
		t.Fatal("missing verifier granted install success")
	}
}

// Private fixture executables only. These tests never edit installed runtimes,
// daemon configuration, package receipts or live native installation ledgers.
func TestRuntimeVersionProcessNativeRejectsWrongPrefixTruncationAndExit(t *testing.T) {
	r, _ := runtimecatalog.Find("nginx-1.30.6")
	for name, output := range map[string]string{
		"exact":                 "nginx version: nginx/1.30.6\n",
		"wrong-prefix":          "nginx version: nginx/1.30.60\n",
		"truncated-good-prefix": "nginx version: nginx/1.30.6" + strings.Repeat(" ", 33000),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "fixed-version-fixture")
			if err := os.WriteFile(file, []byte("#!/bin/sh\nprintf '%s' '"+output+"' >&2\n"), 0700); err != nil {
				t.Fatal(err)
			}
			st, err := os.Lstat(file)
			if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0700 {
				t.Fatal("private ordinary executable fixture required", err)
			}
			identity := st.Sys().(*syscall.Stat_t)
			if identity.Uid != uint32(os.Geteuid()) || identity.Nlink != 1 {
				t.Fatal("fixture ownership/link identity invalid")
			}
			err = verifyRuntimeProgramVersion(context.Background(), r, file)
			if (err == nil) != (name == "exact") {
				t.Fatal("wrong native command result", err)
			}
		})
	}
	file := filepath.Join(t.TempDir(), "fixed-exit-fixture")
	if err := os.WriteFile(file, []byte("#!/bin/sh\nexit 7\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntimeProgramVersion(context.Background(), r, file); err == nil {
		t.Fatal("failed actual child accepted")
	}
}

func TestRuntimeVersionProcessNativeHonorsOriginalCancellation(t *testing.T) {
	r, _ := runtimecatalog.Find("nginx-1.30.6")
	file := filepath.Join(t.TempDir(), "fixed-sleep-fixture")
	if err := os.WriteFile(file, []byte("#!/bin/sh\nexec /bin/sleep 60\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := verifyRuntimeProgramVersion(ctx, r, file); err == nil {
		t.Fatal("timed-out child accepted")
	}
	if ctx.Err() != context.DeadlineExceeded || time.Since(start) > 3*time.Second {
		t.Fatal("original tighter deadline was replaced")
	}
}

func TestRuntimeVersionActualInstalledReadOnlyQA(t *testing.T) {
	if !*runtimeVersionInstalledQA {
		t.Skip("explicit native QA only; command fixtures are not installed programme evidence")
	}
	if os.Geteuid() != 0 {
		t.Fatal("explicit native QA requires the existing executor's read authority")
	}
	if _, ok := runtimecatalog.Find(*runtimeVersionRequiredQA); !ok {
		t.Fatal("test-only required programme must be in the unchanged compiled source allowlist")
	}
	found := false
	checked := 0
	for _, r := range runtimecatalog.All() {
		if _, err := LoadRuntime(r.ID); err != nil {
			continue
		}
		checked++
		if err := verifyRuntimeVersion(context.Background(), r); err != nil {
			t.Errorf("actual fixed programme version command refused %s: %v", r.ID, err)
		}
		found = found || r.ID == *runtimeVersionRequiredQA
	}
	if !found || checked < 2 || checked > 100 {
		t.Fatal("expected original fixed native programme and bounded other installed runtimes", *runtimeVersionRequiredQA, found, checked)
	}
	t.Logf("actual fixed installed version commands checked=%d; no application, runtime or programme operations", checked)
}

func TestRuntimeVersionAbsoluteMySQLFromActualReadOnlyMainObservation(t *testing.T) {
	// Captured from the original installed Main CLI with --no-defaults --version,
	// without SQL, login, configuration or service operations. Binary SHA256:
	// 6424f8712f0e8252a70e9b6a4a673c527b7bf1d69a4b967700aca80f677cdb00.
	r := runtimecatalog.Release{ID: "mysql-8.4.11", Family: "mysql", Version: "8.4.11"}
	actual := "/opt/panel/runtimes/mysql/8.4.11/bin/mysql  Ver 8.4.11 for Linux on aarch64 (MySQL Community Server - GPL)\n"
	if !runtimeVersionOutputMatches(r, actual) {
		t.Fatal("real original fixed MySQL CLI was mistaken for a damaged or wrong version programme")
	}
	for _, changed := range []string{
		strings.Replace(actual, "bin/mysql", "bin/mysql-foreign", 1),
		strings.Replace(actual, "Ver 8.4.11", "Ver 8.4.110", 1),
		strings.Replace(actual, r.CLI(), "/tmp/mysql", 1),
	} {
		if runtimeVersionOutputMatches(r, changed) {
			t.Fatal("corrected canonical CLI form accepted a foreign path or prefix version")
		}
	}
}

func TestRuntimeVersionProcessPHPDefaultConfigurationSemanticsRemainUnchanged(t *testing.T) {
	r, ok := runtimecatalog.Find("php-8.5.10")
	if !ok {
		t.Fatal("reviewed PHP programme missing")
	}
	file := filepath.Join(t.TempDir(), "fixed-php-argument-fixture")
	// A private child verifies the actual selected argv, not a duplicate model.
	// -n would bypass the default configuration and must fail this handshake.
	script := "#!/bin/sh\nif [ \"$#\" -ne 2 ] || [ \"$1\" != '-r' ] || [ \"$2\" != 'echo PHP_VERSION;' ]; then exit 9; fi\nprintf '%s' '8.5.10'\n"
	if err := os.WriteFile(file, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntimeProgramVersion(context.Background(), r, file); err != nil {
		t.Fatal("default PHP configuration probe was changed", err)
	}
}
