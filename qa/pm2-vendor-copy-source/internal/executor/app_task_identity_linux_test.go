//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTaskManagedCgroupExactCanonicalFamilies(t *testing.T) {
	for _, unit := range []string{"panel-node@" + strings.Repeat("a", 32) + ".service", "panel-pm2@qa-task-project.service", "panel-php@" + strings.Repeat("b", 32) + "-php-8.4.25.service", "panel-php@" + strings.Repeat("c", 32) + "-php-8.4.25-cfg-" + strings.Repeat("d", 24) + ".service"} {
		kind := strings.Split(unit, "@")[0]
		for _, group := range []string{"/system.slice/" + unit, "/system.slice/system-" + strings.ReplaceAll(kind, "-", `\x2d`) + ".slice/" + unit} {
			gotUnit, gotGroup, ok := taskManagedCgroup("0::" + group + "\n")
			if !ok || gotUnit != unit || gotGroup != group {
				t.Fatal("actual system service shape lost", group, gotUnit, gotGroup, ok)
			}
		}
	}
}

func TestTaskManagedCgroupRejectsFragmentsDelegationAndUnknownIdentity(t *testing.T) {
	unit := "panel-node@" + strings.Repeat("a", 32) + ".service"
	good := "0::/system.slice/" + unit + "\n"
	for _, raw := range []string{"", strings.TrimSuffix(good, "\n"), " " + good, good + good, "1:name=systemd:/system.slice/" + unit + "\n", strings.Replace(good, "system.slice", "user.slice/user-1000.slice", 1), strings.Replace(good, "system.slice", "other.slice", 1), strings.Replace(good, "panel-node@", "malicious-panel-node@", 1), strings.Replace(good, ".service", ".service/worker", 1), strings.Replace(good, ".service", ".service (deleted)", 1), strings.Replace(good, "/system.slice/", "/system.slice/../system.slice/", 1), strings.Replace(good, "/system.slice/", "/system.slice//", 1), strings.Replace(good, "/system.slice/", "/system.slice/system-panel\\x2dpm2.slice/", 1), "0::/system.slice/panel-node@fake.service\n", "0::/system.slice/panel-pm2@../../evil.service\n", "0::/system.slice/panel-pm2@-option.service\n", "0::/system.slice/panel-pm2@Uppercase.service\n", "0::/system.slice/panel-php@static.service\n", "0::/system.slice/panel-php@" + strings.Repeat("a", 32) + "-php-8.4.25-cfg-bad.service\n", strings.Replace(good, ".service", ".service\x00", 1), strings.Repeat("x", 8193)} {
		if unit, group, ok := taskManagedCgroup(raw); ok || unit != "" || group != "" {
			t.Fatal("unknown group authorized", strconv.Quote(raw[:min(len(raw), 150)]))
		}
	}
}

func taskIdentityFixtureStatus(uid string) string {
	return "Name:\tfixture\nUid:\t" + uid + " " + uid + " " + uid + " " + uid + "\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\nCapBnd:\tffffffffffffffff\n"
}

func TestTaskProcessStatusRequiresEntireNonRootPolicy(t *testing.T) {
	good := taskIdentityFixtureStatus("501")
	if !taskSafeProcessStatus(good, 501) || taskSafeProcessStatus(taskIdentityFixtureStatus("0"), 0) {
		t.Fatal("non-root or inactive bounding set contract changed")
	}
	for _, raw := range []string{"", good + "Uid:\t501 501 501 501\n", strings.Replace(good, "501 501 501 501", "501 501 0 501", 1), strings.Replace(good, "501 501 501 501", "501 502 501 501", 1), strings.Replace(good, "501 501 501 501", "0501 501 501 501", 1), strings.Replace(good, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), strings.Replace(good, "NoNewPrivs:\t1\n", "", 1), strings.Replace(good, "CapEff:\t0000000000000000", "CapEff:\t0000000000000001", 1), strings.Replace(good, "CapAmb:\t0000000000000000", "CapAmb:\tbad", 1), strings.Replace(good, "CapInh:\t0000000000000000", "CapInh:\t0000000000000001", 1), strings.Replace(good, "CapPrm:\t0000000000000000", "CapPrm:\t0000000000000001", 1), strings.Replace(good, "CapAmb:\t0000000000000000\n", "", 1), good + strings.Repeat("x", 16385)} {
		if taskSafeProcessStatus(raw, 501) {
			t.Fatal("unknown process policy authorized")
		}
	}
	if taskSafeProcessStatus(good, 502) {
		t.Fatal("directory owner mismatch authorized")
	}
}

func TestTaskProcessIdentityAnchoredBoundedFiles(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "42")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[19] = "S", "12345"
	stat := "42 (fixture (worker)) " + strings.Join(fields, " ") + "\n"
	cgroup := "0::/system.slice/panel-pm2@qa-task-project.service\n"
	status := taskIdentityFixtureStatus(strconv.Itoa(os.Geteuid()))
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", stat)
	write("cgroup", cgroup)
	write("status", status)
	got, err := readTaskProcessIdentity(root, 42)
	if err != nil || got.PID != 42 || got.StartTime != 12345 || got.Unit != "panel-pm2@qa-task-project.service" || got.SafeUser != (os.Geteuid() != 0) {
		t.Fatal("proc-shaped fixture identity", got, err)
	}
	for _, state := range []string{"Z", "X", "x"} {
		write("stat", strings.Replace(stat, ") S ", ") "+state+" ", 1))
		if _, err := readTaskProcessIdentity(root, 42); err == nil {
			t.Fatal("dead process authorized", state)
		}
	}
	write("stat", strings.Replace(stat, "42 (", "43 (", 1))
	if _, err := readTaskProcessIdentity(root, 42); err == nil {
		t.Fatal("wrong stat PID accepted")
	}
	write("stat", stat)
	write("cgroup", cgroup+strings.Repeat("x", 8193))
	if _, err := readTaskProcessIdentity(root, 42); err == nil {
		t.Fatal("oversized cgroup accepted")
	}
	write("cgroup", cgroup)
	write("status", strings.Repeat("x", 16385))
	if _, err := readTaskProcessIdentity(root, 42); err == nil {
		t.Fatal("oversized status accepted")
	}
	write("status", status)
	if err := os.Rename(filepath.Join(directory, "status"), filepath.Join(directory, "status-original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("status-original", filepath.Join(directory, "status")); err != nil {
		t.Fatal(err)
	}
	if _, err := readTaskProcessIdentity(root, 42); err == nil {
		t.Fatal("linked status followed")
	}
	if err := os.Symlink("42", filepath.Join(root, "43")); err != nil {
		t.Fatal(err)
	}
	if _, err := readTaskProcessIdentity(root, 43); err == nil {
		t.Fatal("linked process directory followed")
	}
	t.Log("Bounded proc-shaped file fixture only; not actual kernel signal acceptance")
}
