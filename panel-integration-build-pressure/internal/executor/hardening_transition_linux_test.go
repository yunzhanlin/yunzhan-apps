//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every command is a closed in-memory sysctl adapter; never the host kernel.
type hardeningFixture struct {
	s               *Service
	values          map[string]string
	writes          int
	failApply       bool
	onApplied       func()
	failWrite       string
	failWriteAlways bool
	mismatchRead    string
}

func newHardeningFixture(t *testing.T) *hardeningFixture {
	t.Helper()
	f := &hardeningFixture{values: map[string]string{}}
	for key := range hardeningValues("strict") {
		f.values[key] = "0"
	}
	base := t.TempDir()
	// Go's temporary-directory mode is not the private journal contract.
	// Establish the isolated fixture explicitly; never repair a production root.
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	c := Config{SystemRoot: base, SecurityDir: filepath.Join(base, "security"), SitesDir: filepath.Join(base, "sites"), ConfDir: filepath.Join(base, "config"), StateDir: filepath.Join(base, "state"), ApacheSiteConfig: filepath.Join(base, "apache.conf"), NginxConf: filepath.Join(base, "nginx.conf"), NginxBin: "/usr/sbin/nginx"}
	for _, dir := range []string{c.SecurityDir, c.SitesDir, c.ConfDir, c.StateDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	c.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if name != "/usr/sbin/sysctl" || len(args) != 2 {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		switch args[0] {
		case "-n":
			if f.mismatchRead == args[1] {
				f.mismatchRead = ""
				return "0\n", nil
			}
			value, ok := f.values[args[1]]
			if !ok {
				return "", errors.New("unknown key")
			}
			return value + "\n", nil
		case "-w":
			key, value, ok := strings.Cut(args[1], "=")
			if f.failWrite == key {
				if !f.failWriteAlways {
					f.failWrite = ""
				}
				return "", errors.New("isolated original kernel write refusal")
			}
			if !ok {
				t.Fatal("invalid assignment")
			}
			if _, ok := f.values[key]; !ok {
				t.Fatal("foreign write", key)
			}
			f.values[key] = value
			f.writes++
			return "", nil
		case "-p":
			raw, err := os.ReadFile(args[1])
			if err != nil {
				return "", err
			}
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
					continue
				}
				key, value, ok := strings.Cut(line, "=")
				if !ok {
					t.Fatal("invalid profile")
				}
				key = strings.TrimSpace(key)
				if _, ok := f.values[key]; !ok {
					t.Fatal("foreign profile write", key)
				}
				f.values[key] = strings.TrimSpace(value)
				f.writes++
			}
			if f.onApplied != nil {
				f.onApplied()
			}
			if f.failApply {
				f.failApply = false
				return "", errors.New("actual apply failed after partial kernel writes")
			}
			return "", nil
		}
		t.Fatal("unsupported command", args)
		return "", nil
	}
	f.s = New(c)
	if err := os.Chmod(f.s.Config.SecurityDir, 0700); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *hardeningFixture) apply(profile string, install bool) error {
	return f.s.applyHardening(context.Background(), map[string]any{"profile": profile}, install, func(string) {})
}

func TestHardeningStrictNeverRequestsPermanentKernelLatch(t *testing.T) {
	if hardeningValues("strict")["kernel.unprivileged_bpf_disabled"] != "2" {
		t.Fatal("strict profile requests irreversible BPF1 rather than reversible disabled2")
	}
}

func TestHardeningProfileTransitionCapturesNewOriginalsAndReleasesRemovedKeys(t *testing.T) {
	f := newHardeningFixture(t)
	if err := f.apply("baseline", true); err != nil {
		t.Fatal(err)
	}
	if err := f.apply("strict", false); err != nil {
		t.Fatal(err)
	}
	m, err := f.s.readSoftwareManifest("system-hardening")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"kernel.unprivileged_bpf_disabled", "net.ipv4.conf.all.log_martians"} {
		if value, ok := m.Previous[key]; !ok || value != "0" {
			t.Fatal("new strict key original not captured", key, m.Previous)
		}
	}
	if f.values["kernel.unprivileged_bpf_disabled"] != "2" {
		t.Fatal("irreversible BPF assignment")
	}
	if err := f.apply("baseline", false); err != nil {
		t.Fatal(err)
	}
	m, err = f.s.readSoftwareManifest("system-hardening")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"kernel.unprivileged_bpf_disabled", "net.ipv4.conf.all.log_martians"} {
		if f.values[key] != "0" {
			t.Fatal("removed key not restored", key)
		}
		if _, ok := m.Previous[key]; ok {
			t.Fatal("released key still claimed", key)
		}
	}
}

func TestHardeningFailedConfigureRestoresImmediatePriorValuesAndExactFiles(t *testing.T) {
	f := newHardeningFixture(t)
	if err := f.apply("baseline", true); err != nil {
		t.Fatal(err)
	}
	before := maps.Clone(f.values)
	config := f.s.systemPath("/etc/sysctl.d/99-zz-panel-hardening.conf")
	oldConfig, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	oldManifest, err := os.ReadFile(f.s.softwareManifestPath("system-hardening"))
	if err != nil {
		t.Fatal(err)
	}
	f.failApply = true
	if err := f.apply("strict", false); err == nil {
		t.Fatal("failed kernel apply became success")
	}
	if !reflect.DeepEqual(before, f.values) {
		t.Fatal("rollback used installation originals, not immediate pre-operation kernel values", before, f.values)
	}
	got, _ := os.ReadFile(config)
	manifest, _ := os.ReadFile(f.s.softwareManifestPath("system-hardening"))
	if string(got) != string(oldConfig) || string(manifest) != string(oldManifest) {
		t.Fatal("previous profile files lost")
	}
}

func TestHardeningManifestFailureRestoresKernelAndDoesNotDeleteForeignObject(t *testing.T) {
	f := newHardeningFixture(t)
	before := maps.Clone(f.values)
	foreign := f.s.softwareManifestPath("system-hardening")
	f.onApplied = func() {
		if err := os.Mkdir(foreign, 0700); err != nil {
			t.Fatal(err)
		}
		f.onApplied = nil
	}
	if err := f.apply("baseline", true); err == nil {
		t.Fatal("manifest collision accepted")
	}
	if !reflect.DeepEqual(before, f.values) {
		t.Fatal("manifest failure left partial live settings")
	}
	if _, err := os.Lstat(f.s.systemPath("/etc/sysctl.d/99-zz-panel-hardening.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed installation left persistent config", err)
	}
	if st, err := os.Lstat(foreign); err != nil || !st.IsDir() {
		t.Fatal("foreign collision removed", err)
	}
}

func TestHardeningIrreversibleCurrentBPFRefusesBeforeAnyWrites(t *testing.T) {
	f := newHardeningFixture(t)
	f.values["kernel.unprivileged_bpf_disabled"] = "1"
	before := maps.Clone(f.values)
	if err := f.apply("strict", true); err == nil {
		t.Fatal("irreversible current kernel was claimed reversible")
	}
	if f.writes != 0 || !reflect.DeepEqual(before, f.values) {
		t.Fatal("preflight refusal changed kernel")
	}
	if _, err := os.Lstat(f.s.systemPath("/etc/sysctl.d/99-zz-panel-hardening.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preflight refusal changed persistent config", err)
	}
}

func TestHardeningUnknownProfileRefusesWithoutKernelOrFiles(t *testing.T) {
	f := newHardeningFixture(t)
	if err := f.apply("foreign-profile", true); err == nil {
		t.Fatal("unknown profile accepted as baseline")
	}
	if f.writes != 0 {
		t.Fatal("invalid request reached kernel")
	}
}

func TestHardeningLegacyMissingOriginalRefusesReleaseWithoutMutation(t *testing.T) {
	f := newHardeningFixture(t)
	if err := f.apply("baseline", true); err != nil {
		t.Fatal(err)
	}
	m, err := f.s.readSoftwareManifest("system-hardening")
	if err != nil {
		t.Fatal(err)
	}
	m.Settings = map[string]any{"profile": "strict"}
	if err = f.s.writeSoftwareManifest(m); err != nil {
		t.Fatal(err)
	}
	before := maps.Clone(f.values)
	writes := f.writes
	old, _ := os.ReadFile(f.s.softwareManifestPath("system-hardening"))
	if err := f.apply("baseline", false); err == nil {
		t.Fatal("legacy missing strict original was guessed")
	}
	after, _ := os.ReadFile(f.s.softwareManifestPath("system-hardening"))
	if f.writes != writes || !reflect.DeepEqual(before, f.values) || string(old) != string(after) {
		t.Fatal("legacy refusal mutated original state")
	}
	if filepath.Base(f.s.Config.SystemRoot) == "/" {
		t.Fatal("fixture escaped private root")
	}
}

func TestHardeningVerificationFailureRestoresImmediateProfile(t *testing.T) {
	f := newHardeningFixture(t)
	if err := f.apply("baseline", true); err != nil {
		t.Fatal(err)
	}
	before := maps.Clone(f.values)
	f.onApplied = func() { f.mismatchRead = "kernel.yama.ptrace_scope"; f.onApplied = nil }
	if err := f.apply("strict", false); err == nil {
		t.Fatal("bad actual verification became success")
	}
	if !maps.Equal(before, f.values) {
		t.Fatal("verification failure left changed kernel")
	}
}

func TestHardeningFailedRemovalRestoresActualPriorProfile(t *testing.T) {
	f := newHardeningFixture(t)
	if err := f.apply("strict", true); err != nil {
		t.Fatal(err)
	}
	before := maps.Clone(f.values)
	config := f.s.systemPath("/etc/sysctl.d/99-zz-panel-hardening.conf")
	old, _ := os.ReadFile(config)
	manifest, _ := os.ReadFile(f.s.softwareManifestPath("system-hardening"))
	f.failWrite = "kernel.dmesg_restrict"
	if err := f.s.uninstallHardening(context.Background(), func(string) {}); err == nil {
		t.Fatal("failed removal accepted")
	}
	if !maps.Equal(before, f.values) {
		t.Fatal("partial removal not rolled back")
	}
	a, _ := os.ReadFile(config)
	b, _ := os.ReadFile(f.s.softwareManifestPath("system-hardening"))
	if string(a) != string(old) || string(b) != string(manifest) {
		t.Fatal("removal failure lost original files")
	}
}

func TestHardeningRollbackFailureCannotClaimRestored(t *testing.T) {
	f := newHardeningFixture(t)
	f.failApply = true
	f.failWrite = "fs.protected_hardlinks"
	f.failWriteAlways = true
	err := f.apply("baseline", true)
	if err == nil || !strings.Contains(err.Error(), "恢复未完成") || strings.Contains(err.Error(), "已核对恢复") {
		t.Fatal("incomplete rollback falsely certified", err)
	}
}

func TestHardeningReleasedParametersAndUnrelatedConfigRemainOutsideRemoval(t *testing.T) {
	f := newHardeningFixture(t)
	for i, p := range []string{"baseline", "strict", "baseline"} {
		if err := f.apply(p, i == 0); err != nil {
			t.Fatal(err)
		}
	}
	f.values["kernel.unprivileged_bpf_disabled"] = "2"
	f.values["net.ipv4.conf.all.log_martians"] = "1"
	other := f.s.systemPath("/etc/sysctl.d/10-unrelated.conf")
	if err := os.WriteFile(other, []byte("# independent administrator settings\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := f.s.uninstallHardening(context.Background(), func(string) {}); err != nil {
		t.Fatal(err)
	}
	if f.values["kernel.unprivileged_bpf_disabled"] != "2" || f.values["net.ipv4.conf.all.log_martians"] != "1" {
		t.Fatal("released parameters changed by later removal")
	}
	raw, err := os.ReadFile(other)
	if err != nil || string(raw) != "# independent administrator settings\n" {
		t.Fatal("unrelated file changed", err)
	}
}

func TestHardeningChangedOrUnsafeConfigRefusesWithoutRepair(t *testing.T) {
	for _, mode := range []string{"changed", "symlink", "hardlink", "writable", "oversize", "duplicate-legacy"} {
		t.Run(mode, func(t *testing.T) {
			f := newHardeningFixture(t)
			if err := f.apply("baseline", true); err != nil {
				t.Fatal(err)
			}
			file := f.s.systemPath("/etc/sysctl.d/99-zz-panel-hardening.conf")
			original, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "changed":
				if err = os.WriteFile(file, append(original, []byte("# external change\n")...), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				saved := filepath.Join(f.s.Config.SystemRoot, "original.conf")
				if err = os.Rename(file, saved); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(saved, file); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err = os.Link(file, filepath.Join(f.s.Config.SystemRoot, "second-link.conf")); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err = os.Chmod(file, 0666); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err = os.WriteFile(file, bytes.Repeat([]byte("#"), (64<<10)+1), 0644); err != nil {
					t.Fatal(err)
				}
			case "duplicate-legacy":
				if err = os.WriteFile(f.s.systemPath("/etc/sysctl.d/90-panel-hardening.conf"), original, 0644); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(file)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			kernel := maps.Clone(f.values)
			writes := f.writes
			if err = f.apply("strict", false); err == nil {
				t.Fatal("unsafe config was normalized", mode)
			}
			after, err := os.Lstat(file)
			if err != nil {
				t.Fatal(err)
			}
			now, _ := os.ReadFile(file)
			if !os.SameFile(before, after) || before.Mode() != after.Mode() || string(raw) != string(now) || writes != f.writes || !maps.Equal(kernel, f.values) {
				t.Fatal("refused config repaired or kernel changed", mode)
			}
		})
	}
}

func TestHardeningMutationLockRefusesBusyAndUnsafeWithoutRepair(t *testing.T) {
	f := newHardeningFixture(t)
	first, err := f.s.hardeningMutationLock()
	if err != nil {
		t.Fatal(err)
	}
	if second, err := f.s.hardeningMutationLock(); err == nil {
		second.Close()
		t.Fatal("second mutation admitted")
	}
	first.Close()
	lock := filepath.Join(f.s.Config.SecurityDir, "hardening-configuration.lock")
	if err = os.Chmod(lock, 0644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Lstat(lock)
	if err = f.apply("baseline", true); err == nil {
		t.Fatal("public mutation lock silently repaired")
	}
	after, _ := os.Lstat(lock)
	if !os.SameFile(before, after) || after.Mode().Perm() != 0644 || f.writes != 0 {
		t.Fatal("lock refusal changed state")
	}
}

func TestHardeningManifestCompensationOnlyRevertsExactOwnCandidate(t *testing.T) {
	f := newHardeningFixture(t)
	if err := f.apply("baseline", true); err != nil {
		t.Fatal(err)
	}
	before, err := f.s.hardeningManifestBackup()
	if err != nil {
		t.Fatal(err)
	}
	candidate := []byte("{\"exact-own-candidate\":true}\n")
	if err = atomicWrite(before.path, candidate, 0600); err != nil {
		t.Fatal(err)
	}
	if err = f.s.hardeningRestoreManifest(before, candidate, false); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(before.path)
	if string(raw) != string(before.data) {
		t.Fatal("exact own commit not restored")
	}
	foreign := []byte("{\"foreign-object\":true}\n")
	if err = atomicWrite(before.path, foreign, 0600); err != nil {
		t.Fatal(err)
	}
	if err = f.s.hardeningRestoreManifest(before, candidate, false); err == nil {
		t.Fatal("foreign manifest accepted for compensation")
	}
	raw, _ = os.ReadFile(before.path)
	if string(raw) != string(foreign) {
		t.Fatal("foreign manifest overwritten")
	}
}
