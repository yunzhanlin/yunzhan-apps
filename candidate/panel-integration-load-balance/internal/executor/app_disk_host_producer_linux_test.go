//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/diskjob"
)

func diskHostProducerRequestFixture() diskjob.Request {
	return diskjob.Request{Format: 1, JobID: strings.Repeat("1", 32), ActorID: strings.Repeat("2", 32), AccessRevision: "1", Selection: diskjob.Selection{BootID: "00000000-0000-4000-8000-000000000001", NamespaceID: "4:4026531841", MountID: "31", MountSHA: strings.Repeat("3", 64), Directory: "", AppVersion: diskjob.HostAppVersion, InstallationID: strings.Repeat("4", 32), AppSHA: strings.Repeat("5", 64)}}
}

func TestHostProducerSourceELFCannotBecomeApprovedInstalledProgram(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual root source-ELF refusal not executed")
	}
	name, sha, err := diskHostProgram()
	if err == nil || name != "" || sha != "" {
		t.Fatal("uninstalled source/test ELF substituted for approved running program", name, sha, err)
	}
}

func TestHostProducerNoAlternateRootOrApplicationAnchor(t *testing.T) {
	base := t.TempDir()
	for _, cfg := range []Config{{SystemRoot: base, SecurityDir: "/etc/panel/security-apps"}, {SystemRoot: "/", SecurityDir: filepath.Join(base, "private-apps")}} {
		s := New(cfg)
		if s.diskHostFixedEnvironment() {
			t.Fatal("alternate view became full host")
		}
		in := diskHostProducerRequestFixture()
		if _, err := s.diskHostDispatch(context.Background(), in); err == nil {
			t.Fatal("alternate root dispatched native task")
		}
		if _, err := s.diskHostInventory(context.Background(), diskjob.InventoryRequest{Format: 1, ActorID: in.ActorID, AccessRevision: "1"}); err == nil {
			t.Fatal("alternate root collected host metadata")
		}
		if _, err := s.diskHostCancel(context.Background(), in); err == nil {
			t.Fatal("alternate root sent native cancellation")
		}
		if lease, err := s.diskHostLifecycleBarrier(context.Background()); err == nil || lease != nil {
			if lease != nil {
				lease.Close()
			}
			t.Fatal("alternate root acquired production lifecycle authority")
		}
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused view created/repaired caller directories", entries, err)
	}
}

func TestHostProducerEnvironmentClosedAndNoParentCredentialInheritance(t *testing.T) {
	want := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "SYSTEMD_COLORS=0", "GOMEMLIMIT=384MiB"}
	if got := diskHostEnvironment(); !reflect.DeepEqual(got, want) {
		t.Fatal("worker environment no longer closed", got)
	}
	got := diskHostEnvironment()
	got[0] = "LD_PRELOAD=untrusted"
	if !reflect.DeepEqual(diskHostEnvironment(), want) {
		t.Fatal("mutable launch environment reused")
	}
	in := diskHostProducerRequestFixture()
	if diskjob.ValidateRequest(in) != nil {
		t.Fatal("invalid producer refusal fixture")
	}
}

func TestHostProducerImplicitInstallAndAlternateViewDoNotOptInto14(t *testing.T) {
	base := t.TempDir()
	s := New(Config{SystemRoot: base, SecurityDir: filepath.Join(base, "security")})
	calls := 0
	s.Config.Run = func(context.Context, string, ...string) (string, error) { calls++; return "", nil }
	for _, version := range []string{"", "1.4.0", "1.4.1", "1.4", "1.4.0-rc1", "1.4.1-rc1"} {
		if err := s.appModuleLifecycleVersion(t.Context(), "disk-analysis", "install", nil, version, func(string) {}); err == nil {
			t.Fatal("implicit installation/alternate root opted into host authority", version)
		}
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 || calls != 0 {
		t.Fatal("refused install mutated state", entries, calls, err)
	}
}

func TestHostProducerInstalledEpochIsVersionSpecificAndNeverRepaired(t *testing.T) {
	s := New(Config{SecurityDir: filepath.Join(t.TempDir(), "security")})
	p := filepath.Join(s.moduleDir("disk-analysis"), "installed.json")
	for _, item := range []struct {
		version, epoch string
		valid          bool
	}{
		{"1.3.0", "", true}, {"1.3.0", strings.Repeat("a", 32), false},
		{"1.4.0", "", false}, {"1.4.0", "invalid", false}, {"1.4.0", strings.Repeat("a", 32), true},
		{"1.4.1", "", false}, {"1.4.1", "invalid", false}, {"1.4.1", strings.Repeat("a", 32), true},
		{"1.4.0-rc1", strings.Repeat("a", 32), false},
		{"1.4.1-rc1", strings.Repeat("a", 32), false}, {"1.4.2", strings.Repeat("a", 32), false},
	} {
		record := map[string]any{"id": "disk-analysis", "version": item.version, "settings": map[string]any{}}
		if item.epoch != "" {
			record["installation_id"] = item.epoch
		}
		if err := moduleWrite(p, record); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.moduleInstalledRecord("disk-analysis")
		if (err == nil) != item.valid {
			t.Fatal(item, err)
		}
		after, e := os.ReadFile(p)
		if e != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("record read repaired original epoch", e)
		}
	}
}
