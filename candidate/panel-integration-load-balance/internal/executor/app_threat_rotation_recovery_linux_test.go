//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func threatIDSColdRotationFixture(t *testing.T) (*Service, threatIDSRotation, threatIDSAccount, string, string, *string) {
	t.Helper()
	s := threatIDSRotationRootFixture(t)
	state := "MainPID=0\nActiveState=inactive\n"
	s.Config.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name != "/usr/bin/systemctl" || strings.Join(args, " ") != "show "+threatIDSService+" --property=ActiveState,MainPID" {
			t.Fatal("cold recovery mutated services", name, args)
		}
		return state, nil
	}
	account := threatIDSAccount{Format: 1, UID: 800, GID: 801}
	if err := s.prepareThreatIDSLogs(account); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.systemPath("/proc"), 0700); err != nil {
		t.Fatal(err)
	}
	live := s.systemPath("/var/lib/panel-network-ids/logs/eve.json")
	data := []byte(threatEVEFixture("2026-10-09T02:00:00Z", 1, 1001) + "\n")
	if err := os.WriteFile(live, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(live, int(account.UID), int(account.GID)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(live)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	p := &threatIDSRotationPending{ID: core.ID(), At: core.Now(), Device: uint64(st.Dev), Inode: st.Ino, UID: account.UID, GID: account.GID, Revision: 1, RuntimeSHA: core.Hash("runtime"), UnitSHA: core.Hash("unit")}
	v := threatIDSRotation{Format: 1, Archives: []threatIDSArchive{}, Retired: []threatIDSArchive{}, Pending: p}
	if err := s.writeThreatIDSRotation(v); err != nil {
		t.Fatal(err)
	}
	archive := s.systemPath("/var/lib/panel-network-ids/history/eve-" + p.ID + ".json")
	return s, v, account, live, archive, &state
}

func TestThreatIDSRotationColdRecoveryBeforeRenamePreservesActualOutput(t *testing.T) {
	s, v, account, live, archive, _ := threatIDSColdRotationFixture(t)
	original, _ := os.ReadFile(live)
	if err := s.threatIDSStartOutputReady(); err == nil {
		t.Fatal("startup ignored pending rotation")
	}
	recovered, err := s.recoverThreatIDSStoppedRotation(context.Background(), v, account)
	if err != nil || recovered.Pending != nil || len(recovered.Archives) != 0 {
		t.Fatal(recovered, err)
	}
	actual, _ := os.ReadFile(live)
	if string(original) != string(actual) {
		t.Fatal("before-rename cold recovery rewrote native output")
	}
	if _, err := os.Lstat(archive); !os.IsNotExist(err) {
		t.Fatal("before-rename recovery created an archive")
	}
	if err := s.threatIDSStartOutputReady(); err != nil {
		t.Fatal(err)
	}
}

func TestThreatIDSRotationColdRecoveryAfterRenameRequiresStoppedAndDetached(t *testing.T) {
	s, v, account, live, archive, state := threatIDSColdRotationFixture(t)
	if err := os.Rename(live, archive); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.threatIDSRotationPath())
	*state = "MainPID=42\nActiveState=active\n"
	if _, err := s.recoverThreatIDSStoppedRotation(context.Background(), v, account); err == nil {
		t.Fatal("running capture accepted as cold recovery")
	}
	*state = "MainPID=0\nActiveState=inactive\n"
	proc := s.systemPath("/proc/42")
	if err := os.MkdirAll(filepath.Join(proc, "fd"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(proc, int(account.UID), int(account.GID)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "status"), []byte("Uid:\t800\t800\t800\t800\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Non-dumpable processes can expose root-owned proc entries. The kernel
	// UID fields, not this directory's ownership, must select their descriptors.
	if err := os.Chown(proc, 0, 0); err != nil {
		t.Fatal(err)
	}
	fd := filepath.Join(proc, "fd/3")
	if err := os.Symlink(archive, fd); err != nil {
		t.Fatal(err)
	}
	if _, err := s.recoverThreatIDSStoppedRotation(context.Background(), v, account); err == nil {
		t.Fatal("account's old output descriptor ignored")
	}
	actual, _ := os.ReadFile(s.threatIDSRotationPath())
	info, _ := os.Lstat(archive)
	if string(actual) != string(before) || info.Sys().(*syscall.Stat_t).Uid != account.UID {
		t.Fatal("failed closed recovery changed journal or ownership")
	}
	if err := os.Remove(fd); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.recoverThreatIDSStoppedRotation(context.Background(), v, account)
	if err != nil || recovered.Pending != nil || len(recovered.Archives) != 1 {
		t.Fatal(recovered, err)
	}
	if _, err := s.threatIDSArchiveFile(recovered.Archives[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(live); !os.IsNotExist(err) {
		t.Fatal("cold recovery created active output or started capture")
	}
	if err := s.threatIDSStartOutputReady(); err != nil {
		t.Fatal(err)
	}
}

func TestThreatIDSRotationColdRecoveryRefusesMissingChangedOrUnknownFiles(t *testing.T) {
	for _, kind := range []string{"missing-live", "changed-live", "unknown-history", "missing-sealed", "unknown-new-live", "unknown-stopped-state", "account-change"} {
		t.Run(kind, func(t *testing.T) {
			s, v, account, live, archive, state := threatIDSColdRotationFixture(t)
			switch kind {
			case "missing-live":
				if err := os.Rename(live, live+".retained-fixture"); err != nil {
					t.Fatal(err)
				}
			case "changed-live":
				if err := os.Rename(live, live+".retained-fixture"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(live, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(live, int(account.UID), int(account.GID)); err != nil {
					t.Fatal(err)
				}
			case "unknown-history":
				if err := os.WriteFile(filepath.Join(filepath.Dir(archive), "foreign.json"), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-sealed":
				v.Pending.Sealed = &threatIDSArchive{ID: v.Pending.ID, At: v.Pending.At, Device: v.Pending.Device, Inode: v.Pending.Inode, SHA: core.Hash("missing"), Bytes: 7}
				if err := s.writeThreatIDSRotation(v); err != nil {
					t.Fatal(err)
				}
			case "unknown-new-live":
				if err := os.Rename(live, archive); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(live, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown-stopped-state":
				*state = "ActiveState=failed\nMainPID=0\n"
			case "account-change":
				account.GID++
			}
			before, _ := os.ReadFile(s.threatIDSRotationPath())
			if _, err := s.recoverThreatIDSStoppedRotation(context.Background(), v, account); err == nil {
				t.Fatal("foreign/unknown cold set recovered", kind)
			}
			actual, _ := os.ReadFile(s.threatIDSRotationPath())
			if string(actual) != string(before) {
				t.Fatal("failed cold recovery rewrote intent", kind)
			}
		})
	}
}

func TestThreatIDSRotationPendingSourceBindingAndStartupGate(t *testing.T) {
	s, v, account, _, _, _ := threatIDSColdRotationFixture(t)
	in := threatIDSConfig{Revision: 1, Interface: "lo", HomeNetworks: []string{"127.0.0.1/32"}}
	unit := threatIDSUnitRecord{UnitSHA: v.Pending.UnitSHA}
	if err := threatIDSRotationBinding(v.Pending, in, account, unit, v.Pending.RuntimeSHA); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"revision", "uid", "gid", "unit", "runtime"} {
		p := *v.Pending
		switch field {
		case "revision":
			p.Revision++
		case "uid":
			p.UID++
		case "gid":
			p.GID++
		case "unit":
			p.UnitSHA = core.Hash("foreign")
		case "runtime":
			p.RuntimeSHA = core.Hash("foreign")
		}
		if threatIDSRotationBinding(&p, in, account, unit, v.Pending.RuntimeSHA) == nil {
			t.Fatal("changed source binding accepted", field)
		}
	}
	if err := os.WriteFile(s.threatIDSRotationPath(), []byte(`{"format":1,"format":1,"archives":[],"retired":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.threatIDSStartOutputReady(); err == nil {
		t.Fatal("startup accepted malformed private output journal")
	}
}
