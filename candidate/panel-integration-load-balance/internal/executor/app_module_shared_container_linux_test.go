//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// The shared directory contains public application IDs. All application leaves
// and records keep their existing private mode and immutable handle checks.
func TestModuleSharedContainerPreservesInstalledAndKnownAbsentLeaves(t *testing.T) {
	for _, mode := range []os.FileMode{0700, 0711, 0750, 0755} {
		t.Run(mode.String(), func(t *testing.T) {
			s, record := moduleRecordFixture(t)
			// Preparation is confined to this declared private fixture root;
			// the production parent guard must keep refusing writable /tmp.
			s.Config.SystemRoot = filepath.Dir(s.Config.SecurityDir)
			container := filepath.Dir(filepath.Dir(record))
			if err := os.Chmod(container, mode); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(container)
			if err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			if status := s.appModuleStatus(context.Background(), "task-manager"); status.StateUnknown || !status.Installed || !status.Healthy {
				t.Fatal("Root-controlled shared parent hid a private installed app", status)
			}
			if status := s.appModuleStatus(context.Background(), "website-statistics-v2"); status.StateUnknown || status.Installed {
				t.Fatal("missing sibling was not a known absence", status)
			}
			if _, err := s.moduleInstalledRecord("website-statistics-v2"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if err := s.prepareStatisticsPrivateDirectory(); err != nil {
				t.Fatal("explicit statistics preparation rejected shared parent", err)
			}
			after, err := os.Lstat(container)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("shared parent was replaced or chmodded", err)
			}
			old, ok := before.Sys().(*syscall.Stat_t)
			current, currentOK := after.Sys().(*syscall.Stat_t)
			if !ok || !currentOK || old.Uid != current.Uid || old.Gid != current.Gid {
				t.Fatal("shared parent ownership changed")
			}
			private, err := os.Lstat(s.moduleDir("website-statistics-v2"))
			if err != nil || !moduleRecordInfo(private, true, false) {
				t.Fatal("new statistics leaf is not private", err)
			}
			actual, err := os.ReadFile(record)
			if err != nil || string(actual) != string(original) {
				t.Fatal("sibling installed record changed", err)
			}
		})
	}
}

func TestModuleSharedContainerStillPinsParentAndPrivateLeaf(t *testing.T) {
	s, record := moduleRecordFixture(t)
	container := filepath.Dir(filepath.Dir(record))
	if err := os.Chmod(container, 0755); err != nil {
		t.Fatal(err)
	}
	directory, err := s.moduleRecordDirectory("task-manager")
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if !directory.current() {
		t.Fatal("fresh shared-parent handle is not current")
	}
	if err := os.Rename(container, container+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(container, 0755); err != nil {
		t.Fatal(err)
	}
	if directory.current() {
		t.Fatal("replaced shared parent retained authority to detached private record")
	}
	if err := os.Rename(container, container+"-replacement"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(container+"-original", container); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(record), 0755); err != nil {
		t.Fatal(err)
	}
	if directory.current() {
		t.Fatal("public private-app leaf was accepted")
	}
	if status := s.appModuleStatus(context.Background(), "task-manager"); !status.StateUnknown || status.Installed {
		t.Fatal("public app leaf was reported as installed", status)
	}
}

func TestModuleSharedContainerRetrospectiveKeepsPrivateRecords(t *testing.T) {
	for _, name := range []string{"history.json", "last-report.json"} {
		s, record := retrospectiveFixture(t, name)
		if err := os.Chmod(filepath.Dir(filepath.Dir(record)), 0755); err != nil {
			t.Fatal(err)
		}
		before, err := os.Lstat(record)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		var report any
		if err := s.moduleRetrospectiveRecord("task-manager", name, &report); err != nil || report == nil {
			t.Fatal("shared parent hid a complete private retrospective record", name, err)
		}
		after, err := os.Lstat(record)
		actual, readErr := os.ReadFile(record)
		if err != nil || readErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.ModTime() != after.ModTime() || string(raw) != string(actual) {
			t.Fatal("read-only observation changed private retrospective record", name, err, readErr)
		}
	}
}

func TestModuleSharedContainerRejectsForeignWritableOrAliasedParent(t *testing.T) {
	for _, kind := range []string{"group-write", "other-write", "setgid", "sticky", "foreign-owner", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			s, record := moduleRecordFixture(t)
			s.Config.SystemRoot = filepath.Dir(s.Config.SecurityDir)
			container := filepath.Dir(filepath.Dir(record))
			raw, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "group-write":
				err = os.Chmod(container, 0770)
			case "other-write":
				err = os.Chmod(container, 0702)
			case "setgid":
				err = os.Chmod(container, 0755|os.ModeSetgid)
			case "sticky":
				err = os.Chmod(container, 0755|os.ModeSticky)
			case "foreign-owner":
				if os.Geteuid() != 0 {
					t.Skip("actual Root-owned fixture required")
				}
				err = os.Chown(container, 1, -1)
			case "symlink":
				if err = os.Rename(container, container+"-retained"); err == nil {
					err = os.Symlink(container+"-retained", container)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if status := s.appModuleStatus(context.Background(), "task-manager"); !status.StateUnknown || status.Installed {
				t.Fatal("unsafe shared parent was trusted", kind, status)
			}
			if err := s.prepareStatisticsPrivateDirectory(); err == nil {
				t.Fatal("statistics preparation adopted or repaired unsafe parent", kind)
			}
			actual, err := os.ReadFile(record)
			if err != nil || string(actual) != string(raw) {
				t.Fatal("refusal changed original private sibling", kind, err)
			}
		})
	}
}

func TestModuleSharedContainerNativeUnprivilegedAccessStopsAtPrivateLeaf(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Linux Root fixture and credential drop required")
	}
	base, err := os.MkdirTemp("/tmp", "panel-module-shared-privacy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	security := filepath.Join(base, "security")
	container := filepath.Join(security, "modules")
	leaf := filepath.Join(container, "task-manager")
	for _, name := range []string{base, security, container, leaf} {
		if err := os.MkdirAll(name, 0755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0755)
		if name == leaf {
			mode = 0700
		}
		if err := os.Chmod(name, mode); err != nil {
			t.Fatal(err)
		}
	}
	// The traversable container may inherit a service group. Membership must
	// not grant access to any Root-private application's leaf or records.
	if err := os.Chown(container, 0, 65534); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(leaf, "installed.json")
	original := []byte(`{"id":"task-manager","version":"1.2.0","settings":{}}`)
	if err := os.WriteFile(record, original, 0600); err != nil {
		t.Fatal(err)
	}
	s := &Service{Config: Config{SecurityDir: security}}
	if _, err := s.moduleInstalledRecord("task-manager"); err != nil {
		t.Fatal("Root cannot read its private record through shared parent", err)
	}
	command := exec.Command("/bin/sh", "-c", `[ -r "$1" ] && [ -x "$1" ] && [ ! -r "$2" ] && [ ! -x "$2" ] && ! /bin/cat "$3" >/dev/null 2>&1`, "module-private-access", container, leaf, record)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatal("unprivileged process did not traverse public parent and stop at private leaf", string(output), err)
	}
	actual, err := os.ReadFile(record)
	if err != nil || string(actual) != string(original) {
		t.Fatal("native read-only privacy check changed record", err)
	}
}

func TestModuleSharedContainerLedgerWritesKeepPrivateFiles(t *testing.T) {
	for _, mode := range []os.FileMode{0700, 0711, 0750, 0755} {
		t.Run(mode.String(), func(t *testing.T) {
			service, record := moduleRecordFixture(t)
			container := filepath.Dir(filepath.Dir(record))
			if err := os.Chmod(container, mode); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(container)
			if err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if err := service.appendModuleEvent("task-manager", "run", "manual", core.AppModuleInput{Password: "never-in-history"}, map[string]any{"secret": "never-in-result-history"}, nil); err != nil {
					t.Fatal("real history write rejected a Root-controlled shared parent", err)
				}
			}
			if err := service.writeModuleRetrospectiveRecord("task-manager", "last-report.json", map[string]any{"time": core.Now(), "action": "run", "result": map[string]any{"count": 2}}); err != nil {
				t.Fatal(err)
			}
			history, err := service.moduleHistory("task-manager", core.AppModuleInput{})
			if err != nil || history.(map[string]any)["total"] != 2 {
				t.Fatal(history, err)
			}
			for _, name := range []string{"installed.json", "history.sqlite", "history.json", "last-report.json"} {
				info, err := os.Lstat(filepath.Join(filepath.Dir(record), name))
				if err != nil || !moduleRecordInfo(info, false, false) {
					t.Fatal("history write exposed private record", name, err)
				}
			}
			after, err := os.Lstat(container)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("history writer replaced or chmodded shared parent", err)
			}
			current, err := os.ReadFile(record)
			if err != nil || string(current) != string(original) {
				t.Fatal("history writer changed installed identity", err)
			}
		})
	}
}

func TestModuleSharedContainerLedgerRefusesUnsafeAncestryBeforeCreatingFile(t *testing.T) {
	for _, kind := range []string{"public-leaf", "writable-container", "foreign-container", "symlink-container"} {
		t.Run(kind, func(t *testing.T) {
			service, record := moduleRecordFixture(t)
			container := filepath.Dir(filepath.Dir(record))
			original, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "public-leaf":
				err = os.Chmod(filepath.Dir(record), 0755)
			case "writable-container":
				err = os.Chmod(container, 0770)
			case "foreign-container":
				if os.Geteuid() != 0 {
					t.Skip("Root fixture required")
				}
				err = os.Chown(container, 1, -1)
			case "symlink-container":
				if err = os.Rename(container, container+"-original"); err == nil {
					err = os.Symlink(container+"-original", container)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			db, err := service.openModuleLedger(context.Background(), "task-manager")
			if db != nil {
				db.Close()
				t.Fatal("unsafe ledger opened")
			}
			if err == nil {
				t.Fatal("unsafe history ancestry accepted", kind)
			}
			if _, err := os.Lstat(filepath.Join(filepath.Dir(record), "history.sqlite")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal created or modified history", err)
			}
			current, err := os.ReadFile(record)
			if err != nil || string(current) != string(original) {
				t.Fatal("refusal changed original installed identity", err)
			}
		})
	}
}
