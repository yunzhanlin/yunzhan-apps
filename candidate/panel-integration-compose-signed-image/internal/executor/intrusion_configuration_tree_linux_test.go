//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func intrusionTreeFixture(t *testing.T) (*Service, string) {
	t.Helper()
	s := newHardeningFixture(t).s
	base := s.systemPath("/etc/fail2ban")
	if err := os.MkdirAll(filepath.Join(base, "jail.d"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"jail.conf": []byte("[DEFAULT]\n"), "empty.local": {}, "jail.d/panel-intrusion.local": []byte("original-managed-jail\n")} {
		if err := os.WriteFile(filepath.Join(base, name), raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	return s, base
}

func TestIntrusionJournalConfigurationBaselineCannotAdoptPartialOrForeignEvidence(t *testing.T) {
	for name, change := range map[string]func(*intrusionJournalPlan){
		"missing-baseline": func(p *intrusionJournalPlan) { p.ConfigurationBefore = intrusionConfigurationTree{} },
		"missing-parent":   func(p *intrusionJournalPlan) { delete(p.ConfigurationBefore.Entries, "jail.d") },
		"missing-jail":     func(p *intrusionJournalPlan) { delete(p.ConfigurationBefore.Entries, "jail.d/panel-intrusion.local") },
		"wrong-total":      func(p *intrusionJournalPlan) { p.ConfigurationBefore.Bytes++ },
		"jail-digest": func(p *intrusionJournalPlan) {
			v := p.ConfigurationBefore.Entries["jail.d/panel-intrusion.local"]
			v.SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			p.ConfigurationBefore.Entries["jail.d/panel-intrusion.local"] = v
		},
		"foreign-owner": func(p *intrusionJournalPlan) {
			v := p.ConfigurationBefore.Entries["."]
			v.UID++
			p.ConfigurationBefore.Entries["."] = v
		},
		"mode-bits": func(p *intrusionJournalPlan) {
			v := p.ConfigurationBefore.Entries["."]
			v.Mode |= uint32(os.ModeAppend)
			p.ConfigurationBefore.Entries["."] = v
		},
		"absolute-name": func(p *intrusionJournalPlan) {
			p.ConfigurationBefore.Entries["/etc/passwd"] = p.ConfigurationBefore.Entries["jail.d/panel-intrusion.local"]
		},
		"outside-name": func(p *intrusionJournalPlan) {
			p.ConfigurationBefore.Entries["../passwd"] = p.ConfigurationBefore.Entries["jail.d/panel-intrusion.local"]
		},
		"bare-parent": func(p *intrusionJournalPlan) {
			v := p.ConfigurationBefore.Entries["jail.d/panel-intrusion.local"]
			v.Inode = 90
			p.ConfigurationBefore.Entries[".."] = v
			p.ConfigurationBefore.Bytes += v.Size
		},
		"invalid-utf8": func(p *intrusionJournalPlan) {
			v := p.ConfigurationBefore.Entries["jail.d/panel-intrusion.local"]
			v.Inode = 90
			p.ConfigurationBefore.Entries[string([]byte{0xff})] = v
			p.ConfigurationBefore.Bytes += v.Size
		},
		"repeated-identity": func(p *intrusionJournalPlan) {
			v := p.ConfigurationBefore.Entries["jail.d"]
			v.Inode = p.ConfigurationBefore.Entries["."].Inode
			p.ConfigurationBefore.Entries["jail.d"] = v
		},
		"custom-original-action": func(p *intrusionJournalPlan) { p.ActionBefore.Values["actionreload"] = "stop all" },
		"original-process":       func(p *intrusionJournalPlan) { p.ProcessBefore = "0123" },
		"original-backend":       func(p *intrusionJournalPlan) { p.JournalMatchBefore = "_COMM=other" },
	} {
		t.Run(name, func(t *testing.T) {
			p := intrusionJournalFixture(t)
			change(&p)
			before, _ := json.Marshal(p)
			if err := intrusionJournalValidate(p); err == nil {
				t.Fatal("unqualified source evidence accepted")
			}
			after, _ := json.Marshal(p)
			if string(before) != string(after) {
				t.Fatal("false source evidence repaired")
			}
		})
	}
}

func TestIntrusionConfigurationTreeReadsEmptyAndOrdinaryFilesWithoutRepair(t *testing.T) {
	s, base := intrusionTreeFixture(t)
	before, err := s.readIntrusionConfigurationTree(context.Background())
	if err != nil || len(before.Entries) != 5 || before.Entries["empty.local"].Size != 0 || len(before.Entries["empty.local"].SHA256) != 64 {
		t.Fatal(before, err)
	}
	after, err := s.readIntrusionConfigurationTree(context.Background())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("unchanged tree identity lost", err)
	}
	info, err := os.Lstat(base)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("root mode repaired", err)
	}
}

func TestIntrusionConfigurationTreeAllowsOnlyExactOwnedJailReplacement(t *testing.T) {
	s, base := intrusionTreeFixture(t)
	before, err := s.readIntrusionConfigurationTree(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("derived-managed-jail\n")
	name := filepath.Join(base, "jail.d/panel-intrusion.local")
	if err := atomicWrite(name, data, 0644); err != nil {
		t.Fatal(err)
	}
	after, err := s.readIntrusionConfigurationTree(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	owner := &fileOwner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	expected := hardeningJournalFile{Exists: true, Mode: 0644, Owner: owner, Data: data}
	if err := intrusionConfigurationTreeAfterJail(before, after, expected); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"wrong-target", "missing-owned", "other-config", "extra-name", "directory-identity", "same-content-replacement"} {
		t.Run(kind, func(t *testing.T) {
			changed := intrusionConfigurationTree{Entries: map[string]intrusionConfigurationEntry{}, Bytes: after.Bytes}
			for k, v := range after.Entries {
				changed.Entries[k] = v
			}
			target := expected
			switch kind {
			case "wrong-target":
				target.Data = []byte("foreign\n")
			case "missing-owned":
				delete(changed.Entries, "jail.d/panel-intrusion.local")
			case "other-config":
				v := changed.Entries["jail.conf"]
				v.SHA256 = "foreign"
				changed.Entries["jail.conf"] = v
			case "extra-name":
				changed.Entries["new.local"] = changed.Entries["empty.local"]
			case "directory-identity":
				v := changed.Entries["jail.d"]
				v.Inode++
				changed.Entries["jail.d"] = v
			case "same-content-replacement":
				v := changed.Entries["jail.conf"]
				v.Inode++
				changed.Entries["jail.conf"] = v
			}
			if err := intrusionConfigurationTreeAfterJail(before, changed, target); err == nil {
				t.Fatal("non-owned or wrong mutation accepted")
			}
		})
	}
}

func TestIntrusionConfigurationTreeRefusesLinksUnsafePermissionsAndNonRegularEntries(t *testing.T) {
	for _, kind := range []string{"symlink", "dangling-symlink", "hardlink", "fifo", "writable-file", "writable-directory", "setuid-file", "oversized-file"} {
		t.Run(kind, func(t *testing.T) {
			s, base := intrusionTreeFixture(t)
			file := filepath.Join(base, "untrusted.local")
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink("jail.conf", file)
			case "dangling-symlink":
				err = os.Symlink("missing", file)
			case "hardlink":
				err = os.Link(filepath.Join(base, "jail.conf"), file)
			case "fifo":
				err = unix.Mkfifo(file, 0600)
			case "writable-file":
				err = os.WriteFile(file, []byte("foreign"), 0644)
				if err == nil {
					err = os.Chmod(file, 0666)
				}
			case "writable-directory":
				err = os.Chmod(filepath.Join(base, "jail.d"), 0777)
			case "setuid-file":
				err = os.WriteFile(file, []byte("foreign"), 0644)
				if err == nil {
					err = os.Chmod(file, os.ModeSetuid|0755)
				}
			case "oversized-file":
				err = os.WriteFile(file, make([]byte, intrusionConfigurationFileBytes+1), 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(file)
			if kind == "writable-directory" {
				before, err = os.Lstat(filepath.Join(base, "jail.d"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.readIntrusionConfigurationTree(context.Background()); err == nil {
				t.Fatal("unsafe tree accepted")
			}
			after, err := os.Lstat(file)
			if kind == "writable-directory" {
				after, err = os.Lstat(filepath.Join(base, "jail.d"))
			}
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("unsafe entry repaired or deleted", err)
			}
		})
	}
}

func TestIntrusionConfigurationTreeHasFixedDirectoryDepthAndEntryBudgets(t *testing.T) {
	for _, kind := range []string{"depth", "entries"} {
		t.Run(kind, func(t *testing.T) {
			s, base := intrusionTreeFixture(t)
			if kind == "depth" {
				name := base
				for i := 0; i < 10; i++ {
					name = filepath.Join(name, "nested")
				}
				if err := os.MkdirAll(name, 0755); err != nil {
					t.Fatal(err)
				}
			} else {
				for i := 0; i < intrusionConfigurationEntries; i++ {
					if err := os.WriteFile(filepath.Join(base, fmt.Sprintf("fixture-%03d.local", i)), nil, 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := s.readIntrusionConfigurationTree(context.Background()); err == nil {
				t.Fatal("unbounded tree accepted")
			}
		})
	}
}

func TestIntrusionConfigurationTreeCancelledReadDoesNotCreateAuthority(t *testing.T) {
	s, base := intrusionTreeFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.readIntrusionConfigurationTree(ctx); err == nil {
		t.Fatal("cancelled tree accepted")
	}
	if _, err := os.Lstat(filepath.Join(base, "intrusion-configuration.lock")); !os.IsNotExist(err) {
		t.Fatal("readonly inventory created a lock", err)
	}
}
