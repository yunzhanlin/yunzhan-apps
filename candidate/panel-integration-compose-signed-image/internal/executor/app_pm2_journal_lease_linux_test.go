//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPM2JournalLeaseSerializesDifferentServiceInstances(t *testing.T) {
	s, _, _ := pm2StateAppFixture(t)
	first, err := s.lockPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	path := filepath.Join(s.moduleDir("pm2-manager"), pm2ConfigurationJournalLock)
	before, err := os.Lstat(path)
	if err != nil || !moduleRecordInfo(before, false, false) || before.Size() != 0 {
		t.Fatalf("private lock not established: %v", err)
	}
	other := New(s.Config)
	if second, err := other.lockPM2ConfigurationJournal(); err == nil {
		second.Close()
		t.Fatal("another service instance acquired the held journal")
	}
	if !first.current() {
		t.Fatal("rejected contender changed original lock")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := other.lockPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || !second.current() {
		t.Fatal("release replaced or repaired original lock")
	}
}

func TestPM2JournalLeaseRejectsAndPreservesUnverifiableFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public-mode", "nonempty"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _ := pm2StateAppFixture(t)
			path := filepath.Join(s.moduleDir("pm2-manager"), pm2ConfigurationJournalLock)
			original := filepath.Join(t.TempDir(), "original")
			if err := os.WriteFile(original, []byte("retained original"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(original, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(original, path); err != nil {
					t.Fatal(err)
				}
			case "public-mode":
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "nonempty":
				if err := os.WriteFile(path, []byte("retain damaged record"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if lease, err := s.lockPM2ConfigurationJournal(); err == nil {
				lease.Close()
				t.Fatal("unverifiable original lock was accepted")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatal("failed lock attempt changed the original")
			}
			raw, err := os.ReadFile(original)
			if err != nil || string(raw) != "retained original" {
				t.Fatal("failed lock attempt changed the link target")
			}
		})
	}
}

func TestPM2JournalLeaseDetectsDetachedAndSubstitutedParent(t *testing.T) {
	s, _, _ := pm2StateAppFixture(t)
	lease, err := s.lockPM2ConfigurationJournal()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	parent := s.moduleDir("pm2-manager")
	if err := os.Rename(parent, parent+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(parent, pm2ConfigurationJournalLock)
	if err := os.WriteFile(replacement, []byte("retained replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if lease.current() {
		t.Fatal("detached held directory was reported as current")
	}
	if _, err := os.Stat(filepath.Join(parent+"-retained", pm2ConfigurationJournalLock)); err != nil {
		t.Fatal("original detached lock was not retained")
	}
	raw, err := os.ReadFile(replacement)
	if err != nil || string(raw) != "retained replacement" {
		t.Fatal("replacement was changed")
	}
}
