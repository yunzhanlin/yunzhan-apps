//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestThreatIDSDebianKeyringOnlyKnownCanonicalDistroLink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires real root file ownership fixture")
	}
	root := t.TempDir()
	s := New(Config{SystemRoot: root})
	dir := s.systemPath("/usr/share/keyrings")
	if err := s.wafOwnedDirectory(dir, true); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "debian-archive-keyring.gpg")
	canonical := filepath.Join(dir, "debian-archive-keyring.pgp")
	if err := os.WriteFile(canonical, []byte("private fixture canonical key"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/usr/share/keyrings/debian-archive-keyring.pgp", "../keyrings/debian-archive-keyring.pgp", "unknown.pgp"} {
		if err := os.Symlink(target, legacy); err != nil {
			t.Fatal(err)
		}
		if _, err := s.threatIDSDebianKeyringPath(); err == nil {
			t.Fatal("unknown key link followed", target)
		}
		if err := os.Remove(legacy); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("debian-archive-keyring.pgp", legacy); err != nil {
		t.Fatal(err)
	}
	// The production native key link is root:root; our root:panel test process
	// must set the fixture link's exact distro identity, not relax the policy.
	if err := os.Lchown(legacy, 0, 0); err != nil {
		t.Fatal(err)
	}
	if p, err := s.threatIDSDebianKeyringPath(); err != nil || p != canonical {
		t.Fatal(p, err)
	}
	if err := os.Chmod(canonical, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := s.threatIDSDebianKeyringPath(); err == nil {
		t.Fatal("writable canonical keyring accepted")
	}
}
