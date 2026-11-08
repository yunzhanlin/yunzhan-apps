package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountryPublisherStageExclusivePrivateAndNeverRepairsExistingTargets(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "new-country-data")
	s, err := openCountryPublisherStage(target)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Current(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(target); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal(info, err)
	}
	file := filepath.Join(target, "retained-original")
	if err := os.WriteFile(file, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if second, err := openCountryPublisherStage(target); err == nil {
		second.Close()
		t.Fatal("existing directory overwritten or adopted")
	}
	if raw, err := os.ReadFile(file); err != nil || string(raw) != "original\n" {
		t.Fatal("existing staging data repaired", err)
	}
	linked := filepath.Join(parent, "linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	if second, err := openCountryPublisherStage(linked); err == nil {
		second.Close()
		t.Fatal("linked output adopted")
	}
	if second, err := openCountryPublisherStage(filepath.Join(linked, "child")); err == nil {
		second.Close()
		t.Fatal("linked parent adopted")
	}
}

func TestCountryPublisherStageDetectsNamedDirectoryAndParentReplacement(t *testing.T) {
	for _, kind := range []string{"directory", "parent", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			parent := filepath.Join(base, "publisher-parent")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(parent, "new-country-data")
			s, err := openCountryPublisherStage(target)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			switch kind {
			case "directory":
				if err := os.Rename(target, target+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			case "parent":
				if err := os.Rename(parent, parent+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(target, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Current(); err == nil {
				t.Fatal("replacement or permission change accepted for publication")
			}
		})
	}
}
