//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"local/panel/internal/core"
)

func intrusionRemovalCopyFixture(t *testing.T) (*Service, *os.File, intrusionConfigurationTree, hardeningJournalFile) {
	t.Helper()
	s, base := intrusionTreeFixture(t)
	for _, name := range []string{"action.d", "filter.d"} {
		if err := os.Mkdir(filepath.Join(base, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for name, raw := range map[string]string{"action.d/nftables.conf": "[Definition]\n", "filter.d/sshd.conf": "[Definition]\nfailregex = ^<HOST> failed$\n", "jail.d/custom.local": "# independent nonowned fixture\n"} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(raw), 0644); err != nil {
			t.Fatal(err)
		}
	}
	tree, err := s.readIntrusionConfigurationTree(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	jail, err := s.intrusionConfigObservation()
	if err != nil {
		t.Fatal(err)
	}
	lock, err := s.intrusionMutationLock()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close() })
	return s, lock, tree, hardeningJournalFromBackup(jail)
}

func TestIntrusionRemovalCopyKeepsWholeSourceAndOmitsOnlyOwnedJail(t *testing.T) {
	for _, mode := range []os.FileMode{0700, 0750, 0755} {
		t.Run(map[os.FileMode]string{0700: "private", 0750: "shared-group", 0755: "shared-read"}[mode], func(t *testing.T) {
			s, lock, before, jail := intrusionRemovalCopyFixture(t)
			if err := os.Chmod(s.Config.SecurityDir, mode); err != nil {
				t.Fatal(err)
			}
			securityBefore, err := os.Lstat(s.Config.SecurityDir)
			if err != nil {
				t.Fatal(err)
			}
			copy, err := s.newIntrusionRemovalCopy(context.Background(), lock, before, jail)
			if err != nil {
				t.Fatal(err)
			}
			stage := copy.root.Name()
			for name, entry := range before.Entries {
				if name == "jail.d/panel-intrusion.local" {
					if _, err := copy.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("owned Jail was copied", err)
					}
					continue
				}
				actual, exists := copy.tree.Entries[name]
				if !exists || actual.Kind != entry.Kind {
					t.Fatal("nonowned source entry omitted", name)
				}
				if entry.Kind == "directory" {
					if actual.Mode != uint32(os.ModeDir|0700) {
						t.Fatal("copy directory not private", name)
					}
				} else {
					got, data, err := intrusionConfigurationReadFileData(copy.root, name)
					original, readErr := os.ReadFile(filepath.Join(s.systemPath("/etc/fail2ban"), filepath.FromSlash(name)))
					if err != nil || readErr != nil || !bytes.Equal(data, original) || got.Mode != 0600 || got.SHA256 != entry.SHA256 || got.Size != entry.Size {
						t.Fatal("copy bytes, empty file or private mode not retained", name, err, readErr)
					}
				}
			}
			if err := s.closeIntrusionRemovalCopy(context.Background(), lock, copy); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("known new replica not removed", err)
			}
			after, err := s.readIntrusionConfigurationTree(context.Background())
			securityAfter, securityErr := os.Lstat(s.Config.SecurityDir)
			if err != nil || securityErr != nil || !reflect.DeepEqual(before, after) || !os.SameFile(securityBefore, securityAfter) || securityAfter.Mode() != securityBefore.Mode() {
				t.Fatal("source tree or shared security directory was repaired", err, securityErr)
			}
			for _, path := range s.intrusionJournalPaths()[1:] {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("read-only replica created an installation record", err)
				}
			}
		})
	}
}

func TestIntrusionRemovalCopyRejectsUnknownSourceCacheAndOriginalAuthority(t *testing.T) {
	for _, kind := range []string{"source-changed", "source-link", "record-unknown", "record-partial", "missing-jail", "wrong-jail", "unsafe-source", "cancelled", "no-lock", "cache-public", "cache-readonly", "cache-file", "cache-symlink", "full-cache", "unknown-cache-entry"} {
		t.Run(kind, func(t *testing.T) {
			s, lock, before, jail := intrusionRemovalCopyFixture(t)
			cachePath := filepath.Join(s.Config.SecurityDir, intrusionRemovalCacheName)
			ctx := context.Background()
			if kind == "full-cache" || kind == "unknown-cache-entry" {
				if err := os.Mkdir(cachePath, 0700); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "source-changed":
				if err := os.WriteFile(s.systemPath("/etc/fail2ban/jail.conf"), []byte("changed source\n"), 0644); err != nil {
					t.Fatal(err)
				}
			case "source-link":
				file := s.systemPath("/etc/fail2ban/empty.local")
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("jail.conf", file); err != nil {
					t.Fatal(err)
				}
			case "record-unknown":
				before.Entries["../foreign"] = before.Entries["empty.local"]
			case "record-partial":
				delete(before.Entries, "jail.d")
			case "missing-jail":
				jail = hardeningJournalFile{}
			case "wrong-jail":
				jail.Data = []byte("foreign")
			case "unsafe-source":
				if err := os.Chmod(s.systemPath("/etc/fail2ban"), 0777); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "no-lock":
				lock = nil
			case "cache-public", "cache-readonly":
				mode := os.FileMode(0755)
				if kind == "cache-readonly" {
					mode = 0500 // Root's ability to write/read is NOT a valid mode.
				}
				if err := os.Mkdir(cachePath, mode); err != nil {
					t.Fatal(err)
				}
			case "cache-file":
				if err := os.WriteFile(cachePath, []byte("retain original"), 0600); err != nil {
					t.Fatal(err)
				}
			case "cache-symlink":
				if err := os.Symlink(s.systemPath("/etc/fail2ban"), cachePath); err != nil {
					t.Fatal(err)
				}
			case "full-cache":
				for i := 0; i < 16; i++ {
					if err := os.Mkdir(filepath.Join(cachePath, "candidate-"+core.ID()), 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "unknown-cache-entry":
				if err := os.WriteFile(filepath.Join(cachePath, "unknown"), []byte("retained evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cacheBefore, existed := os.Lstat(cachePath)
			if copy, err := s.newIntrusionRemovalCopy(ctx, lock, before, jail); err == nil || copy != nil {
				t.Fatal("unknown source/cache became a candidate", err)
			}
			cacheAfter, afterErr := os.Lstat(cachePath)
			if errors.Is(existed, os.ErrNotExist) {
				if !errors.Is(afterErr, os.ErrNotExist) {
					t.Fatal("refused preflight created cache authority", afterErr)
				}
			} else if existed != nil || afterErr != nil || !os.SameFile(cacheBefore, cacheAfter) || cacheBefore.Mode() != cacheAfter.Mode() {
				t.Fatal("unknown original cache replaced or repaired", existed, afterErr)
			}
		})
	}
}

func TestIntrusionRemovalCopyCleanupRetainsForeignChangesAndReplacements(t *testing.T) {
	for _, kind := range []string{"foreign-file", "replaced-file", "edited-file", "symlink", "foreign-permissions", "stage-renamed", "cache-replaced", "unbound-lock", "cancelled", "stage-readonly"} {
		t.Run(kind, func(t *testing.T) {
			s, lock, before, jail := intrusionRemovalCopyFixture(t)
			copy, err := s.newIntrusionRemovalCopy(context.Background(), lock, before, jail)
			if err != nil {
				t.Fatal(err)
			}
			stage := copy.root.Name()
			retained := stage
			ctx := context.Background()
			switch kind {
			case "foreign-file":
				if err := os.WriteFile(filepath.Join(stage, "foreign.local"), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			case "replaced-file":
				if err := atomicWrite(filepath.Join(stage, "jail.conf"), []byte("[DEFAULT]\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "edited-file":
				if err := os.WriteFile(filepath.Join(stage, "jail.conf"), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				file := filepath.Join(stage, "empty.local")
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("jail.conf", file); err != nil {
					t.Fatal(err)
				}
			case "foreign-permissions":
				if err := os.Chmod(filepath.Join(stage, "jail.conf"), 0644); err != nil {
					t.Fatal(err)
				}
			case "stage-renamed":
				retained = stage + "-detached"
				if err := os.Rename(stage, retained); err != nil {
					t.Fatal(err)
				}
			case "cache-replaced":
				cache := filepath.Dir(stage)
				old := cache + "-detached"
				if err := os.Rename(cache, old); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(cache, 0700); err != nil {
					t.Fatal(err)
				}
				retained = filepath.Join(old, copy.name)
			case "unbound-lock":
				lock.Close()
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "stage-readonly":
				if err := os.Chmod(stage, 0500); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.closeIntrusionRemovalCopy(ctx, lock, copy); err == nil {
				t.Fatal("foreign copy state was silently cleaned or repaired")
			}
			if _, err := os.Lstat(retained); err != nil {
				t.Fatal("original changed copy was deleted", err)
			}
			after, err := s.readIntrusionConfigurationTree(context.Background())
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("copy cleanup changed installed source configuration", err)
			}
		})
	}
}
