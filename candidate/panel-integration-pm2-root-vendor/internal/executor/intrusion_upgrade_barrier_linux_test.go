//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func intrusionUpgradeFixture(t *testing.T) (string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("actual root-owned upgrade barrier fixture required")
	}
	root := newHardeningFixture(t).s.Config.SystemRoot
	anchor := filepath.Join(root, "etc/panel/security-apps")
	if err := os.MkdirAll(anchor, 0750); err != nil {
		t.Fatal(err)
	}
	return root, anchor
}

func intrusionUpgradeInventory(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(name)
		if err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		raw, err := json.Marshal([]any{st.Dev, st.Ino, st.Mode, st.Uid, st.Gid, st.Nlink, st.Size, st.Mtim, st.Ctim})
		if err != nil {
			return err
		}
		out[name] = string(raw)
		// In particular, NEVER read a FIFO, symlink or device as a record.
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			out[name] += "|" + core.Hash(string(data))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIntrusionUpgradePendingPresenceBlocksEveryObjectWithoutReadingOrRepair(t *testing.T) {
	for _, kind := range []string{"valid-original", "partial", "directory", "symlink", "hardlink", "fifo", "public"} {
		t.Run(kind, func(t *testing.T) {
			root, anchor := intrusionUpgradeFixture(t)
			marker := filepath.Join(anchor, intrusionPendingName)
			foreign := filepath.Join(root, "private-fixture-original")
			if err := os.WriteFile(foreign, []byte("foreign fixture\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "valid-original":
				p := intrusionJournalFixture(t)
				raw, encodeErr := intrusionJournalEncode(p)
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				err = os.WriteFile(marker, raw, 0600)
			case "partial":
				err = os.WriteFile(marker, []byte("{"), 0600)
			case "directory":
				err = os.Mkdir(marker, 0700)
			case "symlink":
				err = os.Symlink(foreign, marker)
			case "hardlink":
				err = os.Link(foreign, marker)
			case "fifo":
				err = unix.Mkfifo(marker, 0600)
			case "public":
				err = os.WriteFile(marker, []byte("{}\n"), 0666)
				if err == nil {
					err = os.Chmod(marker, 0666)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before := intrusionUpgradeInventory(t, root)
			err = checkProgramUpgradeQueues(context.Background(), root)
			if err == nil || !strings.Contains(err.Error(), "intrusion") {
				t.Fatal("pending object did not block program replacement", err)
			}
			if !reflect.DeepEqual(before, intrusionUpgradeInventory(t, root)) {
				t.Fatal("upgrade preflight read/removed/repaired pending or foreign object")
			}
		})
	}
}

func TestIntrusionUpgradeAbsentLatchSnapshotDetectsLaterCreation(t *testing.T) {
	for name, mode := range map[string]os.FileMode{"private": 0700, "shared-group": 0750, "shared-read": 0755} {
		t.Run(name, func(t *testing.T) {
			root, anchor := intrusionUpgradeFixture(t)
			if err := os.Chmod(anchor, mode); err != nil {
				t.Fatal(err)
			}
			before := intrusionUpgradeInventory(t, root)
			reader := programQueueReader{ctx: context.Background(), root: root}
			if err := reader.hardeningPending(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, intrusionUpgradeInventory(t, root)) {
				t.Fatal("known-absence check created or repaired state")
			}
			if err := os.WriteFile(filepath.Join(anchor, intrusionPendingName), []byte("{"), 0600); err != nil {
				t.Fatal(err)
			}
			created := intrusionUpgradeInventory(t, root)
			if err := reader.unchanged(); err == nil {
				t.Fatal("late intrusion pending was ignored by final snapshot")
			}
			if !reflect.DeepEqual(created, intrusionUpgradeInventory(t, root)) {
				t.Fatal("late pending was changed by refusal")
			}
		})
	}
}

func TestIntrusionUpgradeMissingOrUnsafeAnchorNeverRepaired(t *testing.T) {
	for _, kind := range []string{"missing", "writable", "read-only", "symlink", "foreign-owner"} {
		t.Run(kind, func(t *testing.T) {
			root, anchor := intrusionUpgradeFixture(t)
			switch kind {
			case "missing":
				if err := os.Remove(anchor); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(anchor, 0777); err != nil {
					t.Fatal(err)
				}
			case "read-only":
				if err := os.Chmod(anchor, 0500); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(anchor); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "security"), anchor); err != nil {
					t.Fatal(err)
				}
			case "foreign-owner":
				if err := os.Chown(anchor, 1, 1); err != nil {
					t.Fatal(err)
				}
			}
			before := intrusionUpgradeInventory(t, root)
			err := checkProgramUpgradeQueues(context.Background(), root)
			if (err == nil) != (kind == "missing") {
				t.Fatal("unsafe anchor trusted or known absence guessed", err)
			}
			if !reflect.DeepEqual(before, intrusionUpgradeInventory(t, root)) {
				t.Fatal("untrusted anchor repaired or created")
			}
		})
	}
}
