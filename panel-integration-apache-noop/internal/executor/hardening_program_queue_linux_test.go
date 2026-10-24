//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

func hardeningGuardFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("native root queue authority, no UID override")
	}
	return t.TempDir()
}

func hardeningGuardTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		s := info.Sys().(*syscall.Stat_t)
		raw, _ := json.Marshal([]any{s.Dev, s.Ino, s.Mode, s.Uid, s.Gid, s.Nlink, s.Size, s.Mtim, s.Ctim})
		out[path] = string(raw)
		if info.Mode().IsRegular() {
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out[path] += "|" + core.Hash(string(body))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestHardeningProgramQueueSharedAnchorUsesExistingTrustContractWithoutRelaxingPrivateQueues(t *testing.T) {
	for _, kind := range []string{"shared0750-closed", "shared0755-closed", "shared0750-pending", "shared0755-pending", "group-writable", "symlink", "foreign-owner", "private-queue0750"} {
		t.Run(kind, func(t *testing.T) {
			root := hardeningGuardFixture(t)
			dir := filepath.Join(root, "etc/panel/security-apps")
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			mode := os.FileMode(0750)
			if kind == "shared0755-closed" || kind == "shared0755-pending" {
				mode = 0755
			}
			if kind == "group-writable" {
				mode = 0770
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			if kind == "shared0750-pending" || kind == "shared0755-pending" {
				if err := os.WriteFile(filepath.Join(dir, hardeningPendingName), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "symlink" {
				if err := os.Rename(dir, dir+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+"-original", dir); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "foreign-owner" {
				if err := os.Chown(dir, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			}
			before := hardeningGuardTree(t, root)
			reader := programQueueReader{ctx: context.Background(), root: root}
			err := reader.hardeningPending()
			wantOK := kind == "shared0750-closed" || kind == "shared0755-closed" || kind == "private-queue0750"
			if (err == nil) != wantOK {
				t.Fatal("shared anchor admission", kind, err)
			}
			if err == nil {
				if err = reader.unchanged(); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(before, hardeningGuardTree(t, root)) {
				t.Fatal("shared anchor was repaired")
			}
			if kind == "private-queue0750" {
				private := filepath.Join(root, "private-queue")
				if err := os.Mkdir(private, 0750); err != nil {
					t.Fatal(err)
				}
				reader = programQueueReader{ctx: context.Background(), root: root}
				handle, err := reader.directory("private-queue")
				if handle != nil {
					handle.Close()
				}
				if err == nil {
					t.Fatal("shared anchor exception weakened private queue contract")
				}
			}
		})
	}
}

func TestHardeningProgramQueueAnyPendingAuthorityRefusesWithoutRepair(t *testing.T) {
	for _, mode := range []string{"partial", "empty", "directory", "symlink", "public", "hardlink"} {
		t.Run(mode, func(t *testing.T) {
			root := hardeningGuardFixture(t)
			dir := filepath.Join(root, "etc/panel/security-apps")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, hardeningPendingName)
			switch mode {
			case "directory":
				if err := os.Mkdir(file, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(root, "missing-original"), file); err != nil {
					t.Fatal(err)
				}
			default:
				data := []byte("{\n")
				if mode == "empty" {
					data = nil
				}
				if err := os.WriteFile(file, data, 0600); err != nil {
					t.Fatal(err)
				}
				if mode == "public" {
					if err := os.Chmod(file, 0644); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "hardlink" {
					if err := os.Link(file, filepath.Join(root, "second-link")); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := hardeningGuardTree(t, root)
			if err := checkProgramUpgradeQueues(context.Background(), root); err == nil {
				t.Fatal("pending hardening source admitted upgrade", mode)
			}
			if !reflect.DeepEqual(before, hardeningGuardTree(t, root)) {
				t.Fatal("pending authority repaired or removed", mode)
			}
		})
	}
}

func TestHardeningProgramQueueClosedMissingMarkerIsPureObservation(t *testing.T) {
	root := hardeningGuardFixture(t)
	if err := os.MkdirAll(filepath.Join(root, "etc/panel/security-apps"), 0700); err != nil {
		t.Fatal(err)
	}
	before := hardeningGuardTree(t, root)
	if err := checkProgramUpgradeQueues(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, hardeningGuardTree(t, root)) {
		t.Fatal("closed inspection created state")
	}
}
