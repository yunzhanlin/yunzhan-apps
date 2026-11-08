//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func pm2VendorKernelSealed(t *testing.T) (string, *pm2VendorWorkspace, map[string]pm2VendorEntry) {
	t.Helper()
	parent := pm2VendorKernelParent(t)
	w, source := pm2VendorKernelBuild(t, parent)
	pm2VendorKernelWrite(t, filepath.Join(source, "package.json"), pm2Package, 0644)
	pm2VendorKernelWrite(t, filepath.Join(source, "package-lock.json"), pm2Lock, 0644)
	pm2VendorKernelWrite(t, filepath.Join(source, "node_modules", "pm2", "package.json"), []byte("{\"name\":\"pm2\",\"version\":\"7.0.4\"}\n"), 0644)
	code := filepath.Join(source, "node_modules", "pm2", "runtime.js")
	pm2VendorKernelWrite(t, code, []byte("original-pinned-runtime\n"), 0644)
	if err := os.Chown(code, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	entries, err := w.copyIndependent(context.Background(), "build", "candidate")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := w.sealCandidate(context.Background(), "candidate", entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.publishIndependent(context.Background(), "candidate", sealed); err != nil {
		t.Fatal(err)
	}
	if err = pm2VendorSealedReadyAt(context.Background(), parent); err != nil {
		t.Fatal("fresh independent Root publication did not pass its private seal", err)
	}
	return parent, w, sealed
}

func TestPM2RootVendorKernelPrivateAnchorReadOnlyAndSameUIDChownRefused(t *testing.T) {
	parent, w, _ := pm2VendorKernelSealed(t)
	before, err := os.ReadFile(filepath.Join(w.path, "vendor-anchor.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err = pm2VendorSealedReadyAt(context.Background(), parent); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(filepath.Join(w.path, "vendor-anchor.json"))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("readiness altered its original private authority", err)
	}
	// Advance beyond the host's coarse inode timestamp granularity. No clock
	// substitution is used: this is an actual metadata change of this owned
	// test file, including a chown back to its original numeric owner.
	time.Sleep(20 * time.Millisecond)
	code := filepath.Join(parent, "pm2", "node_modules", "pm2", "runtime.js")
	if err = os.Chown(code, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(code, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err = pm2VendorSealedReadyAt(context.Background(), parent); err == nil {
		t.Fatal("chown-only ownership repair concealed the original file ctime change")
	}
}

func TestPM2RootVendorKernelPrivateAnchorRejectsChangedAuthorityAndEntries(t *testing.T) {
	for _, kind := range []string{"anchor-link", "anchor-hard-link", "pointer-link", "pointer-chown-back", "same-bytes-new-inode", "file-chmod-back", "unknown-file", "private-directory-mode", "private-directory-link", "public-directory-link"} {
		t.Run(kind, func(t *testing.T) {
			parent, w, _ := pm2VendorKernelSealed(t)
			code := filepath.Join(parent, "pm2", "node_modules", "pm2", "runtime.js")
			pointer := filepath.Join(parent, "pm2", pm2VendorIndexName)
			anchor := filepath.Join(w.path, "vendor-anchor.json")
			time.Sleep(20 * time.Millisecond)
			var err error
			switch kind {
			case "anchor-link":
				err = os.Rename(anchor, anchor+".original")
				if err == nil {
					err = os.Symlink(anchor+".original", anchor)
				}
			case "anchor-hard-link":
				err = os.Link(anchor, anchor+".alias")
			case "pointer-link":
				err = os.Rename(pointer, filepath.Join(w.path, "original-pointer"))
				if err == nil {
					err = os.Symlink(filepath.Join(w.path, "original-pointer"), pointer)
				}
			case "pointer-chown-back":
				err = os.Chown(pointer, 1000, 1000)
				if err == nil {
					err = os.Chown(pointer, 0, 0)
				}
			case "same-bytes-new-inode":
				var raw []byte
				raw, err = os.ReadFile(code)
				if err == nil {
					err = os.Rename(code, filepath.Join(w.path, "original-code"))
				}
				if err == nil {
					err = os.WriteFile(code, raw, 0644)
				}
			case "file-chmod-back":
				err = os.Chmod(code, 0666)
				if err == nil {
					err = os.Chmod(code, 0644)
				}
			case "unknown-file":
				err = os.WriteFile(filepath.Join(parent, "pm2", "unsealed"), []byte("unknown"), 0644)
			case "private-directory-mode":
				err = os.Chmod(w.path, 0755)
			case "private-directory-link":
				err = os.Rename(w.path, w.path+".original")
				if err == nil {
					err = os.Symlink(w.path+".original", w.path)
				}
			case "public-directory-link":
				err = os.Rename(filepath.Join(parent, "pm2"), filepath.Join(parent, "original-public"))
				if err == nil {
					err = os.Symlink(filepath.Join(parent, "original-public"), filepath.Join(parent, "pm2"))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = pm2VendorSealedReadyAt(context.Background(), parent); err == nil {
				t.Fatal("changed original private authority or current inode was accepted")
			}
		})
	}
}

func TestPM2RootVendorKernelUnsealedOwnerBitsCannotClaimIndependentCopy(t *testing.T) {
	parent := pm2VendorKernelParent(t)
	public := filepath.Join(parent, "pm2")
	pm2VendorKernelWrite(t, filepath.Join(public, "package.json"), pm2Package, 0644)
	pm2VendorKernelWrite(t, filepath.Join(public, "package-lock.json"), pm2Lock, 0644)
	pm2VendorKernelWrite(t, filepath.Join(public, "node_modules", "pm2", "package.json"), []byte("{\"name\":\"pm2\",\"version\":\"7.0.4\"}\n"), 0644)
	if err := pm2VendorSealedReadyAt(context.Background(), parent); err == nil {
		t.Fatal("old Root owner bits alone were promoted to an independent-copy receipt")
	}
	var original unix.Stat_t
	if err := unix.Stat(filepath.Join(public, "package-lock.json"), &original); err != nil {
		t.Fatal(err)
	}
	if original.Uid != 0 || original.Gid != 0 {
		t.Fatal("invalid test precondition: original unsealed files were not Root owned")
	}
}
