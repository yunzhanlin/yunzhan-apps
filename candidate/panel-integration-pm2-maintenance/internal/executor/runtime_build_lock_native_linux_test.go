//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRuntimeBuildNativeSerializationRetainsAuthorityAndCancellation(t *testing.T) {
	if os.Getenv("PANEL_QA_RUNTIME_COLLECTION_NATIVE") != "1" {
		t.Skip("explicit private native Root build-lock fixture only")
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if os.Geteuid() != 0 || identity["CapEff"] != "00000000000000e5" || identity["NoNewPrivs"] != "1" {
		t.Fatal("lock supervisor confinement changed", identity)
	}
	const directory = "/var/lib/panel-executor"
	const path = directory + "/build.lock"
	marker := []byte("private Root lock evidence must survive contenders and refusals")
	if err := os.WriteFile(path, marker, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 33); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := acquireRuntimeNativeBuildSerialization(context.Background())
	if err != nil {
		t.Fatal("root-private lock with non-root group must remain valid", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	contender, err := acquireRuntimeNativeBuildSerialization(ctx)
	cancel()
	if contender != nil || !errors.Is(err, context.DeadlineExceeded) {
		lock.Close()
		t.Fatal("contending native compiler ignored its context", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if file, err := acquireRuntimeNativeBuildSerialization(canceled); file != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled compiler mutated or acquired its lock", err)
	}
	lock, err = acquireRuntimeNativeBuildSerialization(context.Background())
	if err != nil {
		t.Fatal("closed contender did not release the shared lock", err)
	}
	lock.Close()
	after, err := os.Lstat(path)
	if err != nil || !runtimeInstallSamePrivateFile(before, after) {
		t.Fatal("lock contenders changed authority inode, owner, mode or contents", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != string(marker) {
		t.Fatal("valid lock content truncated or repaired", err)
	}
	refused := []string{}
	for _, kind := range []string{"symlink", "hardlink", "foreign-owner", "public-mode", "oversize", "fifo", "directory"} {
		valid := filepath.Join(directory, "retained-valid-lock-"+kind)
		if err := os.Rename(path, valid); err != nil {
			t.Fatal(err)
		}
		switch kind {
		case "symlink":
			err = os.Symlink(valid, path)
		case "hardlink":
			err = os.Link(valid, path)
		case "fifo":
			err = syscall.Mkfifo(path, 0600)
		case "directory":
			err = os.Mkdir(path, 0700)
		default:
			data := []byte("retain foreign lock bytes")
			if kind == "oversize" {
				data = make([]byte, 1025)
			}
			err = os.WriteFile(path, data, 0600)
			if err == nil && kind == "public-mode" {
				err = os.Chmod(path, 0644)
			}
			if err == nil && kind == "foreign-owner" {
				err = os.Chown(path, 65534, 65534)
			}
		}
		if err != nil {
			t.Fatal(kind, err)
		}
		before, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		var content []byte
		if before.Mode().IsRegular() {
			content, err = os.ReadFile(path)
			if err != nil {
				t.Fatal(kind, err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		file, attemptErr := acquireRuntimeNativeBuildSerialization(ctx)
		cancel()
		if file != nil || attemptErr == nil {
			t.Fatal("foreign lock accepted", kind, attemptErr)
		}
		after, err := os.Lstat(path)
		if err != nil {
			t.Fatal("refusal lost foreign lock", kind, err)
		}
		x, y := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
		if !os.SameFile(before, after) || x.Mode != y.Mode || x.Uid != y.Uid || x.Gid != y.Gid || x.Nlink != y.Nlink || x.Size != y.Size || x.Mtim != y.Mtim || x.Ctim != y.Ctim {
			t.Fatal("refusal changed foreign lock identity", kind, err)
		}
		if before.Mode().IsRegular() {
			if data, err := os.ReadFile(path); err != nil || string(data) != string(content) {
				t.Fatal("refusal changed foreign lock bytes", kind, err)
			}
		}
		if err := os.Rename(path, filepath.Join(directory, "retained-foreign-lock-"+kind)); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(valid, path); err != nil {
			t.Fatal(err)
		}
		// A retained hard-link refusal is preserved too; give the next case
		// a fresh valid inode rather than deleting that historical evidence.
		if kind == "hardlink" {
			if err := os.Rename(path, filepath.Join(directory, "retained-hardlink-authority")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, marker, 0600); err != nil {
				t.Fatal(err)
			}
		}
		refused = append(refused, kind)
	}
	proof, err := json.MarshalIndent(map[string]any{"passed": true, "actual_native_shared_lock": true, "contender_deadline_observed": true, "cancellation_does_not_acquire": true, "root_private_nonroot_group_accepted": true, "valid_lock_inode_and_bytes_retained": true, "foreign_locks_retained_and_refused": refused, "scope": "Private component lock only; no application or runtime installed."}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite("/run/panel-runtime-collection24amv/lock-proof.json", proof, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("NATIVE_RUNTIME_SERIALIZATION_PROOF", len(refused))
}
