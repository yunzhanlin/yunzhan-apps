//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestThreatIDSStoppedOutputSyncPreservesOriginalEventsAndMetadata(t *testing.T) {
	s := threatIDSRotationRootFixture(t)
	account := threatIDSAccount{Format: 1, UID: 800, GID: 801}
	if err := s.prepareThreatIDSLogs(account); err != nil {
		t.Fatal(err)
	}
	live := s.systemPath("/var/lib/panel-network-ids/logs/eve.json")
	// An absent log is not fabricated or falsely reported as synchronized.
	if synced, size, err := s.syncStoppedThreatIDSOutput(context.Background(), account); err != nil || synced || size != 0 {
		t.Fatal(synced, size, err)
	}
	if _, err := os.Lstat(live); !os.IsNotExist(err) {
		t.Fatal("stop created a fabricated event log", err)
	}
	data := []byte(threatEVEFixture("2026-11-20T02:00:00Z", 1, 9000004) + "\n")
	if err := os.WriteFile(live, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(live, 800, 801); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(live)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		synced, size, err := s.syncStoppedThreatIDSOutput(context.Background(), account)
		if err != nil || !synced || size != int64(len(data)) {
			t.Fatal(synced, size, err)
		}
	}
	after, err := os.Lstat(live)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("sync replaced or rewrote the original log", err)
	}
	st := after.Sys().(*syscall.Stat_t)
	actual, err := os.ReadFile(live)
	if err != nil || string(actual) != string(data) || st.Uid != 800 || st.Gid != 801 || st.Nlink != 1 {
		t.Fatal("sync changed original data or ownership", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if synced, _, err := s.syncStoppedThreatIDSOutput(ctx, account); synced || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled sync reported success", err)
	}
}

func TestThreatIDSStoppedOutputSyncRejectsLinksAndUntrustedFilesWithoutRepair(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "wrong-owner", "public-mode", "directory-symlink"} {
		t.Run(kind, func(t *testing.T) {
			s := threatIDSRotationRootFixture(t)
			account := threatIDSAccount{Format: 1, UID: 800, GID: 801}
			if err := s.prepareThreatIDSLogs(account); err != nil {
				t.Fatal(err)
			}
			live := s.systemPath("/var/lib/panel-network-ids/logs/eve.json")
			retained := filepath.Join(s.Config.SystemRoot, "retained-canary")
			data := []byte("original private fixture; keep unchanged\n")
			if err := os.WriteFile(retained, data, 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(retained, live)
			case "hardlink":
				err = os.Link(retained, live)
			case "fifo":
				err = syscall.Mkfifo(live, 0600)
			case "directory":
				err = os.Mkdir(live, 0700)
			case "directory-symlink":
				original := filepath.Dir(live)
				if err = os.Rename(original, original+"-retained"); err == nil {
					err = os.Symlink(original+"-retained", original)
				}
			default:
				err = os.WriteFile(live, data, 0600)
				if kind == "public-mode" && err == nil {
					err = os.Chown(live, 800, 801)
					if err == nil {
						err = os.Chmod(live, 0644)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if synced, _, err := s.syncStoppedThreatIDSOutput(context.Background(), account); err == nil || synced {
				t.Fatal("untrusted output reported durable", err)
			}
			actual, err := os.ReadFile(retained)
			if err != nil || string(actual) != string(data) {
				t.Fatal("failed synchronization changed retained original data", err)
			}
		})
	}
}
