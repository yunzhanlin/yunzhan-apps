//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestThreatIDSHistoryPrivateSnapshotsMergeAndRefuseForeignEdits(t *testing.T) {
	s := threatIDSRotationRootFixture(t)
	account := threatIDSAccount{Format: 1, UID: 800, GID: 801}
	if err := s.prepareThreatIDSLogs(account); err != nil {
		t.Fatal(err)
	}
	live := s.systemPath("/var/lib/panel-network-ids/logs/eve.json")
	if err := os.WriteFile(live, []byte(threatEVEFixture("2026-10-09T02:00:00Z", 1, 1001)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(live, 800, 801); err != nil {
		t.Fatal(err)
	}
	entry, path := threatIDSRotationArchiveFixture(t, s)
	data := []byte(threatEVEFixture("2026-10-09T01:00:00Z", 2, 1002) + "\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	entry.Bytes = int64(len(data))
	entry.SHA = fmt.Sprintf("%x", sha256.Sum256(data))
	rotation := threatIDSRotation{Format: 1, Archives: []threatIDSArchive{entry}, Retired: []threatIDSArchive{}}
	if err := s.writeThreatIDSRotation(rotation); err != nil {
		t.Fatal(err)
	}
	report, summary, err := s.readThreatIDSRetainedFile(context.Background(), account, threatEVEFilter{Limit: 1, Offset: 1})
	if err != nil || len(report.Alerts) != 1 || report.Alerts[0].SignatureID != 1002 || report.MatchingAlerts != 2 || summary.Archives != 1 || summary.ArchiveBytes != entry.Bytes || report.Stats != nil {
		t.Fatal(report, summary, err)
	}
	data[0] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.readThreatIDSRetainedFile(context.Background(), account, threatEVEFilter{}); err == nil {
		t.Fatal("same-inode same-length history edit returned")
	}
	data[0] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "unknown.json"), []byte("unknown"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.readThreatIDSRetainedFile(context.Background(), account, threatEVEFilter{}); err == nil {
		t.Fatal("unknown history file hidden")
	}
}

func TestThreatIDSReadLockIsNonMutatingAndExcludesConfigurationChanges(t *testing.T) {
	s := threatIDSRotationRootFixture(t)
	path := filepath.Join(s.moduleDir("network-threat-detection"), "waf-configuration.lock")
	if f, err := s.threatIDSReadLock(); err != nil || f != nil {
		t.Fatal("unconfigured read should not initialize a lock", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("read initialized serialization")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if f, err := s.threatIDSReadLock(); err == nil || f != nil {
		t.Fatal("read raced a mutating operation")
	}
	lock.Close()
	read, err := s.threatIDSReadLock()
	if err != nil || read == nil {
		t.Fatal(err)
	}
	if lock, err := s.lockWAFConfiguration(); err == nil || lock != nil {
		t.Fatal("mutation raced shared metadata read")
	}
	read.Close()
	if err := os.Link(path, path+".alias"); err != nil {
		t.Fatal(err)
	}
	if f, err := s.threatIDSReadLock(); err == nil || f != nil {
		t.Fatal("aliased lock accepted")
	}
}

func TestThreatIDSHistoryCreationRequiresRootGroupAndDoesNotRepairForeignDirectory(t *testing.T) {
	s := threatIDSRotationRootFixture(t)
	path, err := s.threatIDSHistoryDirectory(false)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	owner := info.Sys().(*syscall.Stat_t)
	if info.Mode().Perm() != 0700 || owner.Uid != 0 || owner.Gid != 0 {
		t.Fatal("new archive directory inherited executor primary group")
	}
	if err := os.Chown(path, 0, 801); err != nil {
		t.Fatal(err)
	}
	if _, err := s.threatIDSHistoryDirectory(true); err == nil {
		t.Fatal("foreign existing archive group silently repaired")
	}
	info, _ = os.Lstat(path)
	if info.Sys().(*syscall.Stat_t).Gid != 801 {
		t.Fatal("foreign directory modified")
	}
}
