//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func ftpApplyOwnerFixture(t *testing.T, s *Service, lock *os.File) *moduleApplyOwner {
	t.Helper()
	owner, e := currentModuleApplyOwner()
	if e != nil {
		t.Fatal(e)
	}
	proc := s.systemPath("/proc")
	if e = os.MkdirAll(filepath.Join(proc, strconv.Itoa(owner.PID)), 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"stat", "status"} {
		b, e := os.ReadFile(filepath.Join("/proc", strconv.Itoa(owner.PID), name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(proc, strconv.Itoa(owner.PID), name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	info, e := lock.Stat()
	if e != nil {
		t.Fatal(e)
	}
	stat := info.Sys().(*syscall.Stat_t)
	line := fmt.Sprintf("9: FLOCK ADVISORY WRITE %d %02x:%02x:%d 0 EOF\n", owner.PID, unix.Major(uint64(stat.Dev)), unix.Minor(uint64(stat.Dev)), stat.Ino)
	if e = os.WriteFile(filepath.Join(proc, "locks"), []byte(line), 0600); e != nil {
		t.Fatal(e)
	}
	s.Config.Run = func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "show" {
			return strconv.Itoa(owner.PID), nil
		}
		return "active", nil
	}
	return owner
}

func TestFTPLiveCandidateOwnerRequiresCompleteBytesAndActualLock(t *testing.T) {
	for _, phase := range []string{"live", "missing-owner", "dead-owner", "pid-reuse", "wrong-main-pid", "wrong-flock-owner", "untrusted-uid", "unlocked", "partial-config", "partial-certificate", "accounts-pending", "committed", "stopped"} {
		t.Run(phase, func(t *testing.T) {
			s, pemBytes := ftpServiceFixture(t)
			dir := s.moduleDir("pure-ftpd")
			lock, e := s.lockFTP()
			if e != nil {
				t.Fatal(e)
			}
			defer lock.Close()
			owner := ftpApplyOwnerFixture(t, s, lock)
			config := defaultFTPConfig()
			config.Revision = 2
			b, _ := json.Marshal(config)
			if e = atomicWrite(filepath.Join(dir, "service.json"), b, 0600); e != nil {
				t.Fatal(e)
			}
			transaction := ftpServiceTransaction{ID: core.ID(), State: "applying", WasActive: true, NextConfigSHA: core.Hash(string(b)), NextPEMSHA: core.Hash(string(pemBytes)), ApplyOwner: owner}
			switch phase {
			case "missing-owner":
				transaction.ApplyOwner = nil
			case "dead-owner":
				os.Remove(filepath.Join(s.systemPath("/proc"), strconv.Itoa(owner.PID), "stat"))
			case "pid-reuse":
				transaction.ApplyOwner.StartTime++
			case "wrong-main-pid":
				s.Config.Run = func(context.Context, string, ...string) (string, error) { return "1", nil }
			case "wrong-flock-owner":
				os.WriteFile(filepath.Join(s.systemPath("/proc"), "locks"), []byte("9: FLOCK ADVISORY WRITE 1 00:00:1 0 EOF\n"), 0600)
			case "untrusted-uid":
				os.WriteFile(filepath.Join(s.systemPath("/proc"), strconv.Itoa(owner.PID), "status"), []byte("Uid:\t1234\t1234\t1234\t1234\n"), 0600)
			case "unlocked":
				lock.Close()
			case "partial-config":
				atomicWrite(filepath.Join(dir, "service.json"), []byte("old or external bytes"), 0600)
			case "partial-certificate":
				atomicWrite(filepath.Join(dir, "server.pem"), []byte("partial certificate"), 0600)
			case "accounts-pending":
				moduleWrite(filepath.Join(dir, "pending-accounts.json"), map[string]any{"state": "applying"})
			case "committed":
				transaction.State = "committed"
			case "stopped":
				transaction.WasActive = false
			}
			if e = moduleWrite(filepath.Join(dir, "pending-service.json"), transaction); e != nil {
				t.Fatal(e)
			}
			e = s.authorizeFTPStart(context.Background())
			if (phase == "live") != (e == nil) {
				t.Fatalf("candidate admission for %s: %v", phase, e)
			}
			if !exists(filepath.Join(dir, "pending-service.json")) {
				t.Fatal("startup consumed uncommitted recovery journal")
			}
		})
	}
}

func TestFTPOnlineConfigurationRetainsJournalUntilCandidateProbe(t *testing.T) {
	s, _ := ftpServiceFixture(t)
	probeStarts := 0
	s.Config.Run = func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "restart" {
			lockPath := filepath.Join(s.moduleDir("pure-ftpd"), "service.lock")
			lock, e := os.Open(lockPath)
			if e != nil {
				t.Fatal(e)
			}
			defer lock.Close()
			ftpApplyOwnerFixture(t, s, lock)
			if e = s.authorizeFTPStart(context.Background()); e != nil {
				t.Fatal("online restart rejected its own live transaction", e)
			}
			probeStarts++
		}
		return "active", nil
	}
	c := defaultFTPConfig()
	c.IdleMinutes++
	out, e := s.configureFTP(context.Background(), ftpInput(c))
	if e != nil || probeStarts != 1 || out.(map[string]any)["restart_verified"] != true {
		t.Fatal("online candidate not positively verified", out, e, probeStarts)
	}
	if exists(filepath.Join(s.moduleDir("pure-ftpd"), "pending-service.json")) {
		t.Fatal("successful online transaction not committed")
	}
}

func TestModuleFlockOwnerRejectsOtherLocksAndBlockedWaiters(t *testing.T) {
	valid := "7: FLOCK ADVISORY WRITE 42 00:0a:77 0 EOF"
	if !moduleFlockOwner(valid, 42, unix.Mkdev(0, 10), 77) {
		t.Fatal("kernel padded device not recognized")
	}
	for _, bad := range []string{strings.Replace(valid, "FLOCK", "POSIX", 1), strings.Replace(valid, "WRITE", "READ", 1), strings.Replace(valid, "42", "43", 1), strings.Replace(valid, "77", "78", 1), strings.Replace(valid, "FLOCK", "-> FLOCK", 1), strings.Replace(valid, "0 EOF", "0 200", 1)} {
		if moduleFlockOwner(bad, 42, unix.Mkdev(0, 10), 77) {
			t.Fatal("wrong kernel lock accepted", bad)
		}
	}
}
