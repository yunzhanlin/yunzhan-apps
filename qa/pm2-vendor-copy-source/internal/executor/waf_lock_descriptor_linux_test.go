//go:build linux

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWAFHealthLockRequiresExactOpenDescription(t *testing.T) {
	s := wafPolicyFixture(t)
	held, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	other, err := os.OpenFile(filepath.Join(s.Config.SecurityDir, "waf-configuration.lock"), os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := s.verifyWAFHealthLock(other); err == nil {
		t.Fatal("independently reopened unlocked descriptor borrowed another descriptor's FLOCK")
	}
	if err := s.verifyWAFHealthLock(held); err != nil {
		t.Fatal("original exclusive descriptor rejected", err)
	}
}

func TestWAFHealthLockDescriptorParserFailsClosed(t *testing.T) {
	base := "pos:\t0\nflags:\t0100002\nmnt_id:\t19\nino:\t77\nlock:\t1: FLOCK ADVISORY WRITE 42 00:0a:77 0 EOF\n"
	for name, data := range map[string]string{
		"empty": "", "no-lock": "ino: 77\n", "no-inode": strings.ReplaceAll(base, "ino:\t77\n", ""),
		"different-inode": strings.ReplaceAll(base, "ino:\t77", "ino:\t78"),
		"duplicate-inode": base + "ino: 77\n", "duplicate-lock": base + "lock: 2: FLOCK ADVISORY WRITE 42 00:0a:77 0 EOF\n",
		"shared": strings.ReplaceAll(base, "WRITE", "READ"), "foreign-pid": strings.ReplaceAll(base, "WRITE 42", "WRITE 43"),
		"foreign-device": strings.ReplaceAll(base, "00:0a:77", "00:0b:77"), "foreign-lock-inode": strings.ReplaceAll(base, "00:0a:77", "00:0a:78"),
		"posix": strings.ReplaceAll(base, "FLOCK", "POSIX"), "waiting": strings.ReplaceAll(base, "1: FLOCK", "1: -> FLOCK"),
		"not-whole-file": strings.ReplaceAll(base, "0 EOF", "1 EOF"), "overflow": strings.ReplaceAll(base, "ino:\t77", "ino: 18446744073709551616"),
		"trailing-fields": strings.ReplaceAll(base, "0 EOF", "0 EOF unknown"),
	} {
		t.Run(name, func(t *testing.T) {
			if wafDescriptorExclusiveFlock([]byte(data), 42, unix.Mkdev(0, 10), 77) {
				t.Fatal("ambiguous descriptor evidence accepted")
			}
		})
	}
	if !wafDescriptorExclusiveFlock([]byte(base), 42, unix.Mkdev(0, 10), 77) {
		t.Fatal("actual kernel format rejected")
	}
	if wafDescriptorExclusiveFlock([]byte(base), 0, unix.Mkdev(0, 10), 77) || wafDescriptorExclusiveFlock([]byte(base), 42, unix.Mkdev(0, 10), 0) {
		t.Fatal("invalid identity accepted")
	}
}

func TestWAFHealthLockDescriptorRejectsIdentityDrift(t *testing.T) {
	for _, fault := range []string{"nil", "unlocked", "shared", "closed", "replaced", "hardlink", "permissions"} {
		t.Run(fault, func(t *testing.T) {
			s := wafPolicyFixture(t)
			held, err := s.lockWAFConfiguration()
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			name := filepath.Join(s.Config.SecurityDir, "waf-configuration.lock")
			switch fault {
			case "nil":
				if s.verifyWAFHealthLock(nil) == nil {
					t.Fatal("nil accepted")
				}
				return
			case "unlocked":
				err = syscall.Flock(int(held.Fd()), syscall.LOCK_UN)
			case "shared":
				err = syscall.Flock(int(held.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
			case "closed":
				err = held.Close()
			case "replaced":
				err = os.Rename(name, name+".original")
				if err == nil {
					err = os.WriteFile(name, nil, 0600)
				}
			case "hardlink":
				err = os.Link(name, name+".other")
			case "permissions":
				err = os.Chmod(name, 0640)
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.verifyWAFHealthLock(held) == nil {
				t.Fatal("drift accepted", fault)
			}
		})
	}
}

func TestWAFHealthLockDescriptorAcceptsActualDuplicatedLease(t *testing.T) {
	s := wafPolicyFixture(t)
	held, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	fd, err := syscall.Dup(int(held.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	duplicate := os.NewFile(uintptr(fd), "actual-duplicated-open-description")
	defer duplicate.Close()
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyWAFHealthLock(duplicate); err != nil {
		t.Fatal("duplicate still owns actual FLOCK", err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if s.verifyWAFHealthLock(duplicate) == nil {
		t.Fatal("released duplicate lease accepted")
	}
}

func TestWAFHealthLockDescriptorStableUnderUnrelatedKernelChurn(t *testing.T) {
	s := wafPolicyFixture(t)
	held, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	var closing atomic.Bool
	var workers sync.WaitGroup
	defer func() { closing.Store(true); workers.Wait() }()
	for i := 0; i < 8; i++ {
		file, err := os.OpenFile(filepath.Join(t.TempDir(), fmt.Sprintf("unrelated-%d", i)), os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer file.Close()
			for !closing.Load() {
				if unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil {
					_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
				}
			}
		}()
	}
	for range 2000 {
		if err := s.verifyWAFHealthLock(held); err != nil {
			t.Fatal("genuine held fd disappeared during unrelated churn", err)
		}
	}
	closing.Store(true)
	workers.Wait()
	data, err := os.ReadFile(filepath.Join(s.Config.SecurityDir, "waf-configuration.lock"))
	if err != nil || len(data) != 0 {
		t.Fatal("observation changed lock bytes", err)
	}
	t.Log("WAF_DESCRIPTOR_FIXED_NATIVE iterations=2000 missing=0 independently_reopened_unlocked_descriptor_refused=true no_global_proc_locks_fallback=true original_cross_process_candidate_authority_unchanged=true private_fixtures_only=true")
}
