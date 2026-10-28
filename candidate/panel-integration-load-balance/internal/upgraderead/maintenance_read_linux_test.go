//go:build linux

package upgraderead

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMaintenanceReadOwnedChildProbe(t *testing.T) {
	base := os.Getenv("PANEL_OWN_MAINTENANCE_READ_FIXTURE")
	if base == "" {
		t.Skip("private fixture child only")
	}
	w, err := holdMaintenanceReadAt(context.Background(), filepath.Join(base, "pending"), filepath.Join(base, "other"), filepath.Join(base, "release"), filepath.Join(base, "runtime"))
	if os.Getenv("PANEL_OWN_MAINTENANCE_READ_REJECT") == "1" {
		if err == nil {
			w.Close()
			t.Fatal("unowned maintenance accepted")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if os.Getenv("PANEL_OWN_MAINTENANCE_READ_CHANGE") == "1" {
		fmt.Println("OWN-MAINTENANCE-HELD")
		if !bufio.NewScanner(os.Stdin).Scan() {
			t.Fatal("parent fixture handshake unavailable")
		}
		if w.Current(context.Background()) == nil {
			t.Fatal("changed marker or parent lease adopted")
		}
	} else if err := w.Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if w.Current(context.Background()) == nil {
		t.Fatal("closed witness remained current")
	}
}

func TestMaintenanceReadActualParentTwoExclusiveLeasesAndChanges(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Root procfs, pidfds and parent FLOCKs required")
	}
	for _, fault := range []string{"valid-plain", "valid-json", "missing-runtime", "shared-runtime", "shared-release", "wrong-json-parent", "invalid-marker", "writable-marker", "other-marker", "marker-change", "runtime-release", "release-release", "runtime-replaced"} {
		t.Run(fault, func(t *testing.T) {
			base, err := os.MkdirTemp("/var/lib", "panel-own-maintenance-read-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(base) // Only this newly created private Root fixture.
			var fds [2]int
			for i, name := range []string{"release", "runtime"} {
				fd, err := unix.Open(filepath.Join(base, name), unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
				if err != nil {
					t.Fatal(err)
				}
				fds[i] = fd
				defer unix.Close(fd)
				lock := unix.LOCK_EX | unix.LOCK_NB
				if fault == "shared-"+name {
					lock = unix.LOCK_SH | unix.LOCK_NB
				}
				if err := unix.Flock(fd, lock); err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(base, "pending")
			raw := []byte("version=0.1.0-dev.owned\n")
			if fault == "valid-json" || fault == "wrong-json-parent" {
				record := testStartupRecord()
				proc, _ := procRead("/proc/self/stat", 65536)
				ticks, err := processTicks(proc, os.Getpid())
				if err != nil {
					t.Fatal(err)
				}
				boot, err := procRead("/proc/sys/kernel/random/boot_id", 128)
				if err != nil {
					t.Fatal(err)
				}
				var st unix.Stat_t
				if unix.Fstat(fds[0], &st) != nil {
					t.Fatal("lease identity unavailable")
				}
				record.PID, record.StartTicks, record.BootID, record.LockDevice, record.LockInode = os.Getpid(), ticks, strings.TrimSpace(string(boot)), st.Dev, st.Ino
				if fault == "wrong-json-parent" {
					record.PID++
				}
				raw, err = json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
			}
			if fault == "invalid-marker" {
				raw = []byte("version=0.1.0\nunknown=true\n")
			}
			if err := os.WriteFile(marker, raw, 0644); err != nil {
				t.Fatal(err)
			}
			// The outer evidence collector uses umask077. These private fixtures
			// explicitly create the public0644 protocol marker, never production.
			if err := os.Chmod(marker, 0644); err != nil {
				t.Fatal(err)
			}
			if fault == "writable-marker" {
				if err := os.Chmod(marker, 0664); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "missing-runtime" {
				if err := unix.Flock(fds[1], unix.LOCK_UN); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "other-marker" {
				if err := os.WriteFile(filepath.Join(base, "other"), raw, 0644); err != nil {
					t.Fatal(err)
				}
			}
			change := fault == "marker-change" || fault == "runtime-release" || fault == "release-release" || fault == "runtime-replaced"
			reject := !strings.HasPrefix(fault, "valid-") && !change
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestMaintenanceReadOwnedChildProbe$", "-test.count=1", "-test.v")
			cmd.Env = append(os.Environ(), "PANEL_OWN_MAINTENANCE_READ_FIXTURE="+base)
			if reject {
				cmd.Env = append(cmd.Env, "PANEL_OWN_MAINTENANCE_READ_REJECT=1")
			}
			if !change {
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatal(err, string(out))
				}
				return
			}
			cmd.Env = append(cmd.Env, "PANEL_OWN_MAINTENANCE_READ_CHANGE=1")
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = cmd.Stdout
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			scanner := bufio.NewScanner(out)
			held := false
			var transcript strings.Builder
			for scanner.Scan() {
				line := scanner.Text()
				transcript.WriteString(line + "\n")
				if line == "OWN-MAINTENANCE-HELD" {
					held = true
					break
				}
			}
			if !held {
				cmd.Wait()
				t.Fatal("owned parent handshake failed", transcript.String())
			}
			switch fault {
			case "marker-change":
				err = os.WriteFile(marker, []byte("version=0.1.1-dev.owned\n"), 0644)
			case "runtime-release":
				err = unix.Flock(fds[1], unix.LOCK_UN)
			case "release-release":
				err = unix.Flock(fds[0], unix.LOCK_UN)
			case "runtime-replaced":
				err = os.Rename(filepath.Join(base, "runtime"), filepath.Join(base, "runtime-retained"))
				if err == nil {
					err = os.WriteFile(filepath.Join(base, "runtime"), nil, 0600)
				}
			}
			if err != nil {
				in.Close()
				cmd.Wait()
				t.Fatal(err)
			}
			fmt.Fprintln(in, "check")
			in.Close()
			for scanner.Scan() {
				transcript.WriteString(scanner.Text() + "\n")
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal(err, transcript.String())
			}
		})
	}
}

func testStartupRecord() startupRecord {
	return startupRecord{Format: 2, Version: "0.1.0-dev.own", PID: 1234, StartTicks: 123456, BootID: "11111111-2222-3333-4444-555555555555", LockDevice: unix.Mkdev(8, 1), LockInode: 12345, Phase: "program-start", PanelSHA: strings.Repeat("a", 64), ExecutorSHA: strings.Repeat("b", 64)}
}

func TestStartupClosedAuthorizationParser(t *testing.T) {
	record := testStartupRecord()
	raw, _ := json.Marshal(record)
	if got, err := parseStartup(raw); err != nil || got != record {
		t.Fatal("closed authorization rejected", err)
	}
	for _, mutated := range []string{
		"version=old\n", "[]", string(raw) + "{}",
		strings.Replace(string(raw), `"format":2`, `"format":null`, 1),
		strings.Replace(string(raw), `"format":2`, `"Format":2`, 1),
		strings.Replace(string(raw), `"format":2`, `"format":2,"\u0066ormat":2`, 1),
		strings.Replace(string(raw), `"format":2`, `"format":2,"unknown":true`, 1),
		strings.Replace(string(raw), `"pid":1234`, `"pid":1`, 1),
		strings.Replace(string(raw), `"start_ticks":123456`, `"start_ticks":0`, 1),
		strings.Replace(string(raw), `"program-start"`, `"prepared"`, 1),
		strings.Replace(string(raw), record.PanelSHA, "not a SHA", 1),
		strings.Replace(string(raw), `"lock_inode":12345`, `"lock_inode":0`, 1),
	} {
		if _, err := parseStartup([]byte(mutated)); err == nil {
			t.Fatal("unsafe startup record accepted", mutated)
		}
	}
}

func TestStartupExactExclusiveKernelLeaseParser(t *testing.T) {
	record := testStartupRecord()
	valid := "1: FLOCK ADVISORY WRITE 1234 08:01:12345 0 EOF\n"
	if !ownsStartupLock([]byte(valid), record) {
		t.Fatal("exact kernel lock rejected")
	}
	for _, invalid := range []string{strings.Replace(valid, "WRITE", "READ", 1), strings.Replace(valid, "FLOCK", "POSIX", 1), strings.Replace(valid, "1234 ", "5678 ", 1), strings.Replace(valid, ":12345", ":12346", 1), strings.Replace(valid, "08:01", "08:02", 1), strings.Replace(valid, "0 EOF", "1 EOF", 1), strings.Replace(valid, "1: ", "1: -> ", 1), valid + valid, ""} {
		if ownsStartupLock([]byte(invalid), record) {
			t.Fatal("wrong, blocked, shared or duplicate lock accepted", invalid)
		}
	}
}

func TestStartupPIDStartTimeHandlesNamesAndRejectsDeadOwners(t *testing.T) {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[19] = "S", "987654"
	raw := "1234 (name with ) spaces) " + strings.Join(fields, " ")
	if ticks, err := processTicks([]byte(raw), 1234); err != nil || ticks != 987654 {
		t.Fatal(ticks, err)
	}
	for _, invalid := range []string{strings.Replace(raw, "1234 (", "5678 (", 1), strings.Replace(raw, ") S ", ") Z ", 1), strings.Replace(raw, "987654", "0", 1), "1234 (short) S"} {
		if _, err := processTicks([]byte(invalid), 1234); err == nil {
			t.Fatal("dead or reused owner accepted")
		}
	}
}

// Probe is only part of the test binary. No runtime flag/environment override
// for marker, lease, executable or host root exists in either shipped program.

func TestStartupLeaseEnumerationIsBoundedAndRequiresOneExactSnapshot(t *testing.T) {
	record := testStartupRecord()
	valid := []byte("1: FLOCK ADVISORY WRITE 1234 08:01:12345 0 EOF\n")
	fixed := time.Unix(100, 0)
	now := func() time.Time { return fixed }
	calls := 0
	read := func() ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, nil
		}
		if calls == 2 {
			return append(append([]byte{}, valid...), valid...), nil
		}
		return valid, nil
	}
	if err := startupLeaseSnapshot(record, read, now); err != nil || calls != 3 {
		t.Fatal("fresh unique exact kernel lease was not required", calls, err)
	}
	for _, raw := range [][]byte{nil, append(append([]byte{}, valid...), valid...), []byte("1: FLOCK ADVISORY WRITE 5678 08:01:12345 0 EOF\n"), []byte("1: FLOCK ADVISORY READ 1234 08:01:12345 0 EOF\n")} {
		calls = 0
		if err := startupLeaseSnapshot(record, func() ([]byte, error) { calls++; return raw, nil }, now); err == nil || calls != 8 {
			t.Fatal("absent, duplicate, foreign or shared kernel lease accepted", calls, err)
		}
	}
	calls = 0
	if err := startupLeaseSnapshot(record, func() ([]byte, error) { calls++; return valid, errors.New("unavailable procfs") }, now); err == nil || calls != 1 {
		t.Fatal("kernel I/O failure must refuse immediately", calls, err)
	}
	calls = 0
	if err := startupLeaseSnapshot(record, func() ([]byte, error) { calls++; return make([]byte, 4*1024*1024+1), nil }, now); err == nil || calls != 1 {
		t.Fatal("oversized enumeration accepted", calls, err)
	}
	calls = 0
	if err := startupLeaseSnapshot(record, func() ([]byte, error) { calls++; fixed = fixed.Add(100 * time.Millisecond); return valid, nil }, now); err == nil || calls != 1 {
		t.Fatal("late exact enumeration accepted", calls, err)
	}
}
