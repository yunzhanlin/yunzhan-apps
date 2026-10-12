//go:build linux

package upgradeguard

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

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
func TestStartupOwnUnprivilegedProbe(t *testing.T) {
	base := os.Getenv("PANEL_OWN_STARTUP_PROBE")
	if base == "" {
		t.Skip("only scope-owned unprivileged child fixture")
	}
	if os.Geteuid() == 0 || !strings.HasPrefix(base, "/var/lib/panel-own-startup-") || filepath.Clean(base) != base {
		t.Fatal("invalid child fixture scope")
	}
	if err := startupAt(filepath.Join(base, "pending"), filepath.Join(base, "lock")); err != nil {
		t.Fatal("unprivileged startup evidence failed", err)
	}
}

func TestStartupRootLiveLeaseStaleBootPIDBytesAndUnprivilegedRead(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual root procfs and unprivileged child required")
	}
	base, err := os.MkdirTemp("/var/lib", "panel-own-startup-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base) // Only our newly created scope-owned fixture.
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	lock, marker := filepath.Join(base, "lock"), filepath.Join(base, "pending")
	fd, err := unix.Open(lock, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		t.Fatal("lock stat unavailable")
	}
	process, err := procRead("/proc/self/stat", 65536)
	if err != nil {
		t.Fatal(err)
	}
	ticks, err := processTicks(process, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	boot, err := procRead("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := runningProgramSHA()
	if err != nil {
		t.Fatal(err)
	}
	record := testStartupRecord()
	record.PID, record.StartTicks, record.BootID = os.Getpid(), ticks, strings.TrimSpace(string(boot))
	record.LockDevice, record.LockInode = st.Dev, st.Ino
	record.PanelSHA, record.ExecutorSHA = digest, digest
	write := func(value startupRecord) {
		t.Helper()
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(marker, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(record)
	if err := startupAt(marker, lock); err != nil {
		t.Fatal("live root-owned startup refused", err)
	}
	for _, field := range []string{"boot", "ticks", "pid", "inode", "bytes"} {
		mutated := record
		switch field {
		case "boot":
			mutated.BootID = "11111111-2222-3333-4444-555555555555"
		case "ticks":
			mutated.StartTicks++
		case "pid":
			mutated.PID = 1
		case "inode":
			mutated.LockInode++
		case "bytes":
			mutated.PanelSHA, mutated.ExecutorSHA = strings.Repeat("a", 64), strings.Repeat("b", 64)
		}
		write(mutated)
		if err := startupAt(marker, lock); err == nil {
			t.Fatal("wrong startup authority accepted", field)
		}
	}
	write(record)
	if err := unix.Flock(fd, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := startupAt(marker, lock); err == nil {
		t.Fatal("released lease accepted")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(marker, 0664); err != nil {
		t.Fatal(err)
	}
	if err := startupAt(marker, lock); err == nil {
		t.Fatal("writable marker accepted")
	}
	if err := os.Chmod(marker, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(marker, marker+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(marker+".retained", marker); err != nil {
		t.Fatal(err)
	}
	if err := startupAt(marker, lock); err == nil {
		t.Fatal("marker link accepted")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	write(record)
	// The nobody user must verify public evidence without opening the 0600 lock.
	// Copy only this exact root-owned test program, never installed binaries.
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	binary := filepath.Join(base, "own-probe.test")
	target, err := os.OpenFile(binary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(target, source); err != nil {
		target.Close()
		t.Fatal(err)
	}
	if err = target.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/sbin/runuser", "-u", "nobody", "--", binary, "-test.run=^TestStartupOwnUnprivilegedProbe$", "-test.count=1", "-test.v")
	command.Env = append(os.Environ(), "PANEL_OWN_STARTUP_PROBE="+base)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("scope-owned unprivileged procfs proof failed", err, string(output))
	}
	t.Log("root live lease, wrong boot/ticks/PID/inode/program, released lock, unsafe marker and actual nobody startup evidence checked; owner PID " + strconv.Itoa(record.PID))
}
