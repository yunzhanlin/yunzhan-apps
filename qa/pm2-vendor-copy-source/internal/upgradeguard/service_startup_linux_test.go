//go:build linux

package upgradeguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestServiceInterlockClosedUnitScope(t *testing.T) {
	for _, unit := range []string{"panel.service", "panel-executor.service", "panel-terminal.service", "panel-terminal-root.service", "panel-mysql-overwrite-recovery.service"} {
		kind, recovery, err := startupService(unit)
		if err != nil || (kind != "panel" && kind != "panel-executor") || recovery != (unit == "panel-mysql-overwrite-recovery.service") {
			t.Fatal("fixed service mapping changed", unit, err)
		}
	}
	for _, unit := range []string{"", "panel", "nginx.service", "panel-install@abc.service", "panel-mysql-overwrite-recovery.timer", "panel.service\n", "--root", "/tmp/panel.service"} {
		if _, _, err := startupService(unit); err == nil {
			t.Fatal("arbitrary service accepted", unit)
		}
	}
}

func TestServiceInterlockRootSelectedBytesNotGuardBytesAndOrphanRefusal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual root ownership, procfs and kernel FLOCK required")
	}
	base, err := os.MkdirTemp("/var/lib", "panel-own-service-interlock-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base) // Only the newly allocated scope-owned fixture.
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	marker, lock, program := filepath.Join(base, "pending"), filepath.Join(base, "lease"), filepath.Join(base, "old-program")
	fd, err := unix.Open(lock, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if unix.Fchmod(fd, 0600) != nil || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		t.Fatal("owned root lease unavailable")
	}
	var lease unix.Stat_t
	if unix.Fstat(fd, &lease) != nil {
		t.Fatal("lease identity unavailable")
	}
	stat, err := procRead("/proc/self/stat", 65536)
	if err != nil {
		t.Fatal(err)
	}
	ticks, err := processTicks(stat, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	boot, err := procRead("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		t.Fatal(err)
	}
	bytes := []byte("owned inert retained payload, never executed by this fixture")
	if err := os.WriteFile(program, bytes, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(program, 0755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bytes)
	record := testStartupRecord()
	record.PID, record.StartTicks, record.BootID = os.Getpid(), ticks, strings.TrimSpace(string(boot))
	record.LockDevice, record.LockInode = lease.Dev, lease.Ino
	record.PanelSHA, record.ExecutorSHA = hex.EncodeToString(digest[:]), strings.Repeat("b", 64)
	write := func() {
		t.Helper()
		raw, _ := json.Marshal(record)
		if err := os.WriteFile(marker, raw, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(marker, 0644); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if err := serviceStartupAt(marker, lock, program, "panel"); err != nil {
		t.Fatal("exact selected old payload refused", err)
	}
	if err := serviceStartupAt(marker, lock, program, "panel-executor"); err == nil {
		t.Fatal("panel authorization permitted executor startup")
	}
	if err := serviceStartupAt(marker, lock, program, "foreign-program"); err == nil {
		t.Fatal("arbitrary program kind accepted")
	}
	if err := unix.Flock(fd, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := serviceStartupAt(marker, lock, program, "panel"); err == nil {
		t.Fatal("orphaned authorization accepted")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	originalBoot := record.BootID
	record.BootID = "11111111-2222-3333-4444-555555555555"
	write()
	if err := serviceStartupAt(marker, lock, program, "panel"); err == nil {
		t.Fatal("cold boot retained authorization accepted")
	}
	record.BootID = originalBoot
	write()
	if err := os.Chmod(program, 0775); err != nil {
		t.Fatal(err)
	}
	if err := serviceStartupAt(marker, lock, program, "panel"); err == nil {
		t.Fatal("writable selected program accepted")
	}
	if err := os.Chmod(program, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(program, program+".linked"); err != nil {
		t.Fatal(err)
	}
	if err := serviceStartupAt(marker, lock, program, "panel"); err == nil {
		t.Fatal("hard-linked selected program accepted")
	}
	if err := os.Remove(program + ".linked"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(program, program+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(program+".retained", program); err != nil {
		t.Fatal(err)
	}
	if err := serviceStartupAt(marker, lock, program, "panel"); err == nil {
		t.Fatal("linked selected program accepted")
	}
	if err := os.Chmod(base, 0775); err != nil {
		t.Fatal(err)
	}
	if _, err := serviceMarkerBlocked(filepath.Join(base, "absent")); err == nil {
		t.Fatal("marker absence below writable parent accepted")
	}
}
