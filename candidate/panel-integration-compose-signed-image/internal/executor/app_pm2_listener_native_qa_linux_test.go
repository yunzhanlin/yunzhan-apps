//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This helper runs only in the explicitly staged private native QA binary.
// The parent passes only that binary's held descriptor and fixed nonsecret
// flags. It drops to the exact existing site's UID/GID; NSS is never changed.
func TestPM2NativeForeignListenerHelper(t *testing.T) {
	if os.Getenv("PANEL_PM2_NATIVE_FOREIGN_HELPER") != "1" {
		t.Skip("explicit native child only")
	}
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Fatal("foreign test listener retained root")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = json.NewEncoder(os.Stdout).Encode(map[string]int{"port": listener.Addr().(*net.TCPAddr).Port, "uid": os.Geteuid(), "gid": os.Getegid(), "pid": os.Getpid()}); err != nil {
		t.Fatal(err)
	}
	var stop [1]byte
	if _, err = io.ReadFull(os.Stdin, stop[:]); err != nil && err != io.EOF {
		t.Fatal(err)
	}
}

func TestPM2NativeExistingProjectOwnedAndForeignSameUIDListeners(t *testing.T) {
	id := os.Getenv("PANEL_PM2_NATIVE_PROJECT")
	if id == "" {
		t.Skip("explicit owned native fixture required")
	}
	if os.Geteuid() != 0 || !moduleResourceID.MatchString(id) {
		t.Fatal("native fixture identity")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || string(boot) != os.Getenv("PANEL_PM2_NATIVE_BOOT")+"\n" {
		t.Fatal("native boot changed")
	}
	s := New(Config{SitesDir: "/srv/panel/sites"})
	raw, err := s.pm2ConfigLiveBytes(id)
	if err != nil {
		t.Fatal("native manifest unavailable")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != os.Getenv("PANEL_PM2_NATIVE_MANIFEST_SHA256") {
		t.Fatal("native manifest changed")
	}
	app, err := pm2ConfigApp(raw)
	if err != nil || app.ID != id {
		t.Fatal("native app identity")
	}
	bounded, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if os.Getenv("PANEL_PM2_NATIVE_REQUIRE_NO_PTRACE") == "1" {
		status, readErr := os.ReadFile("/proc/self/status")
		if readErr != nil {
			t.Fatal(readErr)
		}
		seen := 0
		for _, line := range strings.Split(string(status), "\n") {
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			if key == "CapEff" || key == "CapPrm" || key == "CapBnd" {
				bits, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
				if err != nil || bits&(uint64(1)<<19) != 0 {
					t.Fatal("native QA retained CAP_SYS_PTRACE")
				}
				seen++
			}
		}
		if seen != 3 {
			t.Fatal("native capability evidence incomplete")
		}
	}
	account, err := s.pm2ListenerAccount(bounded, app)
	if err != nil {
		t.Fatal("native site's public NSS and ownership", err)
	}
	unit := "panel-pm2@" + id + ".service"
	if err = s.pm2Ready(bounded, unit, app.Port); err != nil {
		t.Fatal("actual owned project listener rejected", err)
	}
	witness, err := s.capturePM2Listener(bounded, unit, app.Port)
	if err != nil {
		t.Fatal(err)
	}
	owned := len(witness.Listeners)
	processes := len(witness.PIDs)
	mainPID, err := strconv.Atoi(witness.Unit.MainPID)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"exe", "descriptor-count", "sockets"} {
		if _, err = pm2SameUIDProcRead(bounded, "/proc", witness.Processes[mainPID], account.GID, operation); err != nil {
			t.Fatal("real fixed same-UID reader failed", operation, err)
		}
	}
	witness.Close()
	// Execute a copy through a held FD. Its containing directory remains 0700;
	// the non-root child obtains executable code only, never a directory grant.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	helperPath := filepath.Join(t.TempDir(), "native-foreign-listener")
	destination, err := os.OpenFile(helperPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	// The QA worker intentionally has umask 0077. Grant execute on this
	// private code copy explicitly; the enclosing directory stays 0700 and
	// only the exact child receives its held descriptor.
	if err = destination.Chmod(0755); err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(destination, original); err != nil {
		t.Fatal(err)
	}
	if err = destination.Sync(); err != nil {
		t.Fatal(err)
	}
	readOnly, err := os.Open(helperPath)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	// A writable description must not survive exec (ETXTBSY).
	if err = destination.Close(); err != nil {
		t.Fatal(err)
	}
	childCtx, childCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer childCancel()
	child := exec.CommandContext(childCtx, "/proc/self/fd/3", "-test.run=^TestPM2NativeForeignListenerHelper$", "-test.v=false", "-test.timeout=15s")
	child.ExtraFiles = []*os.File{readOnly}
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: account.UID, Gid: account.GID, Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
	child.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "GOMAXPROCS=1", "PANEL_PM2_NATIVE_FOREIGN_HELPER=1"}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &boundedBuffer{max: 4096}
	child.Stderr = stderr
	if err = child.Start(); err != nil {
		t.Fatal("start exact non-root native helper", err)
	}
	waited := false
	defer func() {
		_ = stdin.Close()
		if !waited {
			childCancel()
			_ = child.Wait()
		}
	}()
	var observed struct{ Port, UID, GID, PID int }
	if err = json.NewDecoder(io.LimitReader(stdout, 4096)).Decode(&observed); err != nil {
		t.Fatal("foreign listener bounded announcement", err)
	}
	if observed.UID != int(account.UID) || observed.GID != int(account.GID) || observed.PID != child.Process.Pid || observed.Port < 1024 || observed.Port == app.Port {
		t.Fatal("foreign listener identity")
	}
	isolated := New(Config{SitesDir: "/srv/panel/sites", SecurityDir: filepath.Join(t.TempDir(), "security")})
	app.Port = observed.Port
	if err = moduleWrite(filepath.Join(isolated.moduleDir("pm2-manager"), "apps", id+".json"), app); err != nil {
		t.Fatal(err)
	}
	// Actual systemd state, process census, NSS, UID and kernel socket tables
	// remain real. Only the private candidate port specification is isolated.
	if _, err = isolated.capturePM2Listener(bounded, unit, app.Port); err == nil {
		t.Fatal("same UID outside the PM2 unit was adopted as the project's listener")
	}
	if err = stdin.Close(); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(stdout, 4096))
	err = child.Wait()
	waited = true
	if err != nil || stderr.truncated || len(stderr.Bytes()) != 0 {
		t.Fatal("owned helper did not exit cleanly")
	}
	final, err := s.pm2ConfigLiveBytes(id)
	if err != nil || string(final) != string(raw) {
		t.Fatal("native read-only inspection changed the original manifest")
	}
	if err = s.pm2Ready(bounded, unit, app.Port); err == nil {
		t.Fatal("caller port failed to bind to the original root-owned manifest")
	}
	t.Log("NATIVE_PM2_OWNED_LISTENER", fmt.Sprint(account.UID), fmt.Sprint(account.GID), "processes", strconv.Itoa(processes), "listeners", strconv.Itoa(owned), "foreign_same_uid_rejected")
}
