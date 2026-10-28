//go:build linux

package upgradeguard

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
