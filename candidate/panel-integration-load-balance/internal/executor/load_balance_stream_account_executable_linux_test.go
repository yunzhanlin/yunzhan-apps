//go:build linux

package executor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLoadBalanceStreamAccountExecutablePinsFullHashAndRechecksWithoutDataReads(t *testing.T) {
	ctx := t.Context()
	pid := uint32(os.Getpid())
	e, err := holdLoadBalanceStreamAccountExecutable(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	raw, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	if e.sha256 != hex.EncodeToString(digest[:]) {
		t.Fatal("held executable not fully hashed")
	}
	if _, err := e.file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		if !e.current(ctx, pid, e.sha256) {
			t.Fatal("unchanged actual executable refused", i)
		}
	}
	if position, err := e.file.Seek(0, io.SeekCurrent); err != nil || position != 0 {
		t.Fatal("live identity checks reread executable bytes", position, err)
	}
	other := "a" + e.sha256[1:]
	if other == e.sha256 {
		other = "b" + e.sha256[1:]
	}
	if e.current(ctx, pid, other) || e.current(ctx, 1, e.sha256) || e.current(nil, pid, e.sha256) {
		t.Fatal("wrong hash, PID or missing context reused an integrity witness")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if e.current(canceled, pid, e.sha256) {
		t.Fatal("canceled observation accepted")
	}
	e.close()
	if e.current(ctx, pid, e.sha256) {
		t.Fatal("closed witness reopened or retained authority")
	}
	if e, err := holdLoadBalanceStreamAccountExecutable(canceled, pid); err == nil {
		e.close()
		t.Fatal("canceled acquisition accepted")
	}
}

// Linux protects the ACTUAL mapped executable against writes, independently of
// the filesystem's ctime clock granularity. Test a private writable copy, never
// the installed ELF; after its reader exits, the same write-open must succeed.
func TestLoadBalanceStreamAccountExecutableKernelDeniesWritesWhileRunning(t *testing.T) {
	const mode = "PANEL_PRIVATE_EXECUTABLE_WRITE_DENY_TEST"
	if os.Getenv(mode) == "child" {
		fmt.Fprintln(os.Stdout, "private-executable-ready")
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			t.Fatal(err)
		}
		return
	}
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	path := filepath.Join(t.TempDir(), "private-executable.test")
	copy, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(copy, source); err != nil {
		copy.Close()
		t.Fatal(err)
	}
	if err := copy.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-test.run=^TestLoadBalanceStreamAccountExecutableKernelDeniesWritesWhileRunning$", "-test.v=true")
	cmd.Env = append(os.Environ(), mode+"=child")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		input.Close()
		if !waited {
			cmd.Wait()
		}
	}()
	scanner := bufio.NewScanner(output)
	ready := false
	for scanner.Scan() {
		if scanner.Text() == "private-executable-ready" {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("private executable never entered its bounded child role", scanner.Err())
	}
	for i := 0; i < 8; i++ {
		file, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
		if file != nil {
			file.Close()
		}
		if !errors.Is(err, syscall.ETXTBSY) {
			t.Fatal("actual running private ELF permitted a write-open", err)
		}
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	// Drain the child's normal test epilogue before Wait closes its pipe.
	for scanner.Scan() {
	}
	waitErr := cmd.Wait()
	waited = true
	if scanner.Err() != nil || waitErr != nil {
		t.Fatal("private executable did not exit normally", scanner.Err(), waitErr)
	}
	writable, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal("positive control: stopped private ELF should allow an ordinary write-open", err)
	}
	writable.Close()
}

// Real private filesystem metadata, not a fabricated FileInfo or a host ELF
// mutation. A same-size write with restored mtime must be checked across an
// actual timestamp tick: two ordinary writes in one coarse kernel tick can
// legitimately have identical ctime. The running-ELF invariant is tested above.
func TestLoadBalanceStreamAccountExecutableRejectsEveryOriginalMetadataDrift(t *testing.T) {
	for _, scenario := range []string{"content-and-restored-mtime", "mode", "hardlink", "replacement", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-integrity-model")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			before, err := file.Stat()
			if err != nil || !streamAccountExecutableStable(before, before, before, before, before) {
				t.Fatal("private unchanged metadata fixture refused", err)
			}
			switch scenario {
			case "content-and-restored-mtime":
				probe := filepath.Join(t.TempDir(), "private-timestamp-probe")
				original := before.Sys().(*syscall.Stat_t).Ctim
				deadline := time.Now().Add(2 * time.Second)
				for {
					if err := os.WriteFile(probe, []byte("clock"), 0600); err != nil {
						t.Fatal(err)
					}
					clock, err := os.Stat(probe)
					if err != nil {
						t.Fatal(err)
					}
					if clock.Sys().(*syscall.Stat_t).Ctim != original {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("kernel timestamp did not advance within private metadata model budget")
					}
					time.Sleep(time.Millisecond)
				}
				if err := os.WriteFile(path, []byte("changed!"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			held, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			visible, _ := os.Stat(path)
			if streamAccountExecutableStable(before, held, visible, before, held) {
				t.Fatal("changed original executable metadata accepted")
			}
		})
	}
}
