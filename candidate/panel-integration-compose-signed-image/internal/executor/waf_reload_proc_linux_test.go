//go:build linux

package executor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

type wafReloadFailingReader struct{ err error }

func (r wafReloadFailingReader) Read(p []byte) (int, error) {
	return copy(p, "private partial record"), r.err
}

func TestWAFReloadProcReadPreservesOnlyVerifiedKernelExit(t *testing.T) {
	for _, cause := range []error{syscall.ESRCH, syscall.ENOENT, syscall.EACCES, syscall.EIO} {
		t.Run(cause.Error(), func(t *testing.T) {
			private := &os.PathError{Op: "read", Path: "/private-not-for-receipt/process", Err: cause}
			data, err := readWAFReloadProcData(wafReloadFailingReader{private}, 1024)
			if data != nil || err == nil || !errors.Is(err, cause) {
				t.Fatal("partial bytes or original errno lost", len(data), err)
			}
			wantGone := cause == syscall.ESRCH || cause == syscall.ENOENT
			if errors.Is(err, os.ErrNotExist) != wantGone || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "partial record") {
				t.Fatal("unverified disappearance or private data in receipt", err)
			}
			root := wafReloadFixture(t)
			g, e := captureWAFReloadGeneration(t.Context(), root, wafReloadFixtureBinary, 100)
			if e != nil {
				t.Fatal(e)
			}
			// Even ESRCH from a different read cannot mark an independently
			// verified live original worker as drained.
			gone, e := g.workerSocketReadError(g.Workers[0], err)
			if gone || (e != nil) != (cause != syscall.EACCES) {
				t.Fatal("live worker must remain undrained; permission races retain the original bounded wait", gone, e)
			}
			if e = os.Remove(filepath.Join(root, "101/stat")); e != nil {
				t.Fatal(e)
			}
			gone, e = g.workerSocketReadError(g.Workers[0], err)
			if !gone || e != nil {
				t.Fatal("independently verified exit rejected", gone, e)
			}
		})
	}
}

func TestWAFReloadProcReadKeepsOriginalBudgets(t *testing.T) {
	for _, n := range []int{0, 1, 128, 8192} {
		data := bytes.Repeat([]byte{'x'}, n)
		got, err := readWAFReloadProcData(bytes.NewReader(data), 8192)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal(n, len(got), err)
		}
	}
	if got, err := readWAFReloadProcData(bytes.NewReader(bytes.Repeat([]byte{'x'}, 8193)), 8192); got != nil || err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("oversize accepted or treated as process exit", len(got), err)
	}
	for _, limit := range []int64{-1, 0, (16 << 20) + 1} {
		if got, err := readWAFReloadProcData(strings.NewReader("x"), limit); got != nil || err == nil {
			t.Fatal(limit, got, err)
		}
	}
	if _, err := readWAFReloadProcData(nil, 8192); err == nil {
		t.Fatal("nil reader accepted")
	}
	data, err := readWAFReloadProcData(strings.NewReader(""), 8192)
	if err != nil || len(data) != 0 {
		t.Fatal("empty record must reach existing identity validation", err)
	}
}

func TestWAFReloadOriginalOpenProcDescriptorsAfterOwnedChildExit(t *testing.T) {
	child := exec.Command("/usr/bin/sleep", "0.10")
	child.Stdin, child.Stdout, child.Stderr = nil, io.Discard, io.Discard
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	files := map[string]*os.File{}
	for _, name := range []string{"stat", "status", "cmdline"} {
		f, err := os.Open(filepath.Join("/proc", strconv.Itoa(child.Process.Pid), name))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		files[name] = f
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	for name, f := range files {
		data, err := readWAFReloadProcData(f, 8192)
		if data != nil || !errors.Is(err, syscall.ESRCH) || !errors.Is(err, os.ErrNotExist) {
			t.Fatal("actual held proc fd exit not classified", name, len(data), err)
		}
	}
}
