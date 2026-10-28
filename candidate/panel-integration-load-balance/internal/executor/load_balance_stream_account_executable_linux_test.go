//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
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

// Real private filesystem metadata, not a fabricated FileInfo or a host ELF
// mutation. Even same-length content changes with restored mtime change ctime.
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
