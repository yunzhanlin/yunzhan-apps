//go:build linux

package executor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Fault adapters are private to this test file. Production always opens native
// descriptors and has no injectable I/O policy.
type pm2ConfigFaultFile struct {
	*os.File
	writeError, readError, syncError, closeError error
	shortWrite                                   bool
	syncCalls, closeCalls                        int
}

func (f *pm2ConfigFaultFile) Write(b []byte) (int, error) {
	if f.writeError != nil {
		return 0, f.writeError
	}
	if f.shortWrite {
		return f.File.Write(b[:len(b)/2])
	}
	return f.File.Write(b)
}
func (f *pm2ConfigFaultFile) Read(b []byte) (int, error) {
	if f.readError != nil {
		return 0, f.readError
	}
	return f.File.Read(b)
}
func (f *pm2ConfigFaultFile) Sync() error {
	f.syncCalls++
	if f.syncError != nil {
		return f.syncError
	}
	return f.File.Sync()
}
func (f *pm2ConfigFaultFile) Close() error {
	f.closeCalls++
	return errors.Join(f.File.Close(), f.closeError)
}

func TestPM2ConfigurationWriteRequiresCompleteWriteSyncAndClose(t *testing.T) {
	for _, mode := range []string{"success", "short", "ENOSPC", "sync-EIO", "close-EIO", "sync-and-close"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "immutable.result.json")
			f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			wrapped := &pm2ConfigFaultFile{File: f}
			var expected error
			switch mode {
			case "short":
				wrapped.shortWrite, expected = true, io.ErrShortWrite
			case "ENOSPC":
				wrapped.writeError, expected = unix.ENOSPC, unix.ENOSPC
			case "sync-EIO":
				wrapped.syncError, expected = unix.EIO, unix.EIO
			case "close-EIO":
				wrapped.closeError, expected = unix.EIO, unix.EIO
			case "sync-and-close":
				wrapped.syncError, wrapped.closeError, expected = unix.EIO, unix.EDQUOT, unix.EIO
			}
			raw := []byte("original-visible-terminal-record\n")
			err = pm2ConfigWriteDurable(wrapped, raw)
			if (err == nil) != (expected == nil) || expected != nil && !errors.Is(err, expected) {
				t.Fatal("incomplete durable write was acknowledged", err)
			}
			if mode == "sync-and-close" && !errors.Is(err, unix.EDQUOT) {
				t.Fatal("close failure erased the original sync failure or vice versa", err)
			}
			if wrapped.closeCalls != 1 || (mode == "short" || mode == "ENOSPC") && wrapped.syncCalls != 0 {
				t.Fatal("invalid close count or sync after failed write", wrapped.closeCalls, wrapped.syncCalls)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal("original failed file was deleted", readErr)
			}
			switch mode {
			case "short":
				if !bytes.Equal(got, raw[:len(raw)/2]) {
					t.Fatal("partial original was changed")
				}
			case "ENOSPC":
				if len(got) != 0 {
					t.Fatal("failed write fabricated a record")
				}
			default:
				if !bytes.Equal(got, raw) {
					t.Fatal("visible original bytes were changed")
				}
			}
		})
	}
}

func TestPM2ConfigurationReadableTerminalNeedsFreshStorageAcknowledgement(t *testing.T) {
	for _, mode := range []string{"success", "read-EIO", "sync-EIO", "close-EIO", "sync-and-close", "namespace-changed"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "original.result.json")
			raw := []byte("original-valid-looking-terminal-bytes\n")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			info, _ := os.Lstat(path)
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			wrapped := &pm2ConfigFaultFile{File: f}
			var expected error
			switch mode {
			case "read-EIO":
				wrapped.readError, expected = unix.EIO, unix.EIO
			case "sync-EIO":
				wrapped.syncError, expected = unix.EIO, unix.EIO
			case "close-EIO":
				wrapped.closeError, expected = unix.EIO, unix.EIO
			case "sync-and-close":
				wrapped.syncError, wrapped.closeError, expected = unix.EIO, unix.EDQUOT, unix.EIO
			case "namespace-changed":
				expected = errors.New("namespace changed")
			}
			got, err := pm2ConfigReadDurable(wrapped, info, func() bool { return mode != "namespace-changed" })
			if (err == nil) != (mode == "success") {
				t.Fatal("visible terminal was treated as durable despite I/O error", err)
			}
			if mode != "namespace-changed" && expected != nil && !errors.Is(err, expected) {
				t.Fatal("original storage failure lost", err)
			}
			if mode == "sync-and-close" && !errors.Is(err, unix.EDQUOT) {
				t.Fatal("additional close failure was lost", err)
			}
			if err != nil && got != nil || err == nil && !bytes.Equal(got, raw) || wrapped.closeCalls != 1 {
				t.Fatal("uncertain observation exposed usable terminal bytes or leaked a descriptor", got, err)
			}
			after, _ := os.Lstat(path)
			still, _ := os.ReadFile(path)
			if !programQueueSame(info, after) || !bytes.Equal(still, raw) {
				t.Fatal("observation rewrote or repaired an original")
			}
		})
	}
}

func TestPM2ConfigurationDirectorySyncAndCloseBothRequired(t *testing.T) {
	for _, mode := range []string{"success", "sync-EIO", "close-EIO", "sync-and-close", "namespace-changed"} {
		t.Run(mode, func(t *testing.T) {
			f, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			wrapped := &pm2ConfigFaultFile{File: f}
			switch mode {
			case "sync-EIO":
				wrapped.syncError = unix.EIO
			case "close-EIO":
				wrapped.closeError = unix.EIO
			case "sync-and-close":
				wrapped.syncError, wrapped.closeError = unix.EIO, unix.EDQUOT
			}
			err = pm2ConfigSyncDurable(wrapped, func() bool { return mode != "namespace-changed" })
			if (err == nil) != (mode == "success") || wrapped.closeCalls != 1 {
				t.Fatal("incomplete directory acknowledgement accepted", err)
			}
			if mode == "sync-and-close" && (!errors.Is(err, unix.EIO) || !errors.Is(err, unix.EDQUOT)) {
				t.Fatal("one of the original failures was erased", err)
			}
		})
	}
}
