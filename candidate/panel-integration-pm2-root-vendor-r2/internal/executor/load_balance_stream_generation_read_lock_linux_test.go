//go:build linux

package executor

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func streamRecordedLockFixture(t *testing.T) (string, func(int) *os.File) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "closed-observation.lock")
	if err := os.WriteFile(path, []byte("immutable closed observation\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path, func(flags int) *os.File {
		t.Helper()
		file, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		return file
	}
}

func TestStreamRecordedGenerationReadersShareWithoutGrantingWriter(t *testing.T) {
	path, open := streamRecordedLockFixture(t)
	first, second, writer := open(os.O_RDONLY), open(os.O_RDONLY), open(os.O_RDWR)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := streamLockRecordedGenerationRun(first); err != nil {
		t.Fatal(err)
	}
	if err := streamLockRecordedGenerationRun(second); err != nil {
		t.Fatalf("an independent recorded-data reader contends with another reader: %v", err)
	}
	probeWriter := func(blocked bool) {
		t.Helper()
		// A distinct actual process receives only this private fixture FD. No
		// host path, Core connection, service or application authority is used.
		command := exec.Command("/usr/bin/python3", "-I", "-B", "-c", "import fcntl,sys;\ntry:fcntl.flock(3,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError:sys.exit(42)\n")
		command.ExtraFiles = []*os.File{writer}
		err := command.Run()
		var exit *exec.ExitError
		if blocked {
			if !errors.As(err, &exit) || exit.ExitCode() != 42 {
				t.Fatalf("independent writer was not excluded: %v", err)
			}
		} else if err != nil {
			t.Fatalf("independent writer remained blocked after both readers closed: %v", err)
		}
	}
	probeWriter(true)
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	probeWriter(true)
	if err := syscall.Flock(int(second.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	probeWriter(false)
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("recorded data changed during read-only lock probes", err)
	}
}

func TestStreamRecordedGenerationReaderStillRejectsExclusiveWriter(t *testing.T) {
	_, open := streamRecordedLockFixture(t)
	writer, reader, other := open(os.O_RDWR), open(os.O_RDONLY), open(os.O_RDWR)
	if err := syscall.Flock(int(writer.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := streamLockRecordedGenerationRun(reader); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatal("a live exclusive writer was admitted", err)
	}
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatal("failed reader disturbed the original writer", err)
	}
	if err := syscall.Flock(int(writer.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := streamLockRecordedGenerationRun(reader); err != nil {
		t.Fatal(err)
	}
	if streamLockRecordedGenerationRun(nil) == nil {
		t.Fatal("missing original descriptor accepted")
	}
}
