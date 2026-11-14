//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func openRabbitMQCopyFixture(t *testing.T, name string) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	fd, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fd.Close() })
	return fd
}

func TestRabbitMQColdCopyPreservesIndependentBytesAndMetadata(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires native root")
	}
	from := openRabbitMQCopyFixture(t, "source")
	to := openRabbitMQCopyFixture(t, "next")
	second := openRabbitMQCopyFixture(t, "next-again")
	sub := filepath.Join(from.Name(), "mnesia")
	source := filepath.Join(sub, "durable")
	if err := os.Mkdir(sub, 0750); err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenFile(source, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Close() })
	if _, err = opened.WriteString("classic and quorum payload"); err != nil {
		t.Fatal(err)
	}
	if err := opened.Chown(31310, 31311); err != nil {
		t.Fatal(err)
	}
	when := time.Unix(1_750_000_000, 123456789)
	if err := os.Chtimes(source, when, when); err != nil {
		t.Fatal(err)
	}
	one, err := copyRabbitMQColdVolume(t.Context(), from, to)
	if err != nil {
		t.Fatal(err)
	}
	two, err := copyRabbitMQColdVolume(t.Context(), from, second)
	if err != nil || one != two || one.Files != 1 || one.Directories != 2 || one.Bytes != int64(len("classic and quorum payload")) || len(one.SHA256) != 64 {
		t.Fatalf("incorrect receipt %v %v %v", one, two, err)
	}
	copied := filepath.Join(to.Name(), "mnesia", "durable")
	a, err := rabbitMQCopyStat(opened)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Open(copied)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	b, err := rabbitMQCopyStat(target)
	if err != nil || a.Dev == b.Dev && a.Ino == b.Ino || a.Uid != b.Uid || a.Gid != b.Gid ||
		a.Mode != b.Mode || a.Atim != b.Atim || a.Mtim != b.Mtim {
		t.Fatalf("copy did not preserve metadata and assign a new inode: %v %v %v", a, b, err)
	}
	if _, err := opened.WriteAt([]byte("changed"), 0); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(copied); err != nil || string(raw) != "classic and quorum payload" {
		t.Fatalf("original writer mutated the independently verified copy: %q %v", raw, err)
	}
	if _, err := copyRabbitMQColdVolume(t.Context(), from, to); err == nil {
		t.Fatal("reused a populated volume")
	}
}

func TestRabbitMQColdCopyRefusesUnsafeObjectsAndLeavesSource(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires native root")
	}
	for _, fixture := range []string{"symlink", "hardlink", "fifo", "attributes"} {
		t.Run(fixture, func(t *testing.T) {
			src := openRabbitMQCopyFixture(t, "source")
			dst := openRabbitMQCopyFixture(t, "next")
			allowed := filepath.Join(src.Name(), "01-original")
			unsafe := filepath.Join(src.Name(), "99-unexpected")
			if err := os.WriteFile(allowed, []byte("actual original"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch fixture {
			case "symlink":
				err = os.Symlink(allowed, unsafe)
			case "hardlink":
				err = os.Link(allowed, unsafe)
			case "fifo":
				err = unix.Mkfifo(unsafe, 0600)
			case "attributes":
				if err := os.WriteFile(unsafe, []byte("with attributes"), 0600); err != nil {
					t.Fatal(err)
				}
				err = unix.Setxattr(unsafe, "user.fixture", []byte("evidence"), 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			if result, err := copyRabbitMQColdVolume(t.Context(), src, dst); err == nil || result != (rabbitMQColdCopyResult{}) {
				t.Fatalf("unsafe input got a successful receipt: %v %v", result, err)
			}
			if actual, err := os.ReadFile(allowed); err != nil || string(actual) != "actual original" {
				t.Fatalf("original data was changed: %q %v", actual, err)
			}
			if _, err := os.Lstat(filepath.Join(dst.Name(), "99-unexpected")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe entry was written: %v", err)
			}
		})
	}
	from := openRabbitMQCopyFixture(t, "source")
	to := openRabbitMQCopyFixture(t, "next")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if report, err := copyRabbitMQColdVolume(ctx, from, to); !errors.Is(err, context.Canceled) || report != (rabbitMQColdCopyResult{}) {
		t.Fatalf("request cancellation yielded a success receipt: %v %v", report, err)
	}
}
