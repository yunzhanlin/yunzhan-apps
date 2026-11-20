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

func TestRabbitMQColdCopySecuresOfficialComposeVolumeRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires native root")
	}
	for _, tc := range []struct {
		name      string
		uid, gid  int
		mode      uint32
		stickySub bool
		allowed   bool
	}{
		{"official root", 100, 101, 01777, false, true},
		{"different owner", 1234, 101, 01777, false, false},
		{"different group", 100, 1234, 01777, false, false},
		{"world writable", 100, 101, 0777, false, false},
		{"nested sticky mode", 100, 101, 01777, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			from := openRabbitMQCopyFixture(t, "source")
			to := openRabbitMQCopyFixture(t, "next")
			sub := filepath.Join(from.Name(), "mnesia")
			if err := os.Mkdir(sub, 0700); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(sub, "durable")
			if err := os.WriteFile(source, []byte("retained message"), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.stickySub {
				if err := unix.Chown(sub, 100, 101); err != nil {
					t.Fatal(err)
				}
				if err := unix.Chmod(sub, 01777); err != nil {
					t.Fatal(err)
				}
			}
			if err := unix.Fchown(int(from.Fd()), tc.uid, tc.gid); err != nil {
				t.Fatal(err)
			}
			if err := unix.Fchmod(int(from.Fd()), tc.mode); err != nil {
				t.Fatal(err)
			}
			receipt, err := copyRabbitMQColdVolume(t.Context(), from, to)
			if tc.allowed {
				if err != nil || receipt.Files != 1 {
					t.Fatalf("official volume did not copy: %#v %v", receipt, err)
				}
				got, err := rabbitMQCopyStat(to)
				if err != nil || got.Mode&07777 != 0700 || got.Uid != 100 || got.Gid != 101 {
					t.Fatalf("copied volume root permissions or ownership differ: %#v %v", got, err)
				}
				if contents, err := os.ReadFile(filepath.Join(to.Name(), "mnesia", "durable")); err != nil || string(contents) != "retained message" {
					t.Fatalf("copy differs from original: %v", err)
				}
			} else if !errors.Is(err, errRabbitMQCopyType) || receipt != (rabbitMQColdCopyResult{}) {
				t.Fatalf("unexpected volume was accepted: %#v %v", receipt, err)
			}
			got, err := rabbitMQCopyStat(from)
			if err != nil || got.Mode&07777 != tc.mode || got.Uid != uint32(tc.uid) || got.Gid != uint32(tc.gid) {
				t.Fatalf("original volume root changed: %#v %v", got, err)
			}
		})
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
