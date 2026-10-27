//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Synthetic metadata contains no host account or password data.
type memcachedUnixNSSInfoFixture struct {
	mode os.FileMode
	size int64
	stat syscall.Stat_t
}

func (v memcachedUnixNSSInfoFixture) Name() string       { return "fixture" }
func (v memcachedUnixNSSInfoFixture) Size() int64        { return v.size }
func (v memcachedUnixNSSInfoFixture) Mode() os.FileMode  { return v.mode }
func (v memcachedUnixNSSInfoFixture) ModTime() time.Time { return time.Unix(100, 0) }
func (v memcachedUnixNSSInfoFixture) IsDir() bool        { return v.mode.IsDir() }
func (v memcachedUnixNSSInfoFixture) Sys() any           { s := v.stat; return &s }

func TestMemcachedUnixNSSFileMetadataKeepsSecretsPrivateAndRootOwned(t *testing.T) {
	base := memcachedUnixNSSInfoFixture{mode: 0644, size: 128, stat: syscall.Stat_t{Uid: 0, Gid: 0, Nlink: 1}}
	if !memcachedUnixNSSFileInfo(base, false) || memcachedUnixNSSFileInfo(base, true) || memcachedUnixNSSFileInfo(nil, false) {
		t.Fatal("public/private metadata distinction lost")
	}
	for _, mode := range []os.FileMode{0400, 0600, 0640} {
		v := base
		v.mode = mode
		if !memcachedUnixNSSFileInfo(v, true) {
			t.Fatal("Root-owned locked account file refused", mode)
		}
	}
	for name, change := range map[string]func(*memcachedUnixNSSInfoFixture){
		"unowned":     func(v *memcachedUnixNSSInfoFixture) { v.stat.Uid = 1000 },
		"hardlink":    func(v *memcachedUnixNSSInfoFixture) { v.stat.Nlink = 2 },
		"unlinked":    func(v *memcachedUnixNSSInfoFixture) { v.stat.Nlink = 0 },
		"empty":       func(v *memcachedUnixNSSInfoFixture) { v.size = 0 },
		"negative":    func(v *memcachedUnixNSSInfoFixture) { v.size = -1 },
		"large":       func(v *memcachedUnixNSSInfoFixture) { v.size = (1 << 20) + 1 },
		"group-write": func(v *memcachedUnixNSSInfoFixture) { v.mode = 0660 },
		"other-write": func(v *memcachedUnixNSSInfoFixture) { v.mode = 0602 },
		"execute":     func(v *memcachedUnixNSSInfoFixture) { v.mode = 0700 },
		"directory":   func(v *memcachedUnixNSSInfoFixture) { v.mode = os.ModeDir | 0600 },
		"socket":      func(v *memcachedUnixNSSInfoFixture) { v.mode = os.ModeSocket | 0600 },
		"pipe":        func(v *memcachedUnixNSSInfoFixture) { v.mode = os.ModeNamedPipe | 0600 },
		"symlink":     func(v *memcachedUnixNSSInfoFixture) { v.mode = os.ModeSymlink | 0600 },
		"setuid":      func(v *memcachedUnixNSSInfoFixture) { v.mode = os.ModeSetuid | 0600 },
		"setgid":      func(v *memcachedUnixNSSInfoFixture) { v.mode = os.ModeSetgid | 0600 },
		"sticky":      func(v *memcachedUnixNSSInfoFixture) { v.mode = os.ModeSticky | 0600 },
	} {
		t.Run(name, func(t *testing.T) {
			v := base
			change(&v)
			if memcachedUnixNSSFileInfo(v, false) || memcachedUnixNSSFileInfo(v, true) {
				t.Fatal("unsafe file authorized")
			}
		})
	}
	for _, mode := range []os.FileMode{0601, 0604, 0644} {
		v := base
		v.mode = mode
		if memcachedUnixNSSFileInfo(v, true) {
			t.Fatal("secret source readable/executable by other users")
		}
	}
}

func TestMemcachedUnixNSSFixedSourceRefusesAliasesBeforeOpening(t *testing.T) {
	for _, path := range []string{"", "passwd", "/etc//passwd", "/etc/./passwd", "/etc/passwd/..", "/tmp/passwd", "/proc/self/fd/0", "/etc/nsswitch.conf", "/etc/passwd\x00"} {
		if file, raw, err := openMemcachedUnixNSSFile(path); err == nil || file != nil || raw != nil {
			t.Fatal("configuration supplied a secret source", path)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, value := range []context.Context{nil, ctx} {
		if account, err := memcachedUnixSystemAccount(value, ""); err == nil || account != (memcachedUnixAccount{}) {
			t.Fatal("expired caller reached NSS admission")
		}
	}
	if account, err := memcachedUnixSystemAccount(context.Background(), "../other"); err == nil || account != (memcachedUnixAccount{}) {
		t.Fatal("site path reached NSS admission")
	}
}

func TestMemcachedUnixNSSHeldPrivateFixtureRejectsChangedInodeModeAndContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-fixture")
	if err := os.WriteFile(path, []byte("synthetic fixture only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	r := &memcachedUnixNSSFile{path: path, private: true, file: f, before: before}
	if os.Geteuid() != 0 {
		if r.current() {
			t.Fatal("unprivileged fixture borrowed Root source identity")
		}
		return
	}
	if !r.current() {
		t.Fatal("unchanged private Root fixture refused")
	}
	// Linux may reuse one coarse inode-clock tick for immediate chmod/restore.
	// Separate the OWN fixture transition, then require an actually different
	// kernel ctime before testing the unchanged production comparison.
	time.Sleep(25 * time.Millisecond)
	if err := os.Chmod(path, 0644); err != nil || r.current() {
		t.Fatal("changed secret permissions authorized", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	observed, err := f.Stat()
	if err != nil || before.Sys().(*syscall.Stat_t).Ctim == observed.Sys().(*syscall.Stat_t).Ctim {
		t.Fatal("own ctime fixture has no observable kernel transition", err)
	}
	if r.current() {
		t.Fatal("restored mode erased actual ctime drift")
	}
	if err := os.Rename(path, path+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("synthetic fixture only\n"), 0600); err != nil || r.current() {
		t.Fatal("same-byte replacement borrowed held descriptor", err)
	}
}
