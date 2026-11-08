//go:build linux

package executor

import (
	"golang.org/x/sys/unix"
	"os/user"
	"strings"
	"testing"
)

func TestMemcachedUnixAdministratorAccountCannotGuessContainerOrBorrowServiceIdentity(t *testing.T) {
	u := &user.User{Username: "panel-memcached", Name: "panel-memcached", HomeDir: "/nonexistent", Uid: "1040", Gid: "1041"}
	g := &memcachedUnixGroup{Name: "panel-memcached", Gid: "1041"}
	for _, name := range []string{"valid", "missing", "uid-zero", "gid-zero", "foreign-comment", "foreign-name", "home", "shared-group", "member", "uid-alias", "gid-alias"} {
		t.Run(name, func(t *testing.T) {
			v, w := *u, *g
			switch name {
			case "uid-zero":
				v.Uid = "0"
			case "gid-zero":
				v.Gid = "0"
			case "foreign-comment":
				v.Name = "operator-owned"
			case "foreign-name":
				v.Username = "memcache"
			case "home":
				v.HomeDir = "/home/operator"
			case "shared-group":
				w.Name = "users"
			case "member":
				w.Members = []string{"other"}
			case "uid-alias":
				v.Uid = "01040"
			case "gid-alias":
				v.Gid = "01041"
			}
			lu := func(n string) (*user.User, error) {
				if name == "missing" {
					return nil, nil
				}
				if n != "panel-memcached" {
					t.Fatal("foreign lookup")
				}
				return &v, nil
			}
			lg := func(string) (*memcachedUnixGroup, error) { return &w, nil }
			a, e := memcachedUnixResolveAccount("", lu, lg)
			if (name == "valid") != (e == nil) {
				t.Fatal(name, e)
			}
			if e == nil && a != (memcachedUnixAccount{1040, 1041}) {
				t.Fatal("guessed image UID or changed dedicated account")
			}
		})
	}
}

func TestMemcachedUnixSocketContinuityIgnoresOnlyAccessTimeNotIdentityOrChanges(t *testing.T) {
	before := unix.Stat_t{Dev: 1, Ino: 2, Mode: unix.S_IFSOCK | 0666, Uid: 1010, Gid: 1011, Nlink: 1, Size: 0, Blksize: 4096, Atim: unix.Timespec{Sec: 100}, Mtim: unix.Timespec{Sec: 100}, Ctim: unix.Timespec{Sec: 100}}
	for _, seconds := range []int64{99, 100, 101} {
		after := before
		after.Atim = unix.Timespec{Sec: seconds, Nsec: 123}
		if !sameMemcachedUnixSocketObservation(before, after) {
			t.Fatal("ordinary access-time change was mistaken for peer replacement")
		}
	}
	for name, change := range map[string]func(*unix.Stat_t){
		"device": func(v *unix.Stat_t) { v.Dev++ }, "inode": func(v *unix.Stat_t) { v.Ino++ },
		"mode": func(v *unix.Stat_t) { v.Mode = unix.S_IFSOCK | 0660 }, "type": func(v *unix.Stat_t) { v.Mode = unix.S_IFREG | 0666 },
		"uid": func(v *unix.Stat_t) { v.Uid++ }, "gid": func(v *unix.Stat_t) { v.Gid++ }, "links": func(v *unix.Stat_t) { v.Nlink++ },
		"size": func(v *unix.Stat_t) { v.Size++ }, "block-size": func(v *unix.Stat_t) { v.Blksize++ }, "blocks": func(v *unix.Stat_t) { v.Blocks++ }, "rdev": func(v *unix.Stat_t) { v.Rdev++ },
		"mtime": func(v *unix.Stat_t) { v.Mtim.Nsec++ }, "ctime": func(v *unix.Stat_t) { v.Ctim.Nsec++ },
	} {
		t.Run(name, func(t *testing.T) {
			after := before
			after.Atim.Sec++
			change(&after)
			if sameMemcachedUnixSocketObservation(before, after) {
				t.Fatal("access-time exception borrowed changed inode/owner/mode or other fields")
			}
		})
	}
}

func TestMemcachedUnixProcessStatusBindsAllCredentialsAndEmptyOrPrivateGroups(t *testing.T) {
	a := memcachedUnixAccount{1040, 1041}
	good := strings.Replace(taskIdentityFixtureStatus("1040"), "ffffffffffffffff", "0000000000000000", 1) + "Gid:\t1041 1041 1041 1041\nGroups:\t\n"
	if !memcachedUnixProcessStatus(good, a) || !memcachedUnixProcessStatus(strings.Replace(good, "Groups:\t\n", "Groups:\t1041\n", 1), a) {
		t.Fatal("valid zero-cap account refused")
	}
	for _, raw := range []string{
		strings.Replace(good, "1041 1041 1041 1041", "1041 1041 0 1041", 1),
		strings.Replace(good, "1041 1041 1041 1041", "1041 1041 1041", 1),
		strings.Replace(good, "Groups:\t\n", "Groups:\t1042\n", 1),
		strings.Replace(good, "Groups:\t\n", "Groups:\t1041 1041\n", 1),
		strings.Replace(good, "Groups:\t\n", "", 1),
		strings.Replace(good, "CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001", 1),
		good + "Gid:\t1041 1041 1041 1041\n", good + "Groups:\t\n", good + "CapBnd:\t0000000000000000\n",
	} {
		if memcachedUnixProcessStatus(raw, a) {
			t.Fatal("changed/missing/duplicate process credential accepted")
		}
	}
	if memcachedUnixProcessStatus(good, memcachedUnixAccount{}) || memcachedUnixProcessStatus(good, memcachedUnixAccount{1042, 1041}) {
		t.Fatal("unrelated account borrowed process")
	}
}
