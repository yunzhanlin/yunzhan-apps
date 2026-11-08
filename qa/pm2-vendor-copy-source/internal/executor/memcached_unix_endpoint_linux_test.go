//go:build linux

package executor

import (
	"errors"
	"os/user"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMemcachedUnixAccountRequiresExactExistingPrivateSiteIdentity(t *testing.T) {
	site := strings.Repeat("a", 32)
	name := siteUser(site)
	u := &user.User{Username: name, Name: "panel-managed-" + site, Uid: "1010", Gid: "1011"}
	g := &memcachedUnixGroup{Name: name, Gid: "1011", Members: []string{name}}
	lookupU := func(n string) (*user.User, error) {
		if n != name {
			return nil, errors.New("foreign")
		}
		v := *u
		return &v, nil
	}
	lookupG := func(n string) (*memcachedUnixGroup, error) {
		if n != u.Gid {
			return nil, errors.New("foreign")
		}
		v := *g
		return &v, nil
	}
	if a, e := memcachedUnixResolveAccount(site, lookupU, lookupG); e != nil || a.UID != 1010 || a.GID != 1011 {
		t.Fatal("managed account refused", e)
	}
	if a, e := memcachedUnixResolveAccount("", nil, nil); e == nil || a != (memcachedUnixAccount{}) {
		t.Fatal("missing dedicated administrator account was guessed")
	}
	for _, name := range []string{"root-uid", "root-gid", "uid-alias", "gid-alias", "uid-overflow", "foreign-name", "foreign-comment", "truncated-collision", "shared-group", "foreign-member", "missing-user", "missing-group"} {
		t.Run(name, func(t *testing.T) {
			v, w := *u, *g
			switch name {
			case "root-uid":
				v.Uid = "0"
			case "root-gid":
				v.Gid = "0"
			case "uid-alias":
				v.Uid = "01010"
			case "gid-alias":
				v.Gid = "01011"
			case "uid-overflow":
				v.Uid = "2147483648"
			case "foreign-name":
				v.Username = "root"
			case "foreign-comment":
				v.Name = "unmanaged"
			case "truncated-collision":
				v.Name = "panel-managed-" + strings.Repeat("a", 24) + strings.Repeat("b", 8)
			case "shared-group":
				w.Name = "users"
			case "foreign-member":
				w.Members = []string{"other"}
			}
			lu := func(string) (*user.User, error) {
				if name == "missing-user" {
					return nil, errors.New("absent")
				}
				return &v, nil
			}
			lg := func(string) (*memcachedUnixGroup, error) {
				if name == "missing-group" {
					return nil, errors.New("absent")
				}
				return &w, nil
			}
			if a, e := memcachedUnixResolveAccount(site, lu, lg); e == nil || a != (memcachedUnixAccount{}) {
				t.Fatal("unowned/shared account authorized", name)
			}
		})
	}
}

func TestMemcachedUnixGroupReaderRejectsAmbiguousMembership(t *testing.T) {
	if g, e := memcachedUnixDecodeGroup([]byte("root:x:0:\npsfixture:x:1011:psfixture\n"), "1011"); e != nil || g.Name != "psfixture" || len(g.Members) != 1 {
		t.Fatal("exact local managed group refused", e)
	}
	for _, raw := range []string{"", "psfixture:x:1011:psfixture\nother:x:1011:\n", "broken\npsfixture:x:1011:\n", "psfixture:x:1011:psfixture,psfixture\n", "psfixture:x:1011:psfixture,\n", "psfixture:x:1011: psfixture\n", "psfixture:x:1011:\x00\n", string([]byte{255}), strings.Repeat("x", (1<<20)+1)} {
		if _, e := memcachedUnixDecodeGroup([]byte(raw), "1011"); e == nil {
			t.Fatal("ambiguous group accepted")
		}
	}
}

func TestMemcachedUnixPeerMustBeTheActualNonRootContainerProcess(t *testing.T) {
	a := memcachedUnixAccount{11211, 11211}
	p := &unix.Ucred{Pid: 321, Uid: 11211, Gid: 11211}
	if !memcachedUnixPeerMatches(p, 321, a) {
		t.Fatal("exact kernel peer refused")
	}
	for _, bad := range []*unix.Ucred{nil, {Pid: 1, Uid: 11211, Gid: 11211}, {Pid: 322, Uid: 11211, Gid: 11211}, {Pid: 321, Uid: 0, Gid: 11211}, {Pid: 321, Uid: 11211, Gid: 0}, {Pid: 321, Uid: 11212, Gid: 11211}, {Pid: 321, Uid: 11211, Gid: 11212}} {
		if memcachedUnixPeerMatches(bad, 321, a) {
			t.Fatal("root, replaced or foreign process borrowed socket")
		}
	}
	if memcachedUnixPeerMatches(p, 0, a) || memcachedUnixPeerMatches(p, 321, memcachedUnixAccount{}) {
		t.Fatal("missing process/account authorized")
	}
}
