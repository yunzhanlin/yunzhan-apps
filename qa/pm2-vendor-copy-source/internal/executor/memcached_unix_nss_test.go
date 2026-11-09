package executor

import (
	"bytes"
	"strings"
	"testing"
)

func memcachedUnixNSSFixture(site string) ([]byte, []byte, []byte, []byte, string) {
	name, comment, home := memcachedUnixAdminName, memcachedUnixAdminName, "/nonexistent"
	if site != "" {
		name, comment, home = "ps"+site[:24], "panel-managed-"+site, "/srv/panel/sites/"+site
	}
	passwd := "root:x:0:0:root:/root:/bin/bash\nunrelated:x:4294967294:4294967294:other:/nonexistent:/sbin/nologin\n" + name + ":x:123:234:" + comment + ":" + home + ":/usr/sbin/nologin\n"
	group := "root:x:0:\nunrelated:x:4294967294:\n" + name + ":x:234:\n"
	shadow := "root:!:20000:0:99999:7:::\n" + name + ":!:20000:0:99999:7:::\n"
	gshadow := "root:*::\n" + name + ":!::\n"
	return []byte(passwd), []byte(group), []byte(shadow), []byte(gshadow), name
}

func TestMemcachedUnixNSSClosedAdministratorAndWebsiteIdentity(t *testing.T) {
	for _, site := range []string{"", strings.Repeat("a", 32)} {
		p, g, s, gs, name := memcachedUnixNSSFixture(site)
		before := [][]byte{bytes.Clone(p), bytes.Clone(g), bytes.Clone(s), bytes.Clone(gs)}
		for _, shell := range []string{"/usr/sbin/nologin", "/sbin/nologin"} {
			candidate := bytes.Replace(p, []byte(":/usr/sbin/nologin\n"), []byte(":"+shell+"\n"), 1)
			v, err := validateMemcachedUnixNSS(candidate, g, s, gs, site)
			if err != nil || v.Name != name || v.UID != 123 || v.GID != 234 || v.Shell != shell {
				t.Fatal("closed independent non-login identity refused", site, err)
			}
		}
		for _, locked := range []string{"!", "!!", "!$6$fixtureLocked", "*", "*fixture"} {
			candidate := bytes.Replace(s, []byte(name+":!:"), []byte(name+":"+locked+":"), 1)
			if _, err := validateMemcachedUnixNSS(p, g, candidate, gs, site); err != nil {
				t.Fatal("locked password representation refused")
			}
		}
		withSelf := bytes.Replace(g, []byte(name+":x:234:\n"), []byte(name+":x:234:"+name+"\n"), 1)
		groupSelf := bytes.Replace(gs, []byte(name+":!::\n"), []byte(name+":!::"+name+"\n"), 1)
		if _, err := validateMemcachedUnixNSS(p, withSelf, s, groupSelf, site); err != nil {
			t.Fatal("private self-only group refused", err)
		}
		for i, raw := range [][]byte{p, g, s, gs} {
			if !bytes.Equal(raw, before[i]) {
				t.Fatal("pure account verification changed source/password bytes")
			}
		}
	}
}

func TestMemcachedUnixNSSRejectsSharedUnlockedAliasedAndMalformedAccounts(t *testing.T) {
	for _, site := range []string{"", strings.Repeat("b", 32)} {
		p, g, s, gs, name := memcachedUnixNSSFixture(site)
		changes := map[string]func([][]byte){
			"uid-root":            func(v [][]byte) { v[0] = bytes.Replace(v[0], []byte(name+":x:123:"), []byte(name+":x:0:"), 1) },
			"gid-root":            func(v [][]byte) { v[0] = bytes.Replace(v[0], []byte(name+":x:123:234:"), []byte(name+":x:123:0:"), 1) },
			"uid-alias":           func(v [][]byte) { v[0] = bytes.Replace(v[0], []byte(name+":x:123:"), []byte(name+":x:0123:"), 1) },
			"uid-too-large":       func(v [][]byte) { v[0] = bytes.Replace(v[0], []byte(name+":x:123:"), []byte(name+":x:2147483648:"), 1) },
			"foreign-uid-owner":   func(v [][]byte) { v[0] = append(v[0], []byte("foreign:x:123:444:foreign:/none:/sbin/nologin\n")...) },
			"foreign-primary-gid": func(v [][]byte) { v[0] = append(v[0], []byte("foreign:x:444:234:foreign:/none:/sbin/nologin\n")...) },
			"duplicate-user":      func(v [][]byte) { v[0] = append(v[0], []byte(name+":x:999:999:foreign:/none:/sbin/nologin\n")...) },
			"foreign-comment":     func(v [][]byte) { v[0] = bytes.Replace(v[0], []byte(":123:234:"), []byte(":123:234:forged-"), 1) },
			"home-alias": func(v [][]byte) {
				v[0] = bytes.Replace(v[0], []byte(":/usr/sbin/nologin\n"), []byte("/../alias:/usr/sbin/nologin\n"), 1)
			},
			"interactive-shell":   func(v [][]byte) { v[0] = bytes.Replace(v[0], []byte(":/usr/sbin/nologin\n"), []byte(":/bin/sh\n"), 1) },
			"empty-shell":         func(v [][]byte) { v[0] = bytes.Replace(v[0], []byte(":/usr/sbin/nologin\n"), []byte(":\n"), 1) },
			"passwd-not-shadowed": func(v [][]byte) { v[0] = bytes.Replace(v[0], []byte(name+":x:"), []byte(name+":!:"), 1) },
			"shared-group-member": func(v [][]byte) {
				v[1] = bytes.Replace(v[1], []byte(name+":x:234:\n"), []byte(name+":x:234:foreign\n"), 1)
			},
			"duplicate-private-group":   func(v [][]byte) { v[1] = append(v[1], []byte(name+":x:234:\n")...) },
			"gid-name-alias":            func(v [][]byte) { v[1] = append(v[1], []byte("foreign:x:234:\n")...) },
			"group-not-shadowed":        func(v [][]byte) { v[1] = bytes.Replace(v[1], []byte(name+":x:234:"), []byte(name+":!:234:"), 1) },
			"extra-supplementary-group": func(v [][]byte) { v[1] = append(v[1], []byte("foreign:x:444:"+name+"\n")...) },
			"unlocked-password": func(v [][]byte) {
				v[2] = bytes.Replace(v[2], []byte(name+":!:"), []byte(name+":$6$fixtureNotLocked:"), 1)
			},
			"empty-password":   func(v [][]byte) { v[2] = bytes.Replace(v[2], []byte(name+":!:"), []byte(name+"::"), 1) },
			"duplicate-shadow": func(v [][]byte) { v[2] = append(v[2], []byte(name+":!:20000:0:99999:7:::\n")...) },
			"unlocked-group-password": func(v [][]byte) {
				v[3] = bytes.Replace(v[3], []byte(name+":!::"), []byte(name+":$6$fixtureGroup::"), 1)
			},
			"delegated-group-admin":  func(v [][]byte) { v[3] = bytes.Replace(v[3], []byte(name+":!::"), []byte(name+":!:foreign:"), 1) },
			"gshadow-extra-member":   func(v [][]byte) { v[3] = bytes.Replace(v[3], []byte(name+":!::\n"), []byte(name+":!::foreign\n"), 1) },
			"duplicate-gshadow":      func(v [][]byte) { v[3] = append(v[3], []byte(name+":!::\n")...) },
			"foreign-group-admin":    func(v [][]byte) { v[3] = append(v[3], []byte("foreign:!:"+name+":\n")...) },
			"foreign-gshadow-member": func(v [][]byte) { v[3] = append(v[3], []byte("foreign:!::"+name+"\n")...) },
			"missing-group":          func(v [][]byte) { v[1] = []byte("root:x:0:\n") },
			"missing-shadow":         func(v [][]byte) { v[2] = []byte("root:!:20000:0:99999:7:::\n") },
			"missing-gshadow":        func(v [][]byte) { v[3] = []byte("root:*::\n") },
		}
		for label, change := range changes {
			t.Run(site+"/"+label, func(t *testing.T) {
				value := [][]byte{bytes.Clone(p), bytes.Clone(g), bytes.Clone(s), bytes.Clone(gs)}
				change(value)
				if _, err := validateMemcachedUnixNSS(value[0], value[1], value[2], value[3], site); err == nil {
					t.Fatal("unsafe account identity accepted")
				}
			})
		}
		for index := 0; index < 4; index++ {
			for _, malformed := range [][]byte{nil, []byte{0xff}, []byte("malformed\n"), bytes.Repeat([]byte("\n"), 65537), bytes.Repeat([]byte("x"), (1<<20)+1), []byte("bad:x:1:\x00\n")} {
				value := [][]byte{bytes.Clone(p), bytes.Clone(g), bytes.Clone(s), bytes.Clone(gs)}
				value[index] = malformed
				if _, err := validateMemcachedUnixNSS(value[0], value[1], value[2], value[3], site); err == nil {
					t.Fatal("malformed/oversized/unknown input accepted", index)
				}
			}
		}
		if _, err := validateMemcachedUnixNSS(p, g, s, gs, "not-a-site"); err == nil {
			t.Fatal("caller-selected account scope accepted")
		}
	}
}
