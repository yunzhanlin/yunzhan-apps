package executor

import (
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"local/panel/internal/core"
)

var errMemcachedUnixNSS = errors.New("Memcached 专用本地账户、锁定密码或私有组无法核对；未接管或修改现有账户")

const memcachedUnixAdminName = "panel-memcached"

type memcachedUnixNSSIdentity struct {
	Name, Comment, Home, Shell string
	UID, GID                   uint32
}

func memcachedUnixNSSNumber(raw string) (uint32, bool) {
	v, err := strconv.ParseUint(raw, 10, 32)
	return uint32(v), err == nil && strconv.FormatUint(v, 10) == raw
}

func memcachedUnixNSSRows(raw []byte, fields int) ([][]string, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) || strings.ContainsAny(string(raw), "\x00\r") || strings.Count(string(raw), "\n") > 65536 {
		return nil, errMemcachedUnixNSS
	}
	out := [][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != fields || f[0] == "" || strings.TrimSpace(f[0]) != f[0] {
			return nil, errMemcachedUnixNSS
		}
		out = append(out, f)
	}
	return out, nil
}

// A label/GECOS alone is never account ownership. Callers must also require a
// Root-owned creation receipt, fresh NSS lookup, unchanged source descriptors
// and the live kernel peer; this parser grants none of those authorities.
// Shadow bytes are input only; never return/store/log password fields.
// Password locking does not claim to disable all possible authentication.
func validateMemcachedUnixNSS(passwd, group, shadow, gshadow []byte, site string) (memcachedUnixNSSIdentity, error) {
	var empty memcachedUnixNSSIdentity
	if site != "" && !core.ValidID(site) {
		return empty, errMemcachedUnixNSS
	}
	name, comment, home := memcachedUnixAdminName, memcachedUnixAdminName, "/nonexistent"
	if site != "" {
		name, comment, home = "ps"+site[:24], "panel-managed-"+site, "/srv/panel/sites/"+site
	}
	users, err := memcachedUnixNSSRows(passwd, 7)
	if err != nil {
		return empty, err
	}
	selected := []string(nil)
	for _, f := range users {
		if f[0] == name {
			if selected != nil {
				return empty, errMemcachedUnixNSS
			}
			selected = f
		}
	}
	if selected == nil {
		return empty, errMemcachedUnixNSS
	}
	uid, ok1 := memcachedUnixNSSNumber(selected[2])
	gid, ok2 := memcachedUnixNSSNumber(selected[3])
	if !ok1 || !ok2 || uid == 0 || gid == 0 || uid > 0x7fffffff || gid > 0x7fffffff ||
		selected[1] != "x" || selected[4] != comment || selected[5] != home ||
		selected[6] != "/usr/sbin/nologin" && selected[6] != "/sbin/nologin" {
		return empty, errMemcachedUnixNSS
	}
	for _, f := range users {
		u, good1 := memcachedUnixNSSNumber(f[2])
		g, good2 := memcachedUnixNSSNumber(f[3])
		if !good1 || !good2 || f[0] != name && (u == uid || g == gid) {
			return empty, errMemcachedUnixNSS
		}
	}
	groups, err := memcachedUnixNSSRows(group, 4)
	if err != nil {
		return empty, err
	}
	matched := false
	members := ""
	for _, f := range groups {
		g, good := memcachedUnixNSSNumber(f[2])
		if !good {
			return empty, errMemcachedUnixNSS
		}
		if f[0] != name && g != gid {
			for _, member := range strings.Split(f[3], ",") {
				if strings.TrimSpace(member) == name {
					return empty, errMemcachedUnixNSS
				}
			}
			continue
		}
		if matched || f[0] != name || g != gid || f[1] != "x" || f[3] != "" && f[3] != name {
			return empty, errMemcachedUnixNSS
		}
		matched = true
		members = f[3]
	}
	if !matched {
		return empty, errMemcachedUnixNSS
	}
	secrets, err := memcachedUnixNSSRows(shadow, 9)
	if err != nil {
		return empty, err
	}
	matched = false
	for _, f := range secrets {
		if f[0] != name {
			continue
		}
		if matched || f[1] == "" || !strings.HasPrefix(f[1], "!") && !strings.HasPrefix(f[1], "*") {
			return empty, errMemcachedUnixNSS
		}
		matched = true
	}
	if !matched {
		return empty, errMemcachedUnixNSS
	}
	privateGroups, err := memcachedUnixNSSRows(gshadow, 4)
	if err != nil {
		return empty, err
	}
	matched = false
	for _, f := range privateGroups {
		if f[0] != name {
			for _, list := range f[2:4] {
				for _, member := range strings.Split(list, ",") {
					if strings.TrimSpace(member) == name {
						return empty, errMemcachedUnixNSS
					}
				}
			}
			continue
		}
		// No group password or delegated group administrator may grant an
		// outsider access through newgrp/gpasswd despite an empty user_list.
		if matched || f[1] == "" || !strings.HasPrefix(f[1], "!") && !strings.HasPrefix(f[1], "*") || f[2] != "" || f[3] != members {
			return empty, errMemcachedUnixNSS
		}
		matched = true
	}
	if !matched {
		return empty, errMemcachedUnixNSS
	}
	return memcachedUnixNSSIdentity{Name: name, Comment: comment, Home: home, Shell: selected[6], UID: uid, GID: gid}, nil
}
