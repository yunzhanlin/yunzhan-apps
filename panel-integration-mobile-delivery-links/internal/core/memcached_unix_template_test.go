package core

import (
	"strconv"
	"strings"
	"testing"
)

func TestMemcachedUnixProducerHasNoNetworkAndSeparatesAccountResolution(t *testing.T) {
	project, site := strings.Repeat("a", 32), strings.Repeat("b", 32)
	for _, scope := range []string{"", site} {
		t.Run(map[bool]string{true: "administrator-only", false: "selected-website"}[scope == ""], func(t *testing.T) {
			raw, err := MemcachedUnixRequestCompose(project, scope)
			if err != nil || ValidateMemcachedUnixRequest("memcached-cache", MemcachedUnixProfile, project, scope, raw) != nil {
				t.Fatal("canonical socket request", err)
			}
			dir, _ := MemcachedUnixDirectory(project, scope)
			for _, fixed := range []string{"network_mode: none", `user: "__YZ_MEMCACHED_UID__:__YZ_MEMCACHED_GID__"`, `"-s", "/run/memcached/cache.sock", "-a", "666"`, "read_only: true", "cap_drop: [ALL]", `security_opt: ["no-new-privileges:true"]`, "mem_limit: 192m", "memswap_limit: 192m", "pids_limit: 32", `cpus: "1.0"`, "create_host_path: false", dir, MemcachedUnixLiveness} {
				if !strings.Contains(raw, fixed) {
					t.Fatal("missing bound", fixed)
				}
			}
			for _, bad := range []string{"ports:", "127.0.0.1:", "networks:", "internal: true", "env_file:", "privileged:", "cap_add:", "docker.sock"} {
				if strings.Contains(raw, bad) {
					t.Fatal("network or host privilege appeared", bad)
				}
			}
			effective, err := MemcachedUnixRuntimeCompose(project, scope, 11211, 11211)
			if err != nil || !strings.Contains(effective, `user: "11211:11211"`) || strings.Contains(effective, "__YZ_") {
				t.Fatal("resolved exact account", err)
			}
			if ValidateMemcachedUnixRequest("memcached-cache", MemcachedUnixProfile, project, scope, effective) == nil {
				t.Fatal("caller supplied UID instead of executor resolution")
			}
			for _, changed := range []string{raw + "\n# extra", strings.Replace(raw, "network_mode: none", "network_mode: host", 1), strings.Replace(raw, dir, "/run/docker.sock", 1)} {
				if ValidateMemcachedUnixRequest("memcached-cache", MemcachedUnixProfile, project, scope, changed) == nil {
					t.Fatal("altered request accepted")
				}
			}
			if len(dir+"/cache.sock") >= 108 {
				t.Fatal("AF_UNIX path exceeds Linux limit")
			}
		})
	}
}

func TestMemcachedUnixRefusesBorrowedScopeAndRootAccount(t *testing.T) {
	project := strings.Repeat("a", 32)
	raw, _ := MemcachedUnixRequestCompose(project, "")
	for _, scope := range []string{"../other", "-option", "fake", strings.Repeat("A", 32)} {
		if _, err := MemcachedUnixRequestCompose(project, scope); err == nil {
			t.Fatal("foreign account selector")
		}
	}
	for _, uid := range []uint32{0, 0x80000000, 0xffffffff} {
		if _, err := MemcachedUnixRuntimeCompose(project, "", uid, 11211); err == nil {
			t.Fatal("unsafe uid", strconv.FormatUint(uint64(uid), 10))
		}
	}
	for _, gid := range []uint32{0, 0x80000000, 0xffffffff} {
		if _, err := MemcachedUnixRuntimeCompose(project, "", 11211, gid); err == nil {
			t.Fatal("unsafe gid")
		}
	}
	if ValidateMemcachedUnixRequest("mongodb", MemcachedUnixProfile, project, "", raw) == nil || ValidateMemcachedUnixRequest("memcached-cache", "memcached-sandbox-v1", project, "", raw) == nil || ValidateMemcachedUnixRequest("memcached-cache", MemcachedUnixProfile, strings.Repeat("b", 32), "", raw) == nil {
		t.Fatal("scope/profile borrowed")
	}
}
