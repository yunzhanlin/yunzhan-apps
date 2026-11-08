package core

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"local/panel/internal/appcatalog"
)

const MemcachedUnixProfile = "memcached-unix-v1"
const MemcachedUnixLiveness = "test -S /run/memcached/cache.sock && kill -0 1"

// A selected website maps to its independently verified existing Linux
// account. Empty site means an administrator-only instance under the private
// executor anchor, NOT a shared unauthenticated TCP cache.
func MemcachedUnixDirectory(project, site string) (string, error) {
	if !ValidID(project) || site != "" && !ValidID(site) {
		return "", errors.New("Memcached Socket 实例或网站身份无效")
	}
	base := "/var/lib/panel-executor/memcached-sockets"
	if site != "" {
		base = "/srv/panel/memcached"
	}
	return filepath.Join(base, project), nil
}

func MemcachedUnixRequestCompose(project, site string) (string, error) {
	return memcachedUnixCompose(project, site, "__YZ_MEMCACHED_UID__:__YZ_MEMCACHED_GID__")
}

// UID/GID are resolved by the executor from the exact owned account, never
// accepted from an HTTP request or inferred from a mutable image username.
func MemcachedUnixRuntimeCompose(project, site string, uid, gid uint32) (string, error) {
	if uid == 0 || gid == 0 || uid > 0x7fffffff || gid > 0x7fffffff {
		return "", errors.New("Memcached Socket 运行账户必须为明确的非 root 账户")
	}
	return memcachedUnixCompose(project, site, strconv.FormatUint(uint64(uid), 10)+":"+strconv.FormatUint(uint64(gid), 10))
}

func memcachedUnixCompose(project, site, user string) (string, error) {
	directory, err := MemcachedUnixDirectory(project, site)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`services:
  memcached:
    image: %s
    user: "%s"
    entrypoint: ["memcached"]
    command: ["-s", "/run/memcached/cache.sock", "-a", "666", "-m", "128", "-I", "4m", "-U", "0", "-c", "256", "-t", "2"]
    labels:
      io.yunzhan.memcached.site-id: "%s"
    network_mode: none
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 192m
    memswap_limit: 192m
    pids_limit: 32
    cpus: "1.0"
    ulimits:
      nofile:
        soft: 1024
        hard: 1024
    volumes:
      - type: bind
        source: "%s"
        target: /run/memcached
        bind:
          create_host_path: false
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    healthcheck:
      test: ["CMD-SHELL", "%s"]
      interval: 10s
      timeout: 3s
      retries: 12
    stop_grace_period: 10s
`, appcatalog.MemcachedDigestImage, user, site, directory, MemcachedUnixLiveness), nil
}

// Socket existence/liveness is only Docker's local liveness probe. A genuine
// bounded version exchange with SO_PEERCRED matched to the actual container
// PID/UID is mandatory before accepting install/start/update readiness.
func ValidateMemcachedUnixRequest(template, profile, project, site, raw string) error {
	if profile != MemcachedUnixProfile || template != "memcached-cache" {
		return errors.New("Memcached Socket 执行策略不匹配")
	}
	want, err := MemcachedUnixRequestCompose(project, site)
	if err != nil || raw != want || strings.Count(raw, "type: bind") != 1 {
		return errors.New("Memcached Socket 请求不是原固定配置")
	}
	return nil
}
