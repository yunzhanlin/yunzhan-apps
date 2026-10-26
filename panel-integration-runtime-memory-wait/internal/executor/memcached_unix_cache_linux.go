//go:build linux

package executor

import (
	"context"
	"errors"

	"local/panel/internal/core"
)

var errMemcachedUnixCacheUnknown = errors.New("缓存请求已开始发送但结果不能核对；未自动重试，请查询原键和版本标记后决定")

// Native private transport only. A production workspace must first verify its
// original signed installation/actor/Core binding, actual Docker/kernel state
// and owned account. No HTTP caller supplies path/PID/UID. Same-connection
// SO_PEERCRED/pidfd checks complete BEFORE any request byte; no TCP fallback.
func exchangeMemcachedUnixCacheAt(ctx context.Context, path string, pid int, account memcachedUnixAccount, in core.MemcachedUnixCacheInput) (core.MemcachedUnixCacheResult, error) {
	return exchangeMemcachedUnixCacheGatedAt(ctx, path, pid, account, in, nil)
}

// The private native fixture may use the ungated transport above. Production
// workspace supplies its compiled current-install/actor recheck here, after
// actual peer verification and immediately before any data byte is written.
func exchangeMemcachedUnixCacheGatedAt(ctx context.Context, path string, pid int, account memcachedUnixAccount, in core.MemcachedUnixCacheInput, beforeWrite func(context.Context) error) (core.MemcachedUnixCacheResult, error) {
	var empty core.MemcachedUnixCacheResult
	packet, err := memcachedUnixCachePacket(in)
	if err != nil {
		return empty, err
	}
	defer clear(packet)
	conn, err := dialMemcachedUnixVerifiedAt(ctx, path, pid, account)
	if err != nil {
		return empty, err
	}
	defer conn.Close()
	if beforeWrite != nil {
		if err := beforeWrite(conn.bound); err != nil {
			return empty, err
		}
	}
	if conn.bound.Err() != nil || !redisPeerPIDAlive(conn.pidfd) {
		return empty, errMemcachedUnixProtocol
	}
	n, err := conn.Write(packet)
	if err != nil || n != len(packet) {
		if in.Action == "get" || in.Action == "stats" {
			return empty, errMemcachedUnixProtocol
		}
		return empty, errMemcachedUnixCacheUnknown
	}
	out, err := readMemcachedUnixCacheReply(conn, in.Action)
	if err != nil {
		if errors.Is(err, errMemcachedUnixCAS) || errors.Is(err, errMemcachedUnixMissing) || errors.Is(err, errMemcachedUnixExists) || errors.Is(err, errMemcachedUnixConsoleLarge) {
			return empty, err
		}
		if in.Action != "get" && in.Action != "stats" {
			return empty, errMemcachedUnixCacheUnknown
		}
		return empty, err
	}
	if conn.bound.Err() != nil || !redisPeerPIDAlive(conn.pidfd) {
		if in.Action != "get" && in.Action != "stats" {
			return empty, errMemcachedUnixCacheUnknown
		}
		return empty, errMemcachedUnixProtocol
	}
	return out, nil
}
