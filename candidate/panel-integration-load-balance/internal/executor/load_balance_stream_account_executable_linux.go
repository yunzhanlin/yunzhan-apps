//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"time"
)

// Integrity observation only, never a cached actor, process or effect grant.
// Hash the actual same-programme inode once while its descriptor is held.
// Every use still observes the live parent's procfs name and this process's
// executable, including inode, size, mode, UID/GID, link count, mtime and ctime.
// Closing or replacing the descriptor cannot reopen or refresh this witness.
type loadBalanceStreamAccountExecutable struct {
	file   *os.File
	before os.FileInfo
	sha256 string
}

func (e *loadBalanceStreamAccountExecutable) close() {
	if e != nil && e.file != nil {
		e.file.Close()
		e.file = nil
	}
}

func streamAccountExecutableStable(original, held, parent, self, after os.FileInfo) bool {
	return original != nil && original.Mode().IsRegular() && original.Size() > 0 && original.Size() <= 128<<20 &&
		geoStoreStableInfo(original, held) && geoStoreStableInfo(held, parent) &&
		geoStoreStableInfo(held, self) && geoStoreStableInfo(held, after)
}

func (e *loadBalanceStreamAccountExecutable) current(ctx context.Context, pid uint32, expected string) bool {
	if ctx == nil || ctx.Err() != nil || e == nil || e.file == nil || pid <= 1 || pid > 2147483647 ||
		!loadBalanceStreamAccountHash(expected) || e.sha256 != expected {
		return false
	}
	held, e1 := e.file.Stat()
	parent, e2 := os.Stat("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/exe")
	self, e3 := os.Stat("/proc/self/exe")
	after, e4 := e.file.Stat()
	return e1 == nil && e2 == nil && e3 == nil && e4 == nil &&
		streamAccountExecutableStable(e.before, held, parent, self, after) && ctx.Err() == nil
}

func holdLoadBalanceStreamAccountExecutable(ctx context.Context, pid uint32) (*loadBalanceStreamAccountExecutable, error) {
	if ctx == nil || ctx.Err() != nil || pid <= 1 || pid > 2147483647 {
		return nil, errLoadBalanceStreamAccount
	}
	ctx, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	// Deliberate kernel procfs magic link for a fixed, independently pinned PID.
	f, err := os.Open("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/exe")
	if err != nil {
		return nil, errLoadBalanceStreamAccount
	}
	e := &loadBalanceStreamAccountExecutable{file: f}
	fail := func() (*loadBalanceStreamAccountExecutable, error) {
		e.close()
		return nil, errLoadBalanceStreamAccount
	}
	e.before, err = f.Stat()
	self, selfErr := os.Stat("/proc/self/exe")
	if err != nil || selfErr != nil || !streamAccountExecutableStable(e.before, e.before, self, self, e.before) {
		return fail()
	}
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, (128<<20)+1)); err != nil || n != e.before.Size() || ctx.Err() != nil {
		return fail()
	}
	e.sha256 = hex.EncodeToString(h.Sum(nil))
	if !e.current(ctx, pid, e.sha256) {
		return fail()
	}
	return e, nil
}
