//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"local/panel/internal/core"
)

type memcachedUnixAdminPrepareOps struct {
	absent  func(context.Context) error
	create  func(context.Context) error
	resolve func(context.Context) (memcachedUnixAccount, error)
}

func memcachedUnixAdminAbsent(ctx context.Context) error {
	for _, kind := range []string{"passwd", "group"} {
		if ctx == nil || ctx.Err() != nil {
			return errMemcachedUnixNSS
		}
		child, cancel := context.WithTimeout(ctx, 3*time.Second)
		cmd := exec.CommandContext(child, "/usr/bin/getent", kind, memcachedUnixAdminName)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
		out, stderr := &boundedBuffer{max: 8192}, &boundedBuffer{max: 8192}
		cmd.Stdout = out
		cmd.Stderr = stderr
		cmd.WaitDelay = time.Second
		err := cmd.Run()
		timedOut := child.Err() != nil
		cancel()
		var status *exec.ExitError
		if timedOut || !errors.As(err, &status) || status.ExitCode() != 2 || out.String() != "" || stderr.String() != "" {
			return errMemcachedUnixNSS
		}
	}
	return nil
}

func memcachedUnixAdminCreate(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errMemcachedUnixNSS
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, "/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--comment", memcachedUnixAdminName, memcachedUnixAdminName)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	out, stderr := &boundedBuffer{max: 8192}, &boundedBuffer{max: 8192}
	cmd.Stdout = out
	cmd.Stderr = stderr
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil || child.Err() != nil {
		return errMemcachedUnixNSS
	}
	return nil
}

func (s *memcachedUnixAdminStore) closed() bool {
	if !s.current() {
		return false
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return false
	}
	defer dir.Close()
	entries, err := dir.ReadDir(3)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 2 {
		return false
	}
	for _, entry := range entries {
		if entry.Name() != "admin-intent.json" && entry.Name() != "admin.json" {
			return false
		}
		info, err := s.root.Lstat(entry.Name())
		if err != nil || !memcachedUnixAdminRecordInfo(info) {
			return false
		}
	}
	return s.current()
}

func (s *memcachedUnixAdminStore) writeExclusiveRecord(name string, raw []byte) error {
	if !s.closed() {
		return errMemcachedUnixNSS
	}
	switch name {
	case "admin-intent.json":
		if _, err := decodeMemcachedUnixAdminIntent(raw); err != nil {
			return err
		}
	case "admin.json":
		if _, err := decodeMemcachedUnixAdminReceipt(raw); err != nil {
			return err
		}
	default:
		return errMemcachedUnixNSS
	}
	before := s.before
	file, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return errMemcachedUnixNSS
	}
	defer file.Close()
	// Only this newly exclusive inode can receive fixed ownership/mode.
	if file.Chown(0, 0) != nil || file.Chmod(0600) != nil {
		return errMemcachedUnixNSS
	}
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		return errMemcachedUnixNSS
	}
	if file.Sync() != nil || ruleFeedStoreSync(s.root) != nil {
		return errMemcachedUnixNSS
	}
	info, e1 := file.Stat()
	visible, e2 := s.root.Lstat(name)
	if e1 != nil || e2 != nil || !memcachedUnixAdminRecordInfo(info) || !geoStoreStableInfo(info, visible) {
		return errMemcachedUnixNSS
	}
	// Publishing our own exclusive record changes only the same directory's
	// size/times. Refresh after proving its inode, Root ownership and mode.
	now, err := s.root.Stat(".")
	if err != nil || !os.SameFile(before, now) || !memcachedUnixAdminDirectoryInfo(now) {
		return errMemcachedUnixNSS
	}
	s.before = now
	if !s.closed() {
		return errMemcachedUnixNSS
	}
	return nil
}

func memcachedUnixAdminIdentityAt(ctx context.Context, store *memcachedUnixAdminStore, resolve func(context.Context) (memcachedUnixAccount, error)) (memcachedUnixAccount, error) {
	var empty memcachedUnixAccount
	if ctx == nil || ctx.Err() != nil || resolve == nil || !store.closed() {
		return empty, errMemcachedUnixNSS
	}
	intentFile, raw, err := store.openRecord("admin-intent.json")
	if err != nil {
		return empty, err
	}
	defer intentFile.file.Close()
	if _, err = decodeMemcachedUnixAdminIntent(raw); err != nil {
		return empty, err
	}
	sum := sha256.Sum256(raw)
	receiptFile, body, err := store.openRecord("admin.json")
	if err != nil {
		return empty, err
	}
	defer receiptFile.file.Close()
	receipt, err := decodeMemcachedUnixAdminReceipt(body)
	if err != nil || receipt.IntentSHA != hex.EncodeToString(sum[:]) {
		return empty, errMemcachedUnixNSS
	}
	account, err := resolve(ctx)
	if err != nil || account.UID != receipt.UID || account.GID != receipt.GID || ctx.Err() != nil || !intentFile.current() || !receiptFile.current() {
		return empty, errMemcachedUnixNSS
	}
	return account, nil
}

// Private own-filesystem/command seam. The production wrapper supplies only
// fixed paths, fixed getent/useradd argv and the four-file Root NSS resolver.
// Never delete/modify an account, remove an intent, or adopt an unknown result.
func prepareMemcachedUnixAdminAt(ctx context.Context, store *memcachedUnixAdminStore, ops memcachedUnixAdminPrepareOps) error {
	if ctx == nil || ctx.Err() != nil || ops.absent == nil || ops.create == nil || ops.resolve == nil || !store.closed() {
		return errMemcachedUnixNSS
	}
	if _, err := store.root.Lstat("admin.json"); err == nil {
		_, err = memcachedUnixAdminIdentityAt(ctx, store, ops.resolve)
		return err
	} else if !errors.Is(err, os.ErrNotExist) {
		return errMemcachedUnixNSS
	}
	if _, err := store.root.Lstat("admin-intent.json"); !errors.Is(err, os.ErrNotExist) {
		return errMemcachedUnixNSS
	}
	if ops.absent(ctx) != nil || ctx.Err() != nil {
		return errMemcachedUnixNSS
	}
	intent := memcachedUnixCanonicalRecord(memcachedUnixAdminIntent{Format: 1, Name: memcachedUnixAdminName, Nonce: core.ID()})
	if err := store.writeExclusiveRecord("admin-intent.json", intent); err != nil {
		return err
	}
	if ctx.Err() != nil || ops.create(ctx) != nil {
		return errMemcachedUnixNSS
	}
	account, err := ops.resolve(ctx)
	if err != nil || ctx.Err() != nil {
		return errMemcachedUnixNSS
	}
	sum := sha256.Sum256(intent)
	receipt := memcachedUnixAdminReceipt{Format: 1, Name: memcachedUnixAdminName, UID: account.UID, GID: account.GID, IntentSHA: hex.EncodeToString(sum[:])}
	raw := memcachedUnixCanonicalRecord(receipt)
	if _, err = decodeMemcachedUnixAdminReceipt(raw); err != nil {
		return err
	}
	if err = store.writeExclusiveRecord("admin.json", raw); err != nil {
		return err
	}
	_, err = memcachedUnixAdminIdentityAt(ctx, store, ops.resolve)
	return err
}
