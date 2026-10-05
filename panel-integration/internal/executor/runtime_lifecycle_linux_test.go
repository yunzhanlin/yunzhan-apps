//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func lifecycleFixture(t *testing.T) (lifecycleFS, runtimecatalog.Release) {
	t.Helper()
	r, _ := runtimecatalog.Find("nginx-1.31.5")
	base := t.TempDir()
	os.Chmod(base, 0700)
	prefix := filepath.Join(base, r.Family, r.Version)
	if e := os.MkdirAll(prefix+"/sbin", 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(prefix+"/sbin/nginx", []byte("test-version"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := writeJSON(prefix+"/.panel-runtime.json", RuntimeManifest{Release: r, Architecture: runtime.GOARCH}); e != nil {
		t.Fatal(e)
	}
	l := lifecycleFS{base: base, jobs: t.TempDir(), references: func(string) ([]core.RuntimeReference, error) { return nil, nil }, verify: func(context.Context, runtimecatalog.Release) error { return nil }}
	os.Chmod(l.jobs, 0700)
	return l, r
}
func TestLifecycleReferenceGuardRecoveryAndNoClobber(t *testing.T) {
	l, r := lifecycleFixture(t)
	ctx := context.Background()
	prefix, archive, program := l.paths(r)
	l.references = func(string) ([]core.RuntimeReference, error) {
		return []core.RuntimeReference{{Kind: "stopped-binding", Name: "held"}}, nil
	}
	if _, e := l.apply(ctx, core.ID(), r.ID, "retire"); e == nil {
		t.Fatal("referenced program retired")
	}
	if _, e := os.Stat(prefix); e != nil {
		t.Fatal(e)
	}
	l.references = func(string) ([]core.RuntimeReference, error) { return nil, nil }
	retire := core.ID()
	l.checkpoint = func(point string) error {
		if point == "after-retire" {
			return errors.New("power loss")
		}
		return nil
	}
	result, e := l.apply(ctx, retire, r.ID, "retire")
	if e == nil || result.Status != "needs_attention" {
		t.Fatal("fault not retained", result, e)
	}
	l.checkpoint = nil
	binary := program + "/sbin/nginx"
	os.WriteFile(binary, []byte("damaged after interrupted move"), 0755)
	result, e = l.apply(ctx, retire, r.ID, "retire")
	if e == nil || result.Status != "needs_attention" {
		t.Fatal("retry cleared unresolved mutation", result, e)
	}
	os.WriteFile(binary, []byte("test-version"), 0755)
	result, e = l.apply(ctx, retire, r.ID, "retire")
	if e != nil || result.Status != "quarantined" {
		t.Fatal(result, e)
	}
	if _, e = l.apply(ctx, retire, r.ID, "restore"); e == nil {
		t.Fatal("replayed job with changed action")
	}
	if e = os.Mkdir(prefix, 0755); e != nil {
		t.Fatal(e)
	}
	if _, e = l.apply(ctx, core.ID(), r.ID, "restore"); e == nil {
		t.Fatal("existing prefix overwritten")
	}
	os.Remove(prefix)
	restore := core.ID()
	l.checkpoint = func(point string) error {
		if point == "after-restore" {
			return errors.New("power loss")
		}
		return nil
	}
	if _, e = l.apply(ctx, restore, r.ID, "restore"); e == nil {
		t.Fatal("restore fault not injected")
	}
	l.checkpoint = nil
	result, e = l.apply(ctx, restore, r.ID, "restore")
	if e != nil || result.Status != "installed" {
		t.Fatal(result, e)
	}
	// A completed request stays idempotent even when a later request changes the state.
	result, e = l.apply(ctx, retire, r.ID, "retire")
	if e != nil || result.Status != "quarantined" {
		t.Fatal(result, e)
	}
	if _, e = os.Stat(prefix); e != nil {
		t.Fatal("old request moved restored program")
	}
	if _, e = l.apply(ctx, core.ID(), r.ID, "retire"); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(prefix, 0755); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(prefix+"/fresh-install", []byte("keep"), 0600)
	purge := core.ID()
	l.checkpoint = func(point string) error {
		if point == "after-purge" {
			return errors.New("power loss")
		}
		return nil
	}
	if _, e = l.apply(ctx, purge, r.ID, "purge"); e == nil {
		t.Fatal("purge fault not injected")
	}
	l.checkpoint = nil
	result, e = l.apply(ctx, purge, r.ID, "purge")
	if e != nil || result.Status != "purged" {
		t.Fatal(result, e)
	}
	if b, e := os.ReadFile(prefix + "/fresh-install"); e != nil || string(b) != "keep" {
		t.Fatal("fresh install damaged")
	}
	for _, path := range []string{program, archive} {
		if _, e = os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("archive remains", path, e)
		}
	}
}
func TestLifecycleDetectsTamperingAndRollsBackBadVersion(t *testing.T) {
	l, r := lifecycleFixture(t)
	ctx := context.Background()
	prefix, _, program := l.paths(r)
	if _, e := l.apply(ctx, core.ID(), r.ID, "retire"); e != nil {
		t.Fatal(e)
	}
	binary := program + "/sbin/nginx"
	os.WriteFile(binary, []byte("corrupted"), 0755)
	if _, e := l.apply(ctx, core.ID(), r.ID, "restore"); e == nil {
		t.Fatal("corrupted version restored")
	}
	os.WriteFile(binary, []byte("test-version"), 0755)
	l.verify = func(context.Context, runtimecatalog.Release) error { return errors.New("wrong program version") }
	result, e := l.apply(ctx, core.ID(), r.ID, "restore")
	if e == nil || result.Status != "unchanged" {
		t.Fatal("failed verification did not roll back", e, result)
	}
	if _, e = os.Stat(program); e != nil {
		t.Fatal("backup lost", e)
	}
	if _, e = os.Stat(prefix); !os.IsNotExist(e) {
		t.Fatal("bad program published", e)
	}
}
func TestRuntimeHashRejectsEscapingLinksAndDetectsModeChange(t *testing.T) {
	l, r := lifecycleFixture(t)
	prefix, _, _ := l.paths(r)
	ctx := context.Background()
	a, e := runtimeTreeSHA(ctx, prefix, prefix)
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(prefix+"/sbin/nginx", 0700)
	b, e := runtimeTreeSHA(ctx, prefix, prefix)
	if e != nil || a == b {
		t.Fatal("mode not hashed", e)
	}
	os.Symlink("/etc/passwd", prefix+"/outside")
	if _, e = runtimeTreeSHA(ctx, prefix, prefix); e == nil {
		t.Fatal("outside symlink accepted")
	}
	os.Remove(prefix + "/outside")
	os.Symlink("sbin/nginx", prefix+"/internal")
	if _, e = runtimeTreeSHA(ctx, prefix, prefix); e != nil {
		t.Fatal(e)
	}
}

func TestLifecycleMutationCannotRaceStartupLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lifecycle.lock")
	shared, e := runtimeFileLock(path, syscall.LOCK_SH)
	if e != nil {
		t.Fatal(e)
	}
	if lock, e := runtimeFileLock(path, syscall.LOCK_EX|syscall.LOCK_NB); e == nil {
		lock.Close()
		t.Fatal("mutation acquired lock while a startup is in progress")
	}
	shared.Close()
	lock, e := runtimeFileLock(path, syscall.LOCK_EX|syscall.LOCK_NB)
	if e != nil {
		t.Fatal(e)
	}
	lock.Close()
}

func TestOldPurgeRetryCannotRemoveNewRetirement(t *testing.T) {
	l, r := lifecycleFixture(t)
	ctx := context.Background()
	if _, e := l.apply(ctx, core.ID(), r.ID, "retire"); e != nil {
		t.Fatal(e)
	}
	if _, e := l.apply(ctx, core.ID(), r.ID, "restore"); e != nil {
		t.Fatal(e)
	}
	purge := core.ID()
	l.checkpoint = func(point string) error {
		if point == "after-purge" {
			return errors.New("interrupted response")
		}
		return nil
	}
	if _, e := l.apply(ctx, purge, r.ID, "purge"); e == nil {
		t.Fatal("fault injection failed")
	}
	l.checkpoint = nil
	if _, e := l.apply(ctx, core.ID(), r.ID, "retire"); e != nil {
		t.Fatal(e)
	}
	if _, e := l.apply(ctx, purge, r.ID, "purge"); e == nil {
		t.Fatal("old purge removed a new retirement")
	}
	_, _, program := l.paths(r)
	if _, e := os.Stat(program); e != nil {
		t.Fatal("new copy removed", e)
	}
}
