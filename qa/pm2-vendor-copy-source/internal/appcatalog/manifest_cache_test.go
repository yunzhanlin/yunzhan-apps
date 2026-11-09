//go:build linux || darwin

package appcatalog

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type countedManifestTransport struct {
	base    http.RoundTripper
	calls   atomic.Int32
	blocked atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (p *countedManifestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	p.calls.Add(1)
	if p.blocked.Load() {
		return nil, errors.New("owned repository offline")
	}
	if p.entered != nil {
		close(p.entered)
		select {
		case <-p.release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	return p.base.RoundTrip(r)
}
func manifestCacheFixture(t *testing.T) (*Client, CatalogItem, *countedManifestTransport, string, string) {
	t.Helper()
	c, item, server := testRepository(t, "ready")
	t.Cleanup(server.Close)
	p := &countedManifestTransport{base: c.HTTP.Transport}
	if p.base == nil {
		p.base = http.DefaultTransport
	}
	c.HTTP.Transport = p
	base := filepath.Join(t.TempDir(), "packages")
	return c, item, p, base, filepath.Join(base, item.ID, item.Version, "manifest.json")
}

func TestManifestCacheReverifiesCurrentBindingAndWorksOffline(t *testing.T) {
	c, item, p, base, path := manifestCacheFixture(t)
	first, err := c.FetchManifest(context.Background(), item, base)
	if err != nil || p.calls.Load() != 1 {
		t.Fatal(first, err, p.calls.Load())
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	p.blocked.Store(true)
	next, err := c.FetchManifest(context.Background(), item, base)
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || next.ID != first.ID || next.Version != first.Version || p.calls.Load() != 1 || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("verified offline cache refetched/rewritten", err)
	}
	changed := item
	changed.SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := c.FetchManifest(context.Background(), changed, base); err == nil || p.calls.Load() != 1 {
		t.Fatal("cache bypassed the current signed digest", err)
	}
}

func TestManifestCacheConcurrentPullAndCancelledWait(t *testing.T) {
	c, item, p, base, _ := manifestCacheFixture(t)
	p.entered = make(chan struct{})
	p.release = make(chan struct{})
	done := make(chan error, 1)
	pullCtx, stopPull := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopPull()
	go func() { _, err := c.FetchManifest(pullCtx, item, base); done <- err }()
	select {
	case <-p.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("pull not entered")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.FetchManifest(ctx, item, base); !errors.Is(err, context.Canceled) || p.calls.Load() != 1 {
		t.Fatal("cancelled waiter fetched or blocked", err)
	}
	close(p.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	p.entered = nil
	p.release = nil
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := c.FetchManifest(context.Background(), item, base); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if p.calls.Load() != 1 {
		t.Fatal("same-client concurrent cache reuse fetched again", p.calls.Load())
	}
}

func TestManifestCacheRejectsUntrustedRecordsWithoutNetworkOrOverwrite(t *testing.T) {
	for _, mode := range []string{"symlink", "symlink-version", "symlink-root", "hardlink", "public-file", "public-version", "public-root", "corrupt", "oversize", "directory", "fifo"} {
		t.Run(mode, func(t *testing.T) {
			c, item, p, base, path := manifestCacheFixture(t)
			if _, err := c.FetchManifest(context.Background(), item, base); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "sentinel.json")
			if err := os.WriteFile(outside, original, 0600); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "symlink-version":
				owned := filepath.Dir(path) + "-own-retained"
				if err := os.Rename(filepath.Dir(path), owned); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(owned, filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
			case "symlink-root":
				owned := base + "-own-retained"
				if err := os.Rename(base, owned); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(owned, base); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(filepath.Dir(path), "own-extra-link")); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "public-version":
				if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
			case "public-root":
				if err := os.Chmod(base, 0777); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte("{\"not-signed\":true}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(path, make([]byte, maxManifestBytes+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.FetchManifest(context.Background(), item, base); err == nil || p.calls.Load() != 1 {
				t.Fatal("untrusted cache fetched/accepted", mode, err)
			}
			after, err := os.Lstat(path)
			sentinel, readErr := os.ReadFile(outside)
			if err != nil || readErr != nil || !os.SameFile(before, after) || string(sentinel) != string(original) {
				t.Fatal("refusal changed existing cache or sentinel", mode)
			}
		})
	}
}

func TestManifestCacheMissingInvalidNetworkLeavesNoPublishedPackage(t *testing.T) {
	c, item, p, base, path := manifestCacheFixture(t)
	p.blocked.Store(true)
	if _, err := c.FetchManifest(context.Background(), item, base); err == nil {
		t.Fatal("offline miss accepted")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failure published manifest", err)
	}
	if _, err := openManifestCache("relative-cache", item); err == nil {
		t.Fatal("relative cache anchor accepted")
	}
}
