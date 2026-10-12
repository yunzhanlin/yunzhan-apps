// Package upgradeguard keeps candidate processes read-only until their
// ordinary production upgrade has committed. An interrupted marker stays
// blocking; neither process is authorized to remove the installer's evidence.
package upgradeguard

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const Marker = "/opt/panel/releases/.program-upgrade.pending"

// Blocked treats unreadable or malformed paths as pending, not as success.
// It never parses credentials, follows a marker symlink or changes the file.
func Blocked() bool { return blockedAt(Marker) }

// Handler blocks all routes, including GETs that reconcile durable state,
// except the fixed read-only health probes required by the installer.
func Handler(next http.Handler, probes ...string) http.Handler {
	return handler(next, Blocked, probes...)
}

func handler(next http.Handler, blocked func() bool, probes ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if blocked() {
			allowed := false
			if r.Method == http.MethodGet {
				for _, path := range probes {
					if r.URL.Path == path {
						allowed = true
						break
					}
				}
			}
			if !allowed {
				w.Header().Set("Retry-After", "3")
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "面板程序正在升级；请稍后重试", http.StatusServiceUnavailable)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func blockedAt(path string) bool {
	_, err := os.Lstat(path)
	if err == nil {
		return true
	}
	if !os.IsNotExist(err) {
		return true
	}
	// A missing marker beneath a linked/non-directory parent is not proof that
	// no upgrade is pending. Missing ordinary deployment directories are valid
	// for original development layouts and isolated source tests.
	for parent := filepath.Dir(path); parent != filepath.Dir(parent); parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

// Wait defers background writers while the candidate serves only readiness.
// Cancellation must not start workers during shutdown or failed rollback.
func Wait(ctx context.Context) bool {
	return wait(ctx, Blocked, time.Second)
}

func wait(ctx context.Context, blocked func() bool, interval time.Duration) bool {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return false
		}
		if !blocked() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}
