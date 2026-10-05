//go:build !linux

package executor

import "runtime"

func Snapshot() map[string]any {
	return map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "unavailable": true}
}
