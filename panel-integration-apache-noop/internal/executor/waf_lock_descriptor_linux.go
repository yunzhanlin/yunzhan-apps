//go:build linux

package executor

import (
	"strconv"
	"strings"
)

// fdinfo is the kernel's witness for this open description, not any same-inode
// descriptor in the process. Accept only one current-PID, whole-file exclusive
// FLOCK and its matching inode; absent, shared or ambiguous evidence is closed.
// The distinct cross-process candidate-owner contract is intentionally unchanged.
func wafDescriptorExclusiveFlock(data []byte, pid int, device, inode uint64) bool {
	if pid <= 0 || inode == 0 {
		return false
	}
	inos, locks, owned := 0, 0, false
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "ino:"); ok {
			inos++
			if strings.TrimSpace(value) != strconv.FormatUint(inode, 10) {
				return false
			}
		}
		if value, ok := strings.CutPrefix(line, "lock:"); ok {
			locks++
			owned = moduleFlockOwner(strings.TrimSpace(value), pid, device, inode)
		}
	}
	return inos == 1 && locks == 1 && owned
}
