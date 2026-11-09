//go:build linux

package diskusage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"

	"golang.org/x/sys/unix"
)

func unknownCapacity() Capacity {
	return Capacity{State: "unavailable", InodeState: "unavailable", MayOverlap: true, SnapshotConsistent: false}
}

func decimalPointer(value uint64) *string {
	s := strconv.FormatUint(value, 10)
	return &s
}

func capacityFromStatfs(st unix.Statfs_t, m Mount) Capacity {
	result := unknownCapacity()
	unit := st.Frsize
	if unit == 0 {
		unit = st.Bsize
	}
	// Signed fields and unsupported sentinel values must not wrap to uint64.
	// All products and subtractions are checked before publishing any value.
	if unit <= 0 || st.Blocks == 0 || st.Blocks == math.MaxUint64 || st.Blocks > math.MaxUint64/uint64(unit) || st.Bfree > st.Blocks || st.Bavail > st.Bfree {
		return result
	}
	total, free, available := st.Blocks*uint64(unit), st.Bfree*uint64(unit), st.Bavail*uint64(unit)
	result.State = "available"
	result.TotalBytes, result.FreeBytes, result.AvailableBytes = decimalPointer(total), decimalPointer(free), decimalPointer(available)
	result.UsedBytes, result.ReservedFreeBytes = decimalPointer(total-free), decimalPointer(free-available)
	// Some filesystems do not expose inode counts. Neither zero nor the
	// all-ones sentinel is evidence that there are no files/inodes.
	if st.Files != 0 && st.Files != math.MaxUint64 && st.Ffree != math.MaxUint64 && st.Ffree <= st.Files {
		result.InodeState = "available"
		result.TotalInodes, result.FreeInodes, result.UsedInodes = decimalPointer(st.Files), decimalPointer(st.Ffree), decimalPointer(st.Files-st.Ffree)
	}
	wire, _ := json.Marshal([]any{m.Filesystem, m.Major, m.Minor, st.Fsid.Val})
	h := sha256.Sum256(wire)
	result.ViewSHA = hex.EncodeToString(h[:])
	return result
}

// Capacity performs no path resolution: Fstatfs uses the already-bound mount
// FD. A slow/broken filesystem can still block; call only in an isolated worker.
// https://man7.org/linux/man-pages/man2/statfs.2.html
func (s *Scope) Capacity(ctx context.Context) (Capacity, error) {
	unknown := unknownCapacity()
	if err := ctx.Err(); err != nil {
		return unknown, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return unknown, ErrScopeClosed
	}
	before, err := metadataFD(int(s.root.Fd()), false)
	if err != nil || before.Identity != s.identity {
		return unknown, ErrMountChanged
	}
	var st unix.Statfs_t
	if unix.Fstatfs(int(s.root.Fd()), &st) != nil {
		return unknown, ErrPathUnavailable
	}
	if err = ctx.Err(); err != nil {
		return unknown, err
	}
	after, err := metadataFD(int(s.root.Fd()), false)
	if err != nil || after.Identity != s.identity {
		return unknown, ErrMountChanged
	}
	return capacityFromStatfs(st, s.mount), nil
}
