//go:build linux

package diskusage

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHostCapacityExactDecimalAndNonExclusiveViews(t *testing.T) {
	st := unix.Statfs_t{Bsize: 8192, Frsize: 4096, Blocks: 1 << 42, Bfree: 1234, Bavail: 1000, Files: 100, Ffree: 75}
	st.Fsid.Val = [2]int32{12, 34}
	m := Mount{ID: "1", Major: 8, Minor: 2, Filesystem: "ext4"}
	c := capacityFromStatfs(st, m)
	if c.State != "available" || *c.TotalBytes != "18014398509481984" || *c.FreeBytes != "5054464" || *c.AvailableBytes != "4096000" || *c.ReservedFreeBytes != "958464" || *c.UsedBytes != "18014398504427520" || *c.UsedInodes != "25" || !c.MayOverlap || c.SnapshotConsistent {
		t.Fatalf("incorrect exact capacity: %+v", c)
	}
	m.ID, m.Point = "2", "/same-filesystem-bind"
	if capacityFromStatfs(st, m).ViewSHA != c.ViewSHA {
		t.Fatal("bind capacity view accidentally treated as another exclusive disk")
	}
	m.Minor++
	if capacityFromStatfs(st, m).ViewSHA == c.ViewSHA {
		t.Fatal("different kernel device incorrectly merged")
	}
	raw, err := json.Marshal(c)
	if err != nil || !strings.Contains(string(raw), `"total_bytes":"18014398509481984"`) {
		t.Fatalf("browser numeric rounding: %s %v", raw, err)
	}
}

func TestHostCapacityInvalidOrUnavailableIsNullNotZero(t *testing.T) {
	base := unix.Statfs_t{Bsize: 4096, Frsize: 4096, Blocks: 1000, Bfree: 100, Bavail: 75}
	for name, mutate := range map[string]func(*unix.Statfs_t){
		"negative-unit":       func(s *unix.Statfs_t) { s.Frsize = -1 },
		"no-unit":             func(s *unix.Statfs_t) { s.Frsize, s.Bsize = 0, 0 },
		"no-blocks":           func(s *unix.Statfs_t) { s.Blocks = 0 },
		"multiply-overflow":   func(s *unix.Statfs_t) { s.Blocks = math.MaxUint64 },
		"free-over-total":     func(s *unix.Statfs_t) { s.Bfree = 1001 },
		"available-over-free": func(s *unix.Statfs_t) { s.Bavail = 101 },
	} {
		t.Run(name, func(t *testing.T) {
			st := base
			mutate(&st)
			c := capacityFromStatfs(st, Mount{})
			if c.State != "unavailable" || c.TotalBytes != nil || c.UsedBytes != nil || c.TotalInodes != nil || c.ViewSHA != "" || !c.MayOverlap {
				t.Fatalf("invalid kernel capacity became fabricated success: %+v", c)
			}
		})
	}
	for _, count := range []unix.Statfs_t{base, {Bsize: 4096, Blocks: 1000, Files: math.MaxUint64}, {Bsize: 4096, Blocks: 1000, Files: 100, Ffree: 101}} {
		c := capacityFromStatfs(count, Mount{})
		if c.State != "available" || c.InodeState != "unavailable" || c.TotalInodes != nil || c.FreeInodes != nil || c.UsedInodes != nil {
			t.Fatalf("unknown inodes published as zero: %+v", c)
		}
	}
}
