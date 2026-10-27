package executor

import (
	"fmt"
	"strconv"
	"strings"

	"local/panel/internal/loadbalancestream"
)

// Decoders only. Their inputs are NOT credentials or authority. The Linux
// observer independently reads procfs and the fixed systemctl implementation.
func streamAccountParentRootStatus(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 65536 || strings.ContainsAny(string(raw), "\x00\r") {
		return false
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found || key != "Uid" && key != "Gid" && key != "NoNewPrivs" {
			continue
		}
		if seen[key] {
			return false
		}
		seen[key] = true
		want := "0 0 0 0"
		if key == "NoNewPrivs" {
			want = "1"
		}
		if strings.Join(strings.Fields(value), " ") != want {
			return false
		}
	}
	return len(seen) == 3
}

func streamAccountParentUnitState(raw []byte, p loadbalancestream.AccountChildPermit) bool {
	parent, err := loadbalancestream.AccountParentUnit(p.JobID)
	if err != nil || len(raw) == 0 || len(raw) > 8192 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return false
	}
	want := map[string]string{"Id": parent, "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": strconv.FormatUint(uint64(p.ParentPID), 10), "ControlPID": "0", "ControlGroup": "/system.slice/" + parent, "NoNewPrivileges": "yes", "Slice": "system.slice"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		expected, known := want[key]
		if !ok || !known || seen[key] || value != expected {
			return false
		}
		seen[key] = true
	}
	return len(seen) == len(want)
}

// A single original descriptor must itself report the WRITE FLOCK owned by
// the pinned parent. This avoids an unbounded /proc/locks scan and never takes
// or inherits the parent's lock. Unknown descriptor shapes fail closed.
func streamAccountParentFDInfo(raw []byte, p loadbalancestream.AccountChildPermit, major, minor uint32) bool {
	if len(raw) == 0 || len(raw) > 8192 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return false
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || seen[key] {
			return false
		}
		seen[key] = true
		value = strings.TrimSpace(value)
		switch key {
		case "pos":
			if value != "0" {
				return false
			}
		case "flags":
			flags, err := strconv.ParseUint(value, 8, 32)
			if err != nil || flags&3 != 2 {
				return false
			}
		case "mnt_id":
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil || n == 0 || strconv.FormatUint(n, 10) != value {
				return false
			}
		case "ino":
			if value != strconv.FormatUint(p.RunLockInode, 10) {
				return false
			}
		case "lock":
			f := strings.Fields(value)
			if len(f) != 8 || f[0] != "1:" || f[1] != "FLOCK" || f[2] != "ADVISORY" || f[3] != "WRITE" || f[4] != strconv.FormatUint(uint64(p.ParentPID), 10) || f[6] != "0" || f[7] != "EOF" {
				return false
			}
			device := strings.Split(f[5], ":")
			if len(device) != 3 {
				return false
			}
			a, e1 := strconv.ParseUint(device[0], 16, 32)
			b, e2 := strconv.ParseUint(device[1], 16, 32)
			c, e3 := strconv.ParseUint(device[2], 10, 64)
			if e1 != nil || e2 != nil || e3 != nil || fmt.Sprintf("%x:%x:%d", a, b, c) != fmt.Sprintf("%x:%x:%d", major, minor, p.RunLockInode) {
				return false
			}
		default:
			return false
		}
	}
	return len(seen) == 5
}
