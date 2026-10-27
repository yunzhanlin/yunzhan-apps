package executor

import (
	"strconv"
	"strings"

	"local/panel/internal/loadbalancestream"
)

// A decoder, never authority. The OS observer must read its own actual unit,
// procfs identity and still-live original parent. Core/signature/runtime leases
// and an exclusively retained creation attempt remain independent prerequisites.
func streamAccountChildUnitState(raw []byte, p loadbalancestream.AccountChildPermit, pid uint32) bool {
	if _, err := loadbalancestream.AccountChildPermitBytes(p); err != nil || pid <= 1 || pid > 2147483647 || pid == p.ParentPID ||
		len(raw) == 0 || len(raw) > 8192 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return false
	}
	child, _ := loadbalancestream.AccountCreationUnit(p.JobID)
	parent, _ := loadbalancestream.AccountParentUnit(p.JobID)
	want := map[string]string{
		"Id": child, "LoadState": "loaded", "ActiveState": "active", "SubState": "running",
		"MainPID": strconv.FormatUint(uint64(pid), 10), "ControlPID": "0", "ControlGroup": "/system.slice/" + child,
		"NoNewPrivileges": "yes", "Slice": "system.slice", "Type": "exec", "BindsTo": parent,
		"KillMode": "control-group", "RemainAfterExit": "no",
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return false
		}
		seen[key] = true
		if key != "After" {
			if expected, known := want[key]; !known || value != expected {
				return false
			}
			continue
		}
		// systemd adds ordering for the slice and its normal boot dependencies.
		// Require our exact parent, bounded unique ordinary unit names and no
		// aliases/path/escape syntax; ordering is not substituted for BindsTo.
		units := strings.Split(value, " ")
		if len(units) == 0 || len(units) > 32 {
			return false
		}
		ordered := map[string]bool{}
		for _, unit := range units {
			if unit == "" || len(unit) > 255 || ordered[unit] {
				return false
			}
			for _, ch := range unit {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("_.@:-", ch)) {
					return false
				}
			}
			ordered[unit] = true
		}
		if !ordered[parent] {
			return false
		}
	}
	return len(seen) == len(want)+1 && seen["After"]
}
