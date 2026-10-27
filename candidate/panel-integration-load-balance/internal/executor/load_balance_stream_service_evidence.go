package executor

import (
	"strconv"
	"strings"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Pure syntax/evidence decoders, not authority. Linux obtains these bytes from
// the original held proc/cgroup descriptors and fixed system manager, NEVER
// the browser, a saved receipt, a claimed PID or a successful start reply.
func streamServiceProcessStatus(raw []byte, uid, gid uint32) bool {
	if len(raw) == 0 || len(raw) > 65536 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") || uid < 100 || uid >= 1000 || gid < 100 || gid >= 1000 {
		return false
	}
	u, g := strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10)
	want := map[string]string{"Uid": u + " " + u + " " + u + " " + u, "Gid": g + " " + g + " " + g + " " + g, "Groups": g,
		"CapInh": "0000000000000000", "CapPrm": "0000000000000000", "CapEff": "0000000000000000", "CapBnd": "0000000000000000", "CapAmb": "0000000000000000", "NoNewPrivs": "1", "Seccomp": "2", "Threads": "1"}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, _ := strings.Cut(line, ":")
		if expected, known := want[key]; known {
			if seen[key] || strings.Join(strings.Fields(value), " ") != expected {
				return false
			}
			seen[key] = true
		}
	}
	return len(seen) == len(want)
}

func streamServiceOpenFiles(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 16384 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return false
	}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "Max open files") {
			if strings.Join(strings.Fields(line), " ") != "Max open files 32768 32768 files" {
				return false
			}
			count++
		}
	}
	return count == 1
}

func streamServicePIDs(raw []byte) ([]int, bool) {
	if len(raw) == 0 || len(raw) > 512 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return nil, false
	}
	var out []int
	seen := map[int]bool{}
	for _, value := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		pid, err := strconv.Atoi(value)
		if err != nil || pid < 2 || pid > 1<<30 || strconv.Itoa(pid) != value || seen[pid] || len(out) >= 32 {
			return nil, false
		}
		seen[pid] = true
		out = append(out, pid)
	}
	return out, true
}

func streamServiceCPU100(raw []byte) bool {
	if len(raw) < 4 || len(raw) > 64 || !strings.HasSuffix(string(raw), "\n") {
		return false
	}
	values := strings.Split(strings.TrimSuffix(string(raw), "\n"), " ")
	if len(values) != 2 {
		return false
	}
	quota, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil || quota < 1000 || quota > 1000000 || strconv.FormatUint(quota, 10) != values[0] || values[0] != values[1] {
		return false
	}
	return true
}

var streamServicePropertyNames = []string{"Id", "LoadState", "ActiveState", "SubState", "MainPID", "ControlPID", "ControlGroup", "InvocationID", "Slice", "Transient", "User", "Group", "NoNewPrivileges", "CapabilityBoundingSet", "AmbientCapabilities", "Restart", "RemainAfterExit", "KillMode", "KillSignal", "RuntimeDirectory", "RuntimeDirectoryPreserve", "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices", "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups", "RestrictSUIDSGID", "RestrictRealtime", "LockPersonality", "MemoryDenyWriteExecute", "IPAccounting"}

func decodeStreamServiceProperties(raw []byte) (int, string, error) {
	if len(raw) == 0 || len(raw) > 16384 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return 0, "", loadbalancestream.ErrService
	}
	want := map[string]string{"Id": loadbalancestream.ServiceUnitName, "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "ControlPID": "0", "ControlGroup": "/system.slice/" + loadbalancestream.ServiceUnitName,
		"Slice": "system.slice", "Transient": "yes", "User": loadbalancestream.ServiceAccount, "Group": loadbalancestream.ServiceAccount, "NoNewPrivileges": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "", "Restart": "no", "KillMode": "mixed", "KillSignal": "3", "RuntimeDirectory": "panel-load-balance-stream", "RuntimeDirectoryPreserve": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes", "ProtectControlGroups": "yes", "RestrictSUIDSGID": "yes", "RestrictRealtime": "yes", "LockPersonality": "yes", "MemoryDenyWriteExecute": "yes", "IPAccounting": "yes"}
	seen, values := map[string]bool{}, map[string]string{}
	want["RemainAfterExit"] = "yes"
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return 0, "", loadbalancestream.ErrService
		}
		if key != "MainPID" && key != "InvocationID" {
			expected, known := want[key]
			if !known || value != expected {
				return 0, "", loadbalancestream.ErrService
			}
		}
		seen[key], values[key] = true, value
	}
	pid, err := strconv.Atoi(values["MainPID"])
	invocation := values["InvocationID"]
	if len(seen) != len(want)+2 || err != nil || pid < 2 || pid > 1<<30 || strconv.Itoa(pid) != values["MainPID"] || !core.ValidID(invocation) || invocation == strings.Repeat("0", 32) {
		return 0, "", loadbalancestream.ErrService
	}
	return pid, invocation, nil
}
