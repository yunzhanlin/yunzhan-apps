//go:build linux

package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var cpuState struct {
	sync.Mutex
	total, idle uint64
}

func Snapshot() map[string]any {
	out := map[string]any{"os": "Linux", "arch": runtime.GOARCH, "cpu_cores": runtime.NumCPU()}
	hostname, _ := os.Hostname()
	out["hostname"] = hostname
	var uts syscall.Utsname
	if syscall.Uname(&uts) == nil {
		release := make([]byte, 0, len(uts.Release))
		for _, c := range uts.Release {
			if c == 0 {
				break
			}
			release = append(release, byte(c))
		}
		out["kernel"] = string(release)
	}
	if b, e := os.ReadFile("/etc/os-release"); e == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "PRETTY_NAME=") {
				out["os"] = strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
			}
		}
	}
	if b, e := os.ReadFile("/proc/meminfo"); e == nil {
		vals := map[string]uint64{}
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) >= 2 {
				v, _ := strconv.ParseUint(f[1], 10, 64)
				vals[strings.TrimSuffix(f[0], ":")] = v * 1024
			}
		}
		total, available := vals["MemTotal"], vals["MemAvailable"]
		if total > 0 && available <= total {
			out["memory_total"] = total
			out["memory_used"] = total - available
			out["memory_percent"] = float64(total-available) * 100 / float64(total)
		}
	}
	if b, e := os.ReadFile("/proc/stat"); e == nil {
		f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
		var total, idle uint64
		for i := 1; i < len(f) && i <= 8; i++ {
			n, _ := strconv.ParseUint(f[i], 10, 64)
			total += n
			if i == 4 || i == 5 {
				idle += n
			}
		}
		cpuState.Lock()
		percent := float64(0)
		if cpuState.total > 0 && total > cpuState.total && idle >= cpuState.idle {
			percent = (1 - float64(idle-cpuState.idle)/float64(total-cpuState.total)) * 100
		}
		cpuState.total = total
		cpuState.idle = idle
		cpuState.Unlock()
		out["cpu_percent"] = percent
		out["cpu_total"] = total
		out["cpu_idle"] = idle
	}
	var fs syscall.Statfs_t
	if syscall.Statfs("/srv/panel", &fs) == nil {
		total, used, available := diskUsage(fs)
		out["disk_total"] = total
		out["disk_used"] = used
		out["disk_available"] = available
		if total > 0 {
			out["disk_percent"] = float64(used) * 100 / float64(total)
		}
	}
	if b, e := os.ReadFile("/proc/uptime"); e == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			n, _ := strconv.ParseFloat(f[0], 64)
			out["uptime_seconds"] = n
		}
	}
	if b, e := os.ReadFile("/proc/loadavg"); e == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			out["load"] = strings.Join(f[:3], " / ")
			if n, err := strconv.ParseFloat(f[0], 64); err == nil {
				out["load_1"] = n
			}
		}
	}
	if b, e := os.ReadFile("/proc/net/dev"); e == nil {
		var rx, tx uint64
		for _, l := range strings.Split(string(b), "\n") {
			parts := strings.SplitN(l, ":", 2)
			if len(parts) != 2 || strings.TrimSpace(parts[0]) == "lo" {
				continue
			}
			f := strings.Fields(parts[1])
			if len(f) >= 9 {
				r, _ := strconv.ParseUint(f[0], 10, 64)
				t, _ := strconv.ParseUint(f[8], 10, 64)
				rx += r
				tx += t
			}
		}
		out["network_rx"] = rx
		out["network_tx"] = tx
	}
	if read, write, ok := blockIOCounters("/sys/block"); ok {
		out["disk_read_bytes"] = read
		out["disk_write_bytes"] = write
	}
	if b, e := os.ReadFile("/proc/sys/kernel/random/boot_id"); e == nil {
		var boot string
		if json.Unmarshal([]byte(`"`+strings.TrimSpace(string(b))+`"`), &boot) == nil {
			out["boot_id"] = boot
		}
	}
	return out
}

func diskUsage(fs syscall.Statfs_t) (total, used, available uint64) {
	blockSize := uint64(fs.Bsize)
	total = fs.Blocks * blockSize
	if fs.Bfree <= fs.Blocks {
		used = (fs.Blocks - fs.Bfree) * blockSize
	}
	if fs.Bavail <= fs.Blocks {
		available = fs.Bavail * blockSize
	}
	return
}

func blockIOCounters(root string) (uint64, uint64, bool) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, 0, false
	}
	var read, write uint64
	var found bool
	for _, entry := range entries {
		name := entry.Name()
		if !(strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "xvd") || strings.HasPrefix(name, "nvme") || strings.HasPrefix(name, "mmcblk")) {
			continue
		}
		contents, readErr := os.ReadFile(filepath.Join(root, name, "stat"))
		if readErr != nil {
			continue
		}
		fields := strings.Fields(string(contents))
		if len(fields) < 7 {
			continue
		}
		readSectors, e1 := strconv.ParseUint(fields[2], 10, 64)
		writeSectors, e2 := strconv.ParseUint(fields[6], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		read += readSectors * 512
		write += writeSectors * 512
		found = true
	}
	return read, write, found
}
