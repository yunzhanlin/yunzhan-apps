//go:build linux

package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var cpuState cpuMetricState

func Snapshot() map[string]any {
	out := map[string]any{"os": "Linux", "arch": runtime.GOARCH, "cpu_cores": runtime.NumCPU(), "cpu_percent": nil, "cpu_available": false, "memory_percent": nil, "memory_available": false, "disk_percent": nil, "disk_percent_available": false}
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
		if total, used, ok := parseMemoryMetric(b); ok {
			out["memory_total"] = total
			out["memory_used"] = used
			out["memory_percent"] = float64(used) * 100 / float64(total)
			out["memory_available"] = true
		}
	}
	var cpuLine []byte
	if f, err := os.Open("/proc/stat"); err == nil {
		if line, err := readCPUMetricLine(f); err == nil {
			cpuLine = line
		}
		f.Close()
	}
	if total, idle, percent, ok := cpuState.observe(cpuLine, time.Now()); ok {
		if percent != nil {
			out["cpu_percent"] = *percent
			out["cpu_available"] = true
		}
		out["cpu_total"] = total
		out["cpu_idle"] = idle
	}
	var fs syscall.Statfs_t
	if syscall.Statfs("/srv/panel", &fs) == nil && fs.Bsize > 0 && fs.Blocks > 0 && fs.Blocks <= ^uint64(0)/uint64(fs.Bsize) && fs.Bfree <= fs.Blocks && fs.Bavail <= fs.Bfree {
		total, used, available := diskUsage(fs)
		out["disk_total"] = total
		out["disk_used"] = used
		out["disk_available"] = available
		if total > 0 {
			out["disk_percent"] = float64(used) * 100 / float64(total)
			out["disk_percent_available"] = true
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
