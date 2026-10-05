//go:build linux

package executor

import (
	"bufio"
	"errors"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type procSample struct {
	PID       int
	Name      string
	State     string
	StartTime uint64
	Ticks     uint64
	RSS       uint64
	Read      uint64
	Write     uint64
}

func (s *Service) monitorProcessRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/monitor/processes", func(w http.ResponseWriter, r *http.Request) {
		first, totalFirst, err := readProcessSample("/proc")
		if err != nil {
			respond(w, 500, map[string]string{"error": "读取进程状态失败"})
			return
		}
		started := time.Now()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
		second, totalSecond, err := readProcessSample("/proc")
		if err != nil {
			respond(w, 500, map[string]string{"error": "读取进程状态失败"})
			return
		}
		processes := computeProcesses(first, second, totalFirst, totalSecond, time.Since(started))
		var tcpConnections *int
		if count, countErr := countEstablishedTCP("/proc"); countErr == nil {
			tcpConnections = &count
		}
		respond(w, 200, map[string]any{"processes": processes, "tcp_connections": tcpConnections})
	})
}

func countEstablishedTCP(procRoot string) (int, error) {
	count := 0
	for _, name := range []string{"tcp", "tcp6"} {
		file, err := os.Open(filepath.Join(procRoot, "net", name))
		if errors.Is(err, os.ErrNotExist) && name == "tcp6" {
			continue
		}
		if err != nil {
			return 0, err
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), 65536)
		rows := 0
		for scanner.Scan() {
			rows++
			if rows > 1000000 {
				_ = file.Close()
				return 0, errors.New("TCP socket count exceeds limit")
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 && fields[3] == "01" {
				count++
			}
		}
		err = scanner.Err()
		_ = file.Close()
		if err != nil {
			return 0, err
		}
	}
	return count, nil
}

func readProcessSample(base string) (map[int]procSample, uint64, error) {
	stat, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return nil, 0, err
	}
	firstLine := strings.SplitN(string(stat), "\n", 2)[0]
	fields := strings.Fields(firstLine)
	if len(fields) < 2 || fields[0] != "cpu" {
		return nil, 0, errors.New("系统 CPU 数据无效")
	}
	var total uint64
	for _, field := range fields[1:] {
		value, parseErr := strconv.ParseUint(field, 10, 64)
		if parseErr != nil {
			return nil, 0, parseErr
		}
		total += value
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, 0, err
	}
	out := map[int]procSample{}
	for _, entry := range entries {
		if len(out) >= 2000 {
			break
		}
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(base, entry.Name(), "stat"))
		if readErr != nil {
			continue
		}
		proc, parseErr := parseProcStat(pid, string(data), uint64(os.Getpagesize()))
		if parseErr != nil {
			continue
		}
		ioData, ioErr := os.ReadFile(filepath.Join(base, entry.Name(), "io"))
		if ioErr == nil {
			proc.Read, proc.Write = parseProcIO(string(ioData))
		}
		out[pid] = proc
	}
	return out, total, nil
}

func parseProcStat(pid int, data string, pageSize uint64) (procSample, error) {
	var out procSample
	end := strings.LastIndex(data, ")")
	start := strings.Index(data, "(")
	if start < 0 || end <= start || end+1 >= len(data) {
		return out, errors.New("进程状态格式无效")
	}
	fields := strings.Fields(data[end+1:])
	if len(fields) < 22 {
		return out, errors.New("进程状态字段不足")
	}
	userTicks, e1 := strconv.ParseUint(fields[11], 10, 64)
	systemTicks, e2 := strconv.ParseUint(fields[12], 10, 64)
	startTime, e3 := strconv.ParseUint(fields[19], 10, 64)
	rssPages, e4 := strconv.ParseUint(fields[21], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return out, errors.New("进程状态数值无效")
	}
	name := data[start+1 : end]
	if len(name) > 50 {
		name = name[:50]
	}
	return procSample{PID: pid, Name: name, State: fields[0], StartTime: startTime, Ticks: userTicks + systemTicks, RSS: rssPages * pageSize}, nil
}

func parseProcIO(data string) (uint64, uint64) {
	var read, write uint64
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "read_bytes:":
			read = value
		case "write_bytes:":
			write = value
		}
	}
	return read, write
}

func computeProcesses(before, after map[int]procSample, totalBefore, totalAfter uint64, elapsed time.Duration) []core.MonitorProcess {
	out := []core.MonitorProcess{}
	seconds := elapsed.Seconds()
	for pid, next := range after {
		p := core.MonitorProcess{PID: pid, Name: next.Name, Memory: next.RSS, State: next.State}
		if old, ok := before[pid]; ok && old.StartTime == next.StartTime && seconds > 0 {
			if totalAfter > totalBefore && next.Ticks >= old.Ticks {
				p.CPUPercent = float64(next.Ticks-old.Ticks) * 100 / float64(totalAfter-totalBefore)
			}
			if next.Read >= old.Read {
				p.ReadRate = float64(next.Read-old.Read) / seconds
			}
			if next.Write >= old.Write {
				p.WriteRate = float64(next.Write-old.Write) / seconds
			}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CPUPercent == out[j].CPUPercent {
			return out[i].Memory > out[j].Memory
		}
		return out[i].CPUPercent > out[j].CPUPercent
	})
	if len(out) > 500 {
		out = out[:500]
	}
	return out
}
