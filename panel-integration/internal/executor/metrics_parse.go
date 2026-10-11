package executor

import (
	"bufio"
	"io"
	"math/bits"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Snapshot counters are observations, not defaults. The first CPU read has
// no interval; reset/rollback/overflow/stale intervals remain unknown.
type cpuMetricState struct {
	sync.Mutex
	values [8]uint64
	at     time.Time
}

func readCPUMetricLine(r io.Reader) ([]byte, error) {
	// Large hosts can have huge later IRQ/per-CPU rows; only the bounded
	// aggregate first line is needed. Never reject a valid CPU line because
	// an unrelated later line exceeds the parser's capacity.
	return bufio.NewReader(io.LimitReader(r, 4096)).ReadBytes('\n')
}

func parseCPUMetric(raw []byte) (values [8]uint64, total, idle uint64, ok bool) {
	if len(raw) == 0 || len(raw) > 65536 {
		return
	}
	f := strings.Fields(strings.SplitN(string(raw), "\n", 2)[0])
	if len(f) < 9 || f[0] != "cpu" {
		return
	}
	for i := range values {
		n, err := strconv.ParseUint(f[i+1], 10, 64)
		if err != nil {
			return
		}
		values[i] = n
		var carry uint64
		total, carry = bits.Add64(total, n, 0)
		if carry != 0 {
			return values, 0, 0, false
		}
	}
	idle, carry := bits.Add64(values[3], values[4], 0)
	return values, total, idle, carry == 0 && total > 0
}

func (s *cpuMetricState) observe(raw []byte, now time.Time) (uint64, uint64, *float64, bool) {
	values, total, idle, ok := parseCPUMetric(raw)
	s.Lock()
	defer s.Unlock()
	if !ok {
		s.at = time.Time{}
		return 0, 0, nil, false
	}
	old, at := s.values, s.at
	s.values, s.at = values, now
	if at.IsZero() || !now.After(at) || now.Sub(at) > 30*time.Second {
		return total, idle, nil, true
	}
	var oldTotal, oldIdle uint64
	for i, v := range old {
		if values[i] < v {
			return total, idle, nil, true
		}
		oldTotal += v
		if i == 3 || i == 4 {
			oldIdle += v
		}
	}
	if total <= oldTotal || idle < oldIdle || idle-oldIdle > total-oldTotal {
		return total, idle, nil, true
	}
	percent := float64((total-oldTotal)-(idle-oldIdle)) * 100 / float64(total-oldTotal)
	return total, idle, &percent, true
}

func parseMemoryMetric(raw []byte) (total, used uint64, ok bool) {
	if len(raw) == 0 || len(raw) > 65536 {
		return
	}
	vals := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "MemTotal:" && f[0] != "MemAvailable:" {
			continue
		}
		if len(f) != 3 || f[2] != "kB" {
			return 0, 0, false
		}
		if _, exists := vals[f[0]]; exists {
			return 0, 0, false
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil || n > ^uint64(0)/1024 {
			return 0, 0, false
		}
		vals[f[0]] = n * 1024
	}
	total, totalOK := vals["MemTotal:"]
	available, availableOK := vals["MemAvailable:"]
	if !totalOK || !availableOK || total == 0 || available > total {
		return 0, 0, false
	}
	return total, total - available, true
}
