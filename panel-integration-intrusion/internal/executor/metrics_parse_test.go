package executor

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCPUMetricFirstResetStaleAndGenuineZero(t *testing.T) {
	var s cpuMetricState
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	first := []byte("cpu 10 0 10 80 0 0 0 0 1000 1000\n")
	total, idle, p, ok := s.observe(first, at)
	if !ok || total != 100 || idle != 80 || p != nil {
		t.Fatal("first observation is not a CPU rate", total, idle, p, ok)
	}
	_, _, p, ok = s.observe([]byte("cpu 10 0 10 90 0 0 0 0 9999 9999\n"), at.Add(time.Second))
	if !ok || p == nil || *p != 0 {
		t.Fatal("genuine idle interval zero not retained", p, ok)
	}
	_, _, p, ok = s.observe([]byte("cpu 20 0 10 90 0 0 0 0\n"), at.Add(2*time.Second))
	if !ok || p == nil || *p != 100 {
		t.Fatal("genuine fully busy interval", p, ok)
	}
	_, _, p, ok = s.observe([]byte("cpu 30 0 10 100 0 0 0 0\n"), at.Add(40*time.Second))
	if !ok || p != nil {
		t.Fatal("stale baseline reported current rate")
	}
	_, _, p, ok = s.observe([]byte("cpu 1 0 1 10 0 0 0 0\n"), at.Add(41*time.Second))
	if !ok || p != nil {
		t.Fatal("counter rollback reported rate")
	}
	_, _, p, ok = s.observe([]byte("cpu 1 0 1 11 0 0 0 0\n"), at.Add(42*time.Second))
	if !ok || p == nil || *p != 0 {
		t.Fatal("new valid baseline cannot recover")
	}
	if _, _, p, ok = s.observe([]byte("cpu broken\n"), at.Add(43*time.Second)); ok || p != nil {
		t.Fatal("broken source reported zero")
	}
	if _, _, p, ok = s.observe(first, at.Add(44*time.Second)); !ok || p != nil {
		t.Fatal("invalid source did not invalidate baseline")
	}
}

func TestCPUMetricLargeHostReadsOnlyTheBoundedAggregateLine(t *testing.T) {
	first := "cpu 10 0 10 80 0 0 0 0 0 0\n"
	line, err := readCPUMetricLine(strings.NewReader(first + strings.Repeat("intr 1 2 3 4 5\n", 100000)))
	if err != nil || string(line) != first {
		t.Fatal("unrelated IRQ rows blocked a valid aggregate", err)
	}
	if _, err := readCPUMetricLine(strings.NewReader(strings.Repeat("1", 4097) + "\n")); err == nil {
		t.Fatal("unbounded aggregate line accepted")
	}
}

func TestCPUMetricMalformedAndOverflowAreUnknown(t *testing.T) {
	for _, raw := range []string{"", "cpu 1 2 3 4", "cpu0 1 2 3 4 5 6 7 8", "cpu 1 x 3 4 5 6 7 8", "cpu -1 2 3 4 5 6 7 8", fmt.Sprintf("cpu %d 1 0 0 0 0 0 0", ^uint64(0)), "cpu 0 0 0 0 0 0 0 0"} {
		if _, _, _, ok := parseCPUMetric([]byte(raw)); ok {
			t.Fatal("bad source treated as observed", raw)
		}
	}
}

func TestMemoryMetricRequiresBothValidNonDuplicatedCounters(t *testing.T) {
	for _, raw := range []string{"", "MemTotal: 4 kB\n", "MemAvailable: 4 kB\n", "MemTotal: 4 kB\nMemAvailable: 5 kB\n", "MemTotal: 4 kB\nMemAvailable: x kB\n", "MemTotal: 4 kB\nMemAvailable: 0 MB\n", "MemTotal: 4 kB\nMemAvailable: 0 kB\nMemAvailable: 1 kB\n", fmt.Sprintf("MemTotal: %d kB\nMemAvailable: 0 kB\n", ^uint64(0))} {
		if _, _, ok := parseMemoryMetric([]byte(raw)); ok {
			t.Fatal("bad memory became 100% or zero", raw)
		}
	}
	for _, available := range []uint64{0, 4} {
		total, used, ok := parseMemoryMetric([]byte(fmt.Sprintf("MemTotal: 4 kB\nMemAvailable: %d kB\n", available)))
		if !ok || total != 4096 || used != (4-available)*1024 {
			t.Fatal("genuine zero available/used not retained")
		}
	}
}
