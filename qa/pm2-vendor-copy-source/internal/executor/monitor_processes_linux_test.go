//go:build linux

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProcParsingAndPIDReuse(t *testing.T) {
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[11], fields[12], fields[19], fields[21] = "R", "12", "8", "100", "4"
	proc, err := parseProcStat(42, "42 (nginx worker (test)) "+strings.Join(fields, " "), 4096)
	if err != nil || proc.Name != "nginx worker (test)" || proc.Ticks != 20 || proc.RSS != 16384 {
		t.Fatalf("unexpected process: %+v %v", proc, err)
	}
	read, write, available := parseProcIO("read_bytes: 120\nwrite_bytes: 80\n")
	if read != 120 || write != 80 || !available {
		t.Fatalf("unexpected IO %d %d", read, write)
	}
	before := map[int]procSample{42: {PID: 42, StartTime: 100, Ticks: 20, Read: 120, Write: 80, IOAvailable: true}}
	after := map[int]procSample{42: {PID: 42, Name: "nginx", State: "R", StartTime: 100, Ticks: 25, Read: 220, Write: 100, RSS: 16384, IOAvailable: true}}
	rows := computeProcesses(before, after, 1000, 1100, time.Second)
	if len(rows) != 1 || rows[0].CPUPercent != 5 || rows[0].ReadRate != 100 || rows[0].WriteRate != 20 || !rows[0].CPUAvailable || !rows[0].IOAvailable {
		t.Fatalf("unexpected ranking: %+v", rows)
	}
	after[42] = procSample{PID: 42, StartTime: 200, Ticks: 25}
	rows = computeProcesses(before, after, 1000, 1100, time.Second)
	if rows[0].CPUPercent != 0 || rows[0].ReadRate != 0 || rows[0].CPUAvailable || rows[0].IOAvailable {
		t.Fatalf("PID reuse inherited counters: %+v", rows)
	}
}

func TestProcIOAvailabilityCannotInventZero(t *testing.T) {
	for _, data := range []string{"", "read_bytes: 0\n", "write_bytes: 0\n", "read_bytes: invalid\nwrite_bytes: 0\n", "read_bytes: 01\nwrite_bytes: 0\n", "read_bytes: -1\nwrite_bytes: 0\n", "read_bytes: 18446744073709551616\nwrite_bytes: 0\n", "read_bytes: 0\nwrite_bytes: 0\nread_bytes: 0\n", strings.Repeat("x", 8193)} {
		if r, w, ok := parseProcIO(data); ok || r != 0 || w != 0 {
			t.Fatal("unreadable/partial IO certified", r, w, ok)
		}
	}
	if r, w, ok := parseProcIO("rchar: 999\nread_bytes: 0\nwrite_bytes: 0\n"); !ok || r != 0 || w != 0 {
		t.Fatal("complete real zero is not available", r, w, ok)
	}
	first := map[int]procSample{42: {PID: 42, StartTime: 100, Ticks: 10, Read: 100, Write: 200, IOAvailable: true}}
	for _, next := range []procSample{{PID: 42, StartTime: 100, Ticks: 10}, {PID: 42, StartTime: 100, Ticks: 11, Read: 99, Write: 200, IOAvailable: true}, {PID: 42, StartTime: 100, Ticks: 11, Read: 100, Write: 199, IOAvailable: true}, {PID: 42, StartTime: 101, Ticks: 12, Read: 100, Write: 200, IOAvailable: true}} {
		rows := computeProcesses(first, map[int]procSample{42: next}, 100, 200, time.Second)
		if len(rows) != 1 || rows[0].IOAvailable || rows[0].ReadRate != 0 || rows[0].WriteRate != 0 {
			t.Fatal("counter failure certified a rate", rows)
		}
	}
	valid := procSample{PID: 42, StartTime: 100, Ticks: 10, Read: 100, Write: 200, IOAvailable: true}
	rows := computeProcesses(first, map[int]procSample{42: valid}, 100, 200, time.Second)
	if len(rows) != 1 || !rows[0].CPUAvailable || !rows[0].IOAvailable || rows[0].CPUPercent != 0 || rows[0].ReadRate != 0 || rows[0].WriteRate != 0 {
		t.Fatal("verified zero samples lost", rows)
	}
	rows = computeProcesses(first, map[int]procSample{42: valid}, 200, 100, time.Second)
	if rows[0].CPUAvailable {
		t.Fatal("reset CPU total certified", rows)
	}
}

func TestProcSnapshotLimitsGuestAndMissingIO(t *testing.T) {
	root := t.TempDir()
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[19], fields[21] = "S", "100", "1"
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte("cpu 100 20 30 40 5 6 7 8 90 10\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for pid := 1; pid <= 501; pid++ {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(fmt.Sprintf("%d (bounded-fixture) %s", pid, strings.Join(fields, " "))), 0600); err != nil {
			t.Fatal(err)
		}
	}
	sample, total, err := readProcessSample(root)
	if err != nil || total != 216 || len(sample) != 501 || sample[42].IOAvailable {
		t.Fatal("guest double count or missing IO treated as available", total, len(sample), err)
	}
	rows := computeProcesses(sample, sample, total, total+100, time.Second)
	limits := processSnapshotLimits(sample, sample, len(rows))
	if len(rows) != 500 || limits["partial"] != true || limits["display_limited"] != true || limits["sampled_processes"] != 501 || limits["displayed_processes"] != 500 || limits["sample_limit"] != 2000 || limits["display_limit"] != 500 {
		t.Fatal("hidden display truncation", limits, len(rows))
	}
	if processSnapshotLimits(map[int]procSample{}, map[int]procSample{}, 0)["partial"] != false {
		t.Fatal("empty complete fixture mislabeled")
	}
	large := make(map[int]procSample)
	for i := 0; i < 2000; i++ {
		large[i] = procSample{}
	}
	if processSnapshotLimits(large, large, 500)["partial"] != true {
		t.Fatal("sample boundary missing")
	}
	bad := append([]string{}, fields...)
	bad[11], bad[12] = "18446744073709551615", "1"
	if _, err := parseProcStat(42, "42 (overflow) "+strings.Join(bad, " "), 4096); err == nil {
		t.Fatal("tick overflow wrapped")
	}
	bad = append([]string{}, fields...)
	bad[21] = "18446744073709551615"
	if _, err := parseProcStat(42, "42 (overflow) "+strings.Join(bad, " "), 4096); err == nil {
		t.Fatal("RSS overflow wrapped")
	}
	if _, err := parseProcStat(42, "43 (wrong original) "+strings.Join(fields, " "), 4096); err == nil {
		t.Fatal("wrong PID stat accepted")
	}
	t.Log("Bounded proc-shaped counter/limit fixtures, not native kernel permission or signal acceptance")
}

func TestCountEstablishedTCP(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "net"), 0700); err != nil {
		t.Fatal(err)
	}
	tcp := "sl local_address rem_address st\n0: a b 01\n1: a b 0A\n2: a b 01\n"
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(tcp), 0600); err != nil {
		t.Fatal(err)
	}
	count, err := countEstablishedTCP(root)
	if err != nil || count != 2 {
		t.Fatalf("IPv4 count = %d, %v", count, err)
	}
	if err = os.WriteFile(filepath.Join(root, "net", "tcp6"), []byte("sl local_address rem_address st\n0: a b 01\n"), 0600); err != nil {
		t.Fatal(err)
	}
	count, err = countEstablishedTCP(root)
	if err != nil || count != 3 {
		t.Fatalf("IPv4+IPv6 count = %d, %v", count, err)
	}
	if err = os.Remove(filepath.Join(root, "net", "tcp")); err != nil {
		t.Fatal(err)
	}
	if _, err = countEstablishedTCP(root); err == nil {
		t.Fatal("missing IPv4 table must not look like zero connections")
	}
}
