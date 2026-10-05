//go:build linux

package executor

import (
	"os"
	"path/filepath"
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
	read, write := parseProcIO("read_bytes: 120\nwrite_bytes: 80\n")
	if read != 120 || write != 80 {
		t.Fatalf("unexpected IO %d %d", read, write)
	}
	before := map[int]procSample{42: {PID: 42, StartTime: 100, Ticks: 20, Read: 120, Write: 80}}
	after := map[int]procSample{42: {PID: 42, Name: "nginx", State: "R", StartTime: 100, Ticks: 25, Read: 220, Write: 100, RSS: 16384}}
	rows := computeProcesses(before, after, 1000, 1100, time.Second)
	if len(rows) != 1 || rows[0].CPUPercent != 5 || rows[0].ReadRate != 100 || rows[0].WriteRate != 20 {
		t.Fatalf("unexpected ranking: %+v", rows)
	}
	after[42] = procSample{PID: 42, StartTime: 200, Ticks: 25}
	rows = computeProcesses(before, after, 1000, 1100, time.Second)
	if rows[0].CPUPercent != 0 || rows[0].ReadRate != 0 {
		t.Fatalf("PID reuse inherited counters: %+v", rows)
	}
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
