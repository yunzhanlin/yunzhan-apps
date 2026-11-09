//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDiskUsageKeepsReservedBlocksOutOfAvailable(t *testing.T) {
	total, used, available := diskUsage(syscall.Statfs_t{Blocks: 100, Bfree: 30, Bavail: 20, Bsize: 4096})
	if total != 100*4096 || used != 70*4096 || available != 20*4096 {
		t.Fatalf("unexpected disk usage total=%d used=%d available=%d", total, used, available)
	}
}

func TestBlockIOCountersAvoidVirtualDevices(t *testing.T) {
	root := t.TempDir()
	for name, value := range map[string]string{"vda": "1 0 2 0 3 0 4 0", "sdb": "1 0 6 0 3 0 8 0", "loop0": "1 0 100 0 3 0 100 0"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	read, write, ok := blockIOCounters(root)
	if !ok || read != 8*512 || write != 12*512 {
		t.Fatalf("unexpected counters %d %d %t", read, write, ok)
	}
}
