//go:build linux

package executor

import (
	"context"
	"testing"
	"unsafe"
)

func TestLoadBalanceStreamKernelControllerGrammarAndReadOnlyQueryLayout(t *testing.T) {
	for _, raw := range []string{"cpu memory pids\n", "cpuset cpu io memory pids hugetlb rdma misc dmem\n"} {
		if !loadBalanceStreamRequiredControllers([]byte(raw)) {
			t.Fatal("actual supported controller grammar rejected", raw)
		}
	}
	for _, raw := range []string{"", "cpu memory\n", "pids memory\n", "cpu pids\n", "cpu memory memory pids\n", "cpu memory pids", "cpu memory pids\r\n", "CPU memory pids\n", "cpu memory pids\x00\n"} {
		if loadBalanceStreamRequiredControllers([]byte(raw)) {
			t.Fatal("missing/ambiguous controller inventory accepted", raw)
		}
	}
	var value loadBalanceStreamBPFQuery
	if unsafe.Sizeof(value) != 32 || unsafe.Offsetof(value.ProgramIDs) != 16 || unsafe.Offsetof(value.ProgramCount) != 24 {
		t.Fatal("native BPF read-only query prefix layout drifted")
	}
	if value, err := loadBalanceStreamCgroupBPFPrograms(nil, 0); err == nil || value != nil {
		t.Fatal("unheld descriptor reached a BPF call")
	}
	if facts, err := measureLoadBalanceStreamServiceFacts(context.Background(), nil); err == nil || facts.IPFilterAvailable {
		t.Fatal("missing installed context reported kernel availability")
	}
}
