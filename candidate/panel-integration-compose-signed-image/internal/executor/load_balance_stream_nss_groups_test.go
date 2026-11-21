package executor

import (
	"strings"
	"testing"
)

func TestLoadBalanceStreamInitgroupsRequiresOnlyDedicatedPrimaryGroup(t *testing.T) {
	// getent pads the name field; numeric membership remains exact. Actual
	// installed-system output is qualified separately from these parser cases.
	for _, row := range []string{"panel-lbstream         977\n", "panel-lbstream 991\n", "panel-lbstream\t991\n"} {
		gid := uint32(991)
		if strings.Contains(row, "977") {
			gid = 977
		}
		if !loadBalanceStreamNSSGroups(row, gid) {
			t.Fatalf("dedicated group refused: %q", row)
		}
	}
	for _, row := range []string{"", "991\n", "foreign 991\n", "panel-lbstream 0\n", "panel-lbstream 0991\n", "panel-lbstream 992\n", "panel-lbstream 991 0\n", "panel-lbstream 991 991\n", "panel-lbstream 991\nforeign 0\n", "panel-lbstream 991\n\n", "panel-lbstream 991", "panel-lbstream 991\r\n", "panel-lbstream\v991\n", "panel-lbstream\u00a0991\n", "panel-lbstream 991\x00\n", strings.Repeat(" ", 128) + "panel-lbstream 991\n"} {
		if loadBalanceStreamNSSGroups(row, 991) {
			t.Fatalf("foreign, duplicate, partial or malformed memberships admitted: %q", row)
		}
	}
	for _, gid := range []uint32{0, 99, 1000, 4294967295} {
		if loadBalanceStreamNSSGroups("panel-lbstream 991\n", gid) {
			t.Fatal("out-of-range primary GID admitted")
		}
	}
}
