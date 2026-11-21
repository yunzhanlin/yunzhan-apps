package executor

import (
	"strings"
	"testing"
)

func TestLoadBalanceStreamInitgroupsRequiresNoSupplementaryGroups(t *testing.T) {
	// Actual Ubuntu24 read-only original observation: getent initgroups emits
	// only the padded name for an account with no supplementary groups. The
	// primary GID is independently matched in all four NSS files and actual
	// getent passwd/group; it must not be invented in this command's output.
	for _, row := range []string{"panel-lbstream       \n", "panel-lbstream\n", "panel-lbstream\t\n"} {
		if !loadBalanceStreamNSSGroups(row, 982) {
			t.Fatalf("empty supplementary group list refused: %q", row)
		}
	}
	for _, row := range []string{"", "982\n", "foreign\n", "panel-lbstream 0\n", "panel-lbstream 982\n", "panel-lbstream 0982\n", "panel-lbstream 982 982\n", "panel-lbstream 982 0\n", "panel-lbstream\nforeign\n", "panel-lbstream\n\n", "panel-lbstream", "panel-lbstream\r\n", "panel-lbstream\v\n", "panel-lbstream\u00a0\n", "panel-lbstream\x00\n", strings.Repeat(" ", 128) + "panel-lbstream\n"} {
		if loadBalanceStreamNSSGroups(row, 982) {
			t.Fatalf("supplementary, duplicate, partial or malformed memberships admitted: %q", row)
		}
	}
	for _, gid := range []uint32{0, 99, 1000, 4294967295} {
		if loadBalanceStreamNSSGroups("panel-lbstream\n", gid) {
			t.Fatal("out-of-range independently verified primary GID admitted")
		}
	}
}
