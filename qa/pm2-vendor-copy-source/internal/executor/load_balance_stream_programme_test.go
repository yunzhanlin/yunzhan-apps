package executor

import (
	"strings"
	"testing"
)

func TestLoadBalanceStreamProgrammeInputsRequiresIndependentCompiledCohort(t *testing.T) {
	bound := strings.Repeat("a", 64)
	if !loadBalanceStreamProgrammeInputsMatch(bound, bound) {
		t.Fatal("exact independently compiled cohort refused")
	}
	for _, value := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("b", 64), bound[:63], bound + "\n", "not-a-published-cohort"} {
		if loadBalanceStreamProgrammeInputsMatch(bound, value) || loadBalanceStreamProgrammeInputsMatch(value, bound) {
			t.Fatal("missing or changed compiled source cohort admitted")
		}
	}
}
