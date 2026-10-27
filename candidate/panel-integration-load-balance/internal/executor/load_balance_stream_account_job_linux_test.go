//go:build linux

package executor

import "testing"

func TestLoadBalanceStreamAccountFixedJobRejectsAliasesAndUnboundBuild(t *testing.T) {
	for _, job := range []string{"", "..", "../job", "load-balance", "aabb", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "00000000000000000000000000000000/other"} {
		if RunLoadBalanceStreamAccountJob(job) != errLoadBalanceStreamAccount {
			t.Fatal("invalid fixed original job reached account effects")
		}
	}
}
