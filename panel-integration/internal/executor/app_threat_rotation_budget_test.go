package executor

import (
	"testing"
	"time"
)

func TestThreatIDSRotationWarningBudgetCannotBeBypassedByChangingErrors(t *testing.T) {
	var b threatIDSRotationWarningBudget
	now := time.Unix(1700000000, 0)
	if emit, count := b.deferCycle(now); !emit || count != 1 {
		t.Fatal("initial failure not reported", emit, count)
	}
	for i := range 29 {
		if emit, _ := b.deferCycle(now.Add(time.Duration(i+1) * 2 * time.Second)); emit {
			t.Fatal("repeated or changing failure bypassed minute budget")
		}
	}
	if emit, count := b.deferCycle(now.Add(time.Minute)); !emit || count != 30 {
		t.Fatal("suppressed cycles lost", emit, count)
	}
	b.deferred = ^uint64(0)
	if emit, count := b.deferCycle(now.Add(2 * time.Minute)); !emit || count != ^uint64(0) {
		t.Fatal("cycle count overflowed", emit, count)
	}
}
