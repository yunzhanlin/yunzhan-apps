package executor

import "time"

// Constant-size diagnostics, independent of changing error strings. The next
// deadline is not reset by a successful cycle, preventing alternating errors
// from bypassing the one-message-per-minute journal budget.
type threatIDSRotationWarningBudget struct {
	next     time.Time
	deferred uint64
}

func (b *threatIDSRotationWarningBudget) deferCycle(now time.Time) (bool, uint64) {
	if b.deferred != ^uint64(0) {
		b.deferred++
	}
	if !b.next.IsZero() && now.Before(b.next) {
		return false, 0
	}
	count := b.deferred
	b.deferred = 0
	b.next = now.Add(time.Minute)
	return true, count
}
