package executor

import (
	"bytes"
	"strconv"
)

func compilerCgroupAvailable(maximum, current []byte) (uint64, bool) {
	valid := func(raw []byte) (uint64, bool) {
		if len(raw) < 2 || len(raw) > 32 || raw[len(raw)-1] != '\n' {
			return 0, false
		}
		text := string(raw[:len(raw)-1])
		value, err := strconv.ParseUint(text, 10, 64)
		return value, err == nil && strconv.FormatUint(value, 10) == text
	}
	used, ok := valid(current)
	if !ok {
		return 0, false
	}
	if bytes.Equal(maximum, []byte("max\n")) {
		return 0, true // This ancestor imposes no finite memory ceiling.
	}
	limit, ok := valid(maximum)
	if !ok || limit == 0 {
		return 0, false
	}
	if used >= limit {
		return 1, true // Never underflow into an enormous concurrency allowance.
	}
	return limit - used, true
}
