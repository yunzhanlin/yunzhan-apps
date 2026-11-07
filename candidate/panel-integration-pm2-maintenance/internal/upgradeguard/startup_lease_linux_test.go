//go:build linux

package upgradeguard

import (
	"errors"
	"testing"
	"time"
)

func TestStartupLeaseEnumerationIsBoundedAndRequiresOneExactSnapshot(t *testing.T) {
	record := testStartupRecord()
	valid := []byte("1: FLOCK ADVISORY WRITE 1234 08:01:12345 0 EOF\n")
	fixed := time.Unix(100, 0)
	now := func() time.Time { return fixed }
	calls := 0
	read := func() ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, nil
		}
		if calls == 2 {
			return append(append([]byte{}, valid...), valid...), nil
		}
		return valid, nil
	}
	if err := startupLeaseSnapshot(record, read, now); err != nil || calls != 3 {
		t.Fatal("fresh unique exact kernel lease was not required", calls, err)
	}
	for _, raw := range [][]byte{nil, append(append([]byte{}, valid...), valid...), []byte("1: FLOCK ADVISORY WRITE 5678 08:01:12345 0 EOF\n"), []byte("1: FLOCK ADVISORY READ 1234 08:01:12345 0 EOF\n")} {
		calls = 0
		if err := startupLeaseSnapshot(record, func() ([]byte, error) { calls++; return raw, nil }, now); err == nil || calls != 8 {
			t.Fatal("absent, duplicate, foreign or shared kernel lease accepted", calls, err)
		}
	}
	calls = 0
	if err := startupLeaseSnapshot(record, func() ([]byte, error) { calls++; return valid, errors.New("unavailable procfs") }, now); err == nil || calls != 1 {
		t.Fatal("kernel I/O failure must refuse immediately", calls, err)
	}
	calls = 0
	if err := startupLeaseSnapshot(record, func() ([]byte, error) { calls++; return make([]byte, 4*1024*1024+1), nil }, now); err == nil || calls != 1 {
		t.Fatal("oversized enumeration accepted", calls, err)
	}
	calls = 0
	if err := startupLeaseSnapshot(record, func() ([]byte, error) { calls++; fixed = fixed.Add(100 * time.Millisecond); return valid, nil }, now); err == nil || calls != 1 {
		t.Fatal("late exact enumeration accepted", calls, err)
	}
}
