package executor

import "testing"

func TestCompilerCgroupAvailablePreservesFiniteOwnAndAncestorLimits(t *testing.T) {
	for _, test := range []struct {
		maximum, current string
		free             uint64
		valid            bool
	}{
		{"805306368\n", "134217728\n", 640 << 20, true},
		{"max\n", "0\n", 0, true},
		{"100\n", "100\n", 1, true},
		{"100\n", "101\n", 1, true},
		{"0\n", "0\n", 0, false},
		{"0805\n", "0\n", 0, false},
		{"100\n", "-1\n", 0, false},
		{"100", "0\n", 0, false},
		{"100\n", "0", 0, false},
		{"max\nunknown\n", "0\n", 0, false},
		{"100\n", "0\n0\n", 0, false},
		{"100\n", "+0\n", 0, false},
		{"100\n", " 0\n", 0, false},
		{"100\n", "18446744073709551616\n", 0, false},
	} {
		got, ok := compilerCgroupAvailable([]byte(test.maximum), []byte(test.current))
		if got != test.free || ok != test.valid {
			t.Fatalf("%+v: got %d / %v", test, got, ok)
		}
	}
}
