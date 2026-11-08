package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func requireLoadBalanceWhitespaceEquivalent(t *testing.T, raw []byte) {
	t.Helper()
	before := bytes.Clone(raw)
	digest := sha256.Sum256(raw)
	want := bytes.TrimRight(raw, " \t\r\n")
	got := trimLoadBalanceJSONTrailingWhitespace(raw)
	if !bytes.Equal(got, want) || !bytes.Equal(raw, before) || sha256.Sum256(raw) != digest {
		t.Fatalf("decoder input or complete original bytes changed: input=%x got=%x want=%x", before, got, want)
	}
	if len(got) > 0 && &got[0] != &raw[0] {
		t.Fatal("trimming unexpectedly copied or retained an alternative record")
	}
}

func TestLoadBalanceJSONWhitespaceMatchesOriginalEveryByteAndBoundary(t *testing.T) {
	for value := 0; value < 256; value++ {
		for count := 0; count <= 33; count++ {
			raw := append([]byte(`{"fixed":"云栈"}`), bytes.Repeat([]byte{byte(value)}, count)...)
			requireLoadBalanceWhitespaceEquivalent(t, raw)
		}
	}
	for _, count := range []int{0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 255, 256, 257, 4095, 4096, 65535, 128 << 10, 256 << 10} {
		for _, edge := range []byte{' ', '\t', '\r', '\n', 0, 11, 12, 0x80, 0xff} {
			raw := append([]byte(`{"fixed":true}`), bytes.Repeat([]byte{' '}, count)...)
			raw = append(raw, edge)
			raw = append(raw, bytes.Repeat([]byte{' '}, count%31)...)
			requireLoadBalanceWhitespaceEquivalent(t, raw)
		}
	}
	requireLoadBalanceWhitespaceEquivalent(t, nil)
	requireLoadBalanceWhitespaceEquivalent(t, []byte{})
}

func TestLoadBalanceJSONWhitespaceEveryEightByteASCIIMixture(t *testing.T) {
	whitespace := []byte{' ', '\t', '\r', '\n'}
	for pattern := 0; pattern < 1<<16; pattern++ {
		raw := []byte(`{"original":1}`)
		for index := 0; index < 8; index++ {
			raw = append(raw, whitespace[pattern>>(2*index)&3])
		}
		raw = append(raw, []byte("        \n        ")...)
		requireLoadBalanceWhitespaceEquivalent(t, raw)
	}
}

func TestLoadBalanceJSONWhitespaceNeverStripsOtherControlOrUnicodePadding(t *testing.T) {
	for _, suffix := range []string{"\x00", "\v", "\f", "\u0085", "\u00a0", "\u1680", "\u2000", "\u2028", "\u2029", "\u3000"} {
		raw := append([]byte(`{"original":true}`), []byte(suffix+"        \r\n        ")...)
		requireLoadBalanceWhitespaceEquivalent(t, raw)
		var value map[string]any
		if json.Unmarshal(trimLoadBalanceJSONTrailingWhitespace(raw), &value) == nil {
			t.Fatalf("non-JSON padding acquired validity: %q", suffix)
		}
	}
}

var loadBalanceWhitespaceBenchmarkLength int

func BenchmarkLoadBalanceJSONTrailingWhitespace(b *testing.B) {
	raw := append([]byte(`{"bounded":true}`), bytes.Repeat([]byte{' '}, 256<<10)...)
	for _, test := range []struct {
		name string
		trim func([]byte) []byte
	}{{"original-byte-set", func(data []byte) []byte { return bytes.TrimRight(data, " \t\r\n") }}, {"eight-byte-spaces", trimLoadBalanceJSONTrailingWhitespace}} {
		b.Run(test.name, func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			for index := 0; index < b.N; index++ {
				loadBalanceWhitespaceBenchmarkLength = len(test.trim(raw))
			}
		})
	}
}
