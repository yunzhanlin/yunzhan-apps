package executor

import (
	"strings"
	"testing"
)

func TestApacheBodyELFHardeningActualEvidenceAndFailures(t *testing.T) {
	dynamic := " 0x000000000000001e (FLAGS) BIND_NOW\n"
	headers := "  GNU_STACK 0x000000 0x0 0x0 0x000 0x000 RW 0x10\n  GNU_RELRO 0x009000 0x0 0x0 0x100 0x100 R 0x1\n"
	symbols := "  23: 0000000000000000 0 FUNC GLOBAL DEFAULT UND __stack_chk_fail@GLIBC_2.4 (3)\n"
	if err := verifyApacheBodyELFHardening(dynamic, headers, symbols); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][3]string{
		{"lazy binding", headers, symbols},
		{dynamic, strings.Replace(headers, "RW", "RWE", 1), symbols},
		{dynamic, strings.Replace(headers, "GNU_RELRO", "LOAD", 1), symbols},
		{dynamic, headers + headers, symbols},
		{dynamic, headers, "comment: __stack_chk_fail"},
		{dynamic, headers, strings.Replace(symbols, "UND", "12", 1)},
		{dynamic, headers, strings.Replace(symbols, "FUNC", "OBJECT", 1)},
		{dynamic, headers, strings.Replace(symbols, "__stack_chk_fail", "unrelated__stack_chk_fail", 1)},
		{dynamic + "\x00", headers, symbols},
		{dynamic, headers, strings.Repeat("a", 1<<20+1)},
	} {
		if err := verifyApacheBodyELFHardening(bad[0], bad[1], bad[2]); err == nil {
			t.Fatal("missing/malformed hardening claimed verified")
		}
	}
}
