package executor

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestMemcachedUnixProtocolPacketsAreFixedLengthFramedAndAtomic(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("云栈\r\nflush_all\x00"))
	value := []byte("值😀\r\nEND\r\n\x00")
	for _, action := range []string{"get", "add", "cas", "delete", "stats"} {
		in := core.MemcachedUnixCacheInput{Action: action, KeyBase64: key}
		var want []byte
		switch action {
		case "get":
			want = []byte("mg " + key + " b f c t v u\r\n")
		case "add", "cas":
			in.ValueBase64, in.Flags, in.TTLSeconds = base64.StdEncoding.EncodeToString(value), 0xffffffff, 120
			mode := "ME"
			if action == "cas" {
				in.CAS = "18446744073709551615"
				mode = "C" + in.CAS
			}
			want = append([]byte(fmt.Sprintf("ms %s %d b %s F4294967295 T120 c\r\n", key, len(value), mode)), value...)
			want = append(want, '\r', '\n')
		case "delete":
			in.CAS = "7"
			want = []byte("md " + key + " b C7\r\n")
		case "stats":
			in.KeyBase64, in.Stats = "", "basic"
			want = []byte("stats\r\n")
		}
		packet, err := memcachedUnixCachePacket(in)
		if err != nil || !bytes.Equal(packet, want) {
			t.Fatal(action, err)
		}
	}
	if _, err := memcachedUnixCachePacket(core.MemcachedUnixCacheInput{Action: "flush_all"}); err == nil {
		t.Fatal("arbitrary native command")
	}
}

func TestMemcachedUnixProtocolGetPreservesBinaryValueFlagsTTLAndCAS(t *testing.T) {
	value := []byte("\x00云栈😀\r\nEND\r\n")
	raw := append([]byte(fmt.Sprintf("VA %d t19 c18446744073709551615 f4294967295 b X\r\n", len(value))), value...)
	raw = append(raw, '\r', '\n')
	out, err := readMemcachedUnixCacheReply(bytes.NewReader(raw), "get")
	if err != nil || !out.Found || out.Changed || out.CAS != "18446744073709551615" || out.Flags != 0xffffffff || out.TTLRemaining != 19 || !out.Stale || out.ValueBase64 != base64.StdEncoding.EncodeToString(value) {
		t.Fatal("binary-safe complete snapshot", err)
	}
	for _, wire := range []string{"EN\r\n", "VA 0 f0 c1 t-1\r\n\r\n"} {
		out, err := readMemcachedUnixCacheReply(strings.NewReader(wire), "get")
		if err != nil || out.TTLRemaining != -1 {
			t.Fatal(wire, err)
		}
	}
	if _, err := readMemcachedUnixCacheReply(strings.NewReader(fmt.Sprintf("VA %d f0 c1 t-1\r\n", core.MemcachedUnixConsoleValueBytes+1)), "get"); !errors.Is(err, errMemcachedUnixConsoleLarge) {
		t.Fatal("oversize value silently truncated/reconstructed", err)
	}
}

func TestMemcachedUnixProtocolRejectsAmbiguousTruncatedAndUnboundedReplies(t *testing.T) {
	for _, raw := range []string{
		"EN\n", "EN\r\nEXTRA\r\n", "VA 1 f0 c1\r\na\r\n", "VA 1 f0 f1 c1 t0\r\na\r\n",
		"VA 1 f0 c0 t0\r\na\r\n", "VA 1 f0 c1 t-2\r\na\r\n", "VA 1 f0 c1 t01\r\na\r\n",
		"VA 1 f0 c1 t0 Kunknown\r\na\r\n", "VA 1 f0 c1 t0 W Z\r\na\r\n", "VA 2 f0 c1 t0\r\na\r\n",
		"VA 1 f0 c1 t0\r\naXX", "VA -1 f0 c1 t0\r\n", "VA 01 f0 c1 t0\r\na\r\n",
		"VA 99999999999999999999999 f0 c1 t0\r\n", "SERVER_ERROR secret-not-in-error\r\n", strings.Repeat("x", 4097) + "\r\n",
	} {
		if _, err := readMemcachedUnixCacheReply(strings.NewReader(raw), "get"); err == nil || strings.Contains(err.Error(), "secret-not-in-error") {
			t.Fatal("malformed response accepted/echoed")
		}
	}
}

func TestMemcachedUnixProtocolMutationConflictsNeverBecomeSuccess(t *testing.T) {
	for _, c := range []struct {
		action, wire string
		want         error
	}{
		{"add", "HD c2\r\n", nil}, {"cas", "HD c18446744073709551615\r\n", nil}, {"delete", "HD\r\n", nil},
		{"add", "NS c0\r\n", errMemcachedUnixExists}, {"cas", "EX c0\r\n", errMemcachedUnixCAS}, {"cas", "NF c0\r\n", errMemcachedUnixMissing},
		{"delete", "EX\r\n", errMemcachedUnixCAS}, {"delete", "NF\r\n", errMemcachedUnixMissing},
		{"cas", "HD c0\r\n", errMemcachedUnixProtocol}, {"delete", "HD c2\r\n", errMemcachedUnixProtocol}, {"add", "HD\r\n", errMemcachedUnixProtocol},
	} {
		out, err := readMemcachedUnixCacheReply(strings.NewReader(c.wire), c.action)
		if !errors.Is(err, c.want) || (err == nil) != out.Changed {
			t.Fatal(c.action, c.wire, err)
		}
	}
}

func TestMemcachedUnixProtocolStatsHaveClosedTotalLineAndDuplicateBudgets(t *testing.T) {
	out, err := readMemcachedUnixCacheReply(strings.NewReader("STAT version 1.6.45\r\nSTAT curr_items 12\r\nEND\r\n"), "stats")
	if err != nil || len(out.Statistics) != 2 || out.Statistics["curr_items"] != "12" {
		t.Fatal(err)
	}
	var oversize strings.Builder
	for i := 0; i < 2049; i++ {
		fmt.Fprintf(&oversize, "STAT k%d 1\r\n", i)
	}
	oversize.WriteString("END\r\n")
	for _, wire := range []string{"STAT a 1\r\nSTAT a 2\r\nEND\r\n", "STAT a 1\r\n", oversize.String(), "STAT a " + strings.Repeat("v", 513) + "\r\nEND\r\n", "END\r\nEXTRA\r\n"} {
		if _, err := readMemcachedUnixCacheReply(strings.NewReader(wire), "stats"); err == nil {
			t.Fatal("unsafe stats reply")
		}
	}
}
