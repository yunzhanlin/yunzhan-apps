package executor

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func streamSocketFixture(protocol string) string {
	header := " sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"
	local, remote := "0100007F:A410", "00000000:0000"
	if strings.HasSuffix(protocol, "6") {
		header = strings.Replace(header, "rem_address", "remote_address", 1)
		local = "00000000000000000000000001000000:A410"
		remote = "00000000000000000000000000000000:0000"
	}
	state, extra := "0A", "1 0000000000000000 100 0 0 10 0"
	if strings.HasPrefix(protocol, "udp") {
		header += " ref pointer drops"
		state = "07"
		extra = "2 0000000000000000 0"
	}
	return header + "\n" + fmt.Sprintf(" 0: %s %s %s 00000000:00000000 00:00000000 00000000 991 0 1234 %s\n", local, remote, state, extra)
}

func TestLoadBalanceStreamSocketTablesKeepBothFamiliesBoundUDPAndOwnerlessTimeWait(t *testing.T) {
	for _, protocol := range []string{"tcp", "tcp6", "udp", "udp6"} {
		rows, err := decodeStreamSocketTable([]byte(streamSocketFixture(protocol)), protocol)
		if err != nil || len(rows) != 1 || rows[0].Protocol != protocol || rows[0].Local.Port() != 42000 || !rows[0].Local.Addr().IsLoopback() || rows[0].Remote.Port() != 0 || !rows[0].Remote.Addr().IsUnspecified() || rows[0].UID != 991 || rows[0].Inode != 1234 {
			t.Fatal("actual kernel table grammar lost endpoint/identity", protocol, err)
		}
		if strings.HasPrefix(protocol, "udp") {
			// UDP sl is a hash bucket, not a unique socket/sequence number.
			raw := streamSocketFixture(protocol)
			line := strings.Split(raw, "\n")[1]
			rows, err := decodeStreamSocketTable([]byte(raw+strings.Replace(line, "1234", "1235", 1)+"\n"), protocol)
			if err != nil || len(rows) != 2 {
				t.Fatal("legitimate shared UDP hash slot refused", err)
			}
		}
	}
	raw := strings.Replace(streamSocketFixture("tcp"), " 0A ", " 06 ", 1)
	raw = strings.Replace(raw, "00000000:0000", "0200007F:ABCD", 1)
	raw = strings.Replace(raw, " 1234 ", " 0 ", 1)
	rows, err := decodeStreamSocketTable([]byte(raw), "tcp")
	if err != nil || len(rows) != 1 || rows[0].Inode != 0 || rows[0].State != 6 {
		t.Fatal("ownerless TIME_WAIT was treated as a listener or corrupt table", err)
	}
	for _, tc := range []struct {
		raw  string
		v6   bool
		want string
	}{{"0100007F:A410", false, "127.0.0.1:42000"}, {"00000000:0000", false, "0.0.0.0:0"}, {"00000000000000000000000001000000:A410", true, "[::1]:42000"}, {"B80D0120000000000000000002000000:0050", true, "[2001:db8::2]:80"}} {
		got, ok := streamSocketAddress(tc.raw, tc.v6)
		if !ok || got != netip.MustParseAddrPort(tc.want) {
			t.Fatal("native address word order changed", tc, got)
		}
	}
}

func TestLoadBalanceStreamSocketTablesRejectTruncatedUnknownAndInventedListeners(t *testing.T) {
	good := streamSocketFixture("tcp")
	for _, raw := range []string{"", good[:len(good)-1], good + "\x00\n", strings.Replace(good, "uid timeout inode", "timeout uid inode", 1), strings.Replace(good, " 0A ", " GG ", 1), strings.Replace(good, " 0A ", " 00 ", 1), strings.Replace(good, " 0A ", " 0a ", 1), strings.Replace(good, "A410", "a410", 1), strings.Replace(good, "A410", "0000", 1), strings.Replace(good, " 1234 ", " 0 ", 1), strings.Replace(good, " 1234 ", " 01234 ", 1), strings.Replace(good, " 991 ", " -1 ", 1), strings.Replace(good, " 991 ", " 4294967296 ", 1), strings.Replace(good, "00000000:0000", "0200007F:0000", 1), strings.Replace(good, "00000000:0000", "00000000:0001", 1), strings.Replace(good, "0100007F:A410", "0100007F:A410:01", 1), strings.Repeat("x", streamSocketTableBytes+1)} {
		if rows, err := decodeStreamSocketTable([]byte(raw), "tcp"); err == nil || rows != nil {
			t.Fatal("truncated/ambiguous/ownerless listener accepted")
		}
	}
	for _, protocol := range []string{"unix", "tcp4", "TCP", "", "../tcp"} {
		if rows, err := decodeStreamSocketTable([]byte(good), protocol); err == nil || rows != nil {
			t.Fatal("caller selected a different table grammar", protocol)
		}
	}
	udp := streamSocketFixture("udp")
	if _, err := decodeStreamSocketTable([]byte(strings.Replace(udp, " ref pointer drops", "", 1)), "udp"); err == nil {
		t.Fatal("incomplete UDP header accepted")
	}
	if _, err := decodeStreamSocketTable([]byte(strings.Replace(udp, " 1234 ", " 0 ", 1)), "udp"); err == nil {
		t.Fatal("ownerless UDP listener invented")
	}
}
