//go:build linux

package executor

import (
	"reflect"
	"strings"
	"testing"
)

func TestIntrusionNumericPortGrammarDoesNotGuessAliasesOrUnlimitedRanges(t *testing.T) {
	for raw, wanted := range map[string][]int{"22\n": {22}, "2882, 22\n": {22, 2882}, "2882:2884": {2882, 2883, 2884}} {
		got, err := intrusionPortList(raw)
		if err != nil || !reflect.DeepEqual(got, wanted) {
			t.Fatal(raw, got, err)
		}
	}
	for _, raw := range []string{"", "ssh", "all", "0", "65536", "022", "+22", "22,", "22,22", "22-24", "24:22", "1:65535", "22\n80", "22\r\n", "22;anything", "22\x00", strings.Repeat("22,", 300)} {
		if got, err := intrusionPortList(raw); err == nil {
			t.Fatal("ambiguous ports accepted", raw, got)
		}
	}
}

func TestIntrusionSSHDConfigurationRequiresActualNumericPorts(t *testing.T) {
	got, err := intrusionSSHDPorts("port 2882\nport 22\nport 2882\npasswordauthentication no\n")
	if err != nil || !reflect.DeepEqual(got, []int{22, 2882}) {
		t.Fatal(got, err)
	}
	for _, raw := range []string{"", "passwordauthentication yes\n", "port 2882", "port 22 extra\n", "port 0\n", "port +22\n", "port ssh\n", "port 22\r\n", strings.Repeat("x", 24577) + "\n"} {
		if got, err := intrusionSSHDPorts(raw); err == nil {
			t.Fatal("unverified SSH accepted", raw, got)
		}
	}
}

func TestIntrusionListenersNeedNumericSocketAndExactDaemonOwner(t *testing.T) {
	raw := "LISTEN 0 128 0.0.0.0:2882 0.0.0.0:* users:((\"sshd\",pid=663,fd=6))\nLISTEN 0 128 [::]:2882 [::]:* users:((\"sshd\",pid=663,fd=7),(\"systemd\",pid=1,fd=5))\nLISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=990,fd=3))\n"
	got, err := intrusionListeningPorts(raw)
	if err != nil || !reflect.DeepEqual(got, []int{2882}) {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"", strings.ReplaceAll(raw, `"sshd"`, `"not-sshd"`), strings.ReplaceAll(raw, "LISTEN", "ESTAB"), strings.ReplaceAll(raw, ":2882", ":ssh"), strings.TrimSuffix(raw, "\n"), "LISTEN 0 128 0.0.0.0:22 users:((\"sshd\",pid=663,fd=6))\n"} {
		if got, err := intrusionListeningPorts(bad); err == nil {
			t.Fatal("unknown socket accepted", bad, got)
		}
	}
}

func TestIntrusionActionListNeverBecomesAnOptionOrCommand(t *testing.T) {
	head := "The jail sshd has the following actions:\n"
	got, err := intrusionActionNames(head + "nftables, iptables-multiport\n")
	if err != nil || !reflect.DeepEqual(got, []string{"iptables-multiport", "nftables"}) {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"", head, head + "\n", head + "--restart\n", head + "nftables;nft\n", head + "nftables,nftables\n", head + "nftables\nother\n", strings.Replace(head, "sshd", "foreign", 1) + "nftables\n"} {
		if got, err := intrusionActionNames(bad); err == nil {
			t.Fatal("ambiguous action accepted", bad, got)
		}
	}
}
