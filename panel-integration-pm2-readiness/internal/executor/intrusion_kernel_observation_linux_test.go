//go:build linux

package executor

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func intrusionKernelFixture(t *testing.T) (map[string]string, func(string, ...string) (string, error), *int) {
	t.Helper()
	v, _ := intrusionNftFixture(t)
	answers := map[string]string{
		"/usr/bin/fail2ban-client get sshd action nftables name":                  "probe_sshd\n",
		"/usr/bin/fail2ban-client get sshd action nftables table":                 "f2b-table\n",
		"/usr/bin/fail2ban-client get sshd action nftables table_family":          "inet\n",
		"/usr/bin/fail2ban-client get sshd action nftables chain":                 "ERROR",
		"/usr/sbin/nft -j list tables":                                            "ERROR",
		"/usr/bin/fail2ban-client get sshd action nftables addr_set":              "addr-set-<name>\n",
		"/usr/bin/fail2ban-client get sshd action nftables addr_set?family=inet6": "addr6-set-<name>\n",
		"/usr/sbin/nft -j list table inet f2b-table":                              string(intrusionNftEncode(t, v)),
	}
	calls := new(int)
	read := func(program string, args ...string) (string, error) {
		key := program + " " + strings.Join(args, " ")
		raw, ok := answers[key]
		if !ok {
			t.Fatal("unexpected non-read-only or injected command", key)
		}
		*calls++
		if raw == "ERROR" {
			return "private original backend response", errors.New("secret backend failure")
		}
		return raw, nil
	}
	return answers, read, calls
}

func TestIntrusionKernelObservationUsesRealRuleAndActiveSet(t *testing.T) {
	_, read, calls := intrusionKernelFixture(t)
	out, e := inspectIntrusionKernel(read, "nftables", []int{2882}, []netip.Addr{netip.MustParseAddr("127.0.0.2")})
	if e != nil || !out.Verified || !out.IPv4 || out.IPv6 || out.ActiveBans != 1 || *calls != 6 {
		t.Fatal(out, e, *calls)
	}
	if out, e = inspectIntrusionKernel(read, "nftables", []int{2883}, []netip.Addr{netip.MustParseAddr("127.0.0.2")}); e == nil || out.Verified {
		t.Fatal("new setting masked stale kernel port", out, e)
	}
}

func TestIntrusionKernelMetadataCannotInjectOptionsTagsOrReadPrivateErrors(t *testing.T) {
	for property, raw := range map[string]string{"name": "probe_sshd\nextra", "table": "--help\n", "table_family": "ip\n", "addr_set": "addr-set-<foreign>\n", "addr_set?family=inet6": "addr6-<name>-<name>\n"} {
		answers, read, _ := intrusionKernelFixture(t)
		answers["/usr/bin/fail2ban-client get sshd action nftables "+property] = raw
		if out, e := inspectIntrusionKernel(read, "nftables", []int{2882}, []netip.Addr{netip.MustParseAddr("127.0.0.2")}); e == nil || out.Verified {
			t.Fatal(property, out, e)
		}
	}
	answers, read, _ := intrusionKernelFixture(t)
	answers["/usr/sbin/nft -j list table inet f2b-table"] = "ERROR"
	if out, e := inspectIntrusionKernel(read, "nftables", []int{2882}, []netip.Addr{netip.MustParseAddr("127.0.0.2")}); e == nil || out.Verified || strings.Contains(e.Error(), "private") || strings.Contains(e.Error(), "secret") {
		t.Fatal(out, e)
	}
	_, read, calls := intrusionKernelFixture(t)
	if out, e := inspectIntrusionKernel(read, "--restart", []int{2882}, nil); e == nil || out.Verified || *calls != 0 {
		t.Fatal("action became an option", out, e, *calls)
	}
}

func TestIntrusionBannedAddressesAreBoundedCanonicalSetsNotCommands(t *testing.T) {
	got, e := intrusionBannedAddresses("2001:db8::2 127.0.0.2\n")
	wanted := []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("2001:db8::2")}
	if e != nil || !slices.Equal(got, wanted) {
		t.Fatal(got, e)
	}
	empty, e := intrusionBannedAddresses("\n")
	if e != nil || len(empty) != 0 {
		t.Fatal(empty, e)
	}
	for _, raw := range []string{"127.0.0.2/24", "fe80::2%eth0", "::ffff:127.0.0.2", "127.0.0.2;command", "127.0.0.2\r\n", "127.0.0.2\x00", "127.0.0.2 127.0.0.2", "2001:db8::2 2001:DB8::2", strings.Repeat("127.0.0.2 ", 513)} {
		if got, e := intrusionBannedAddresses(raw); e == nil {
			t.Fatal("ambiguous ban input accepted", raw, got)
		}
	}
}

func TestIntrusionKernelRequiresOneUnambiguousActualChain(t *testing.T) {
	v, scope := intrusionNftFixture(t)
	chain, e := intrusionNftObservedChain(intrusionNftEncode(t, v), scope)
	if e != nil || chain != "f2b-chain" {
		t.Fatal(chain, e)
	}
	own := intrusionNftOwnRule(v)
	clone := map[string]any{}
	for k, value := range own {
		clone[k] = value
	}
	clone["chain"] = "foreign-chain"
	clone["handle"] = float64(30)
	v["nftables"] = append(intrusionNftObjects(v), map[string]any{"rule": clone})
	if chain, e = intrusionNftObservedChain(intrusionNftEncode(t, v), scope); e == nil || chain != "" {
		t.Fatal("multiple enforcing chains guessed", chain, e)
	}
}

func TestIntrusionEmptyBanListStillChecksExistingKernelPortScope(t *testing.T) {
	v, scope := intrusionNftFixture(t)
	intrusionNftOwnSet(v)["elem"] = []any{}
	scope.Banned = nil
	out, e := inspectIntrusionNftScope(intrusionNftEncode(t, v), scope)
	if e != nil || !out.Verified || out.ActiveBans != 0 {
		t.Fatal(out, e)
	}
	scope.Ports = []int{2883}
	if out, e = inspectIntrusionNftScope(intrusionNftEncode(t, v), scope); e == nil || out.Verified {
		t.Fatal("empty ban list masked stale kernel port", out, e)
	}
}
