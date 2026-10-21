//go:build linux

package executor

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"local/panel/internal/core"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"testing"
)

// This opt-in affects only this _test.go binary. It cannot enable a production
// command or weaken runtime authority. The owned fixture independently proves
// the host namespace inode and executes us only in its fresh network namespace.
func TestOwnedIntrusionNftPortPlanNative(t *testing.T) {
	if os.Getenv("PANEL_OWNED_INTRUSION_NFT_FIXTURE") != "24bhjm" {
		t.Skip("explicit owned network-namespace fixture required; not installed application acceptance")
	}
	if os.Geteuid() != 0 {
		t.Fatal("actual root namespace fixture required")
	}
	host, e := strconv.ParseUint(os.Getenv("PANEL_OWNED_HOST_NET_INODE"), 10, 64)
	if e != nil || host == 0 {
		t.Fatal("missing original host namespace identity")
	}
	info, e := os.Stat("/proc/self/ns/net")
	if e != nil || info.Sys().(*syscall.Stat_t).Ino == host {
		t.Fatal("host network is forbidden", e)
	}
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, (24<<10)+1))
	if e != nil || len(raw) > 24<<10 {
		t.Fatal("bounded native snapshot required", e)
	}
	scope := intrusionNftScope{Table: "f2b-table", Chain: "f2b-chain", IPv4Set: "addr-set-probe_sshd", IPv6Set: "addr6-set-probe_sshd", Ports: []int{2882}, Banned: []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("2001:db8::2")}}
	switch os.Getenv("PANEL_OWNED_INTRUSION_NFT_PHASE") {
	case "before":
		plan, e := planIntrusionNftPortChange(raw, scope, []int{2883})
		if e != nil || len(plan.Statements) != 2 || plan.BeforeSHA256 != core.Hash(string(raw)) {
			t.Fatal(plan, e)
		}
		body, e := json.Marshal(plan)
		if e != nil {
			t.Fatal(e)
		}
		t.Log("OWNED_INTRUSION_NFT_PLAN:" + base64.StdEncoding.EncodeToString(body))
	case "after":
		scope.Ports = []int{2883}
		observation, e := inspectIntrusionNftScope(raw, scope)
		if e != nil || !observation.Verified || !observation.IPv4 || !observation.IPv6 || observation.ActiveBans != 2 {
			t.Fatal(observation, e)
		}
		t.Log("OWNED_INTRUSION_NFT_VERIFIED:" + core.Hash(string(raw)))
	default:
		t.Fatal("unknown native phase")
	}
}
