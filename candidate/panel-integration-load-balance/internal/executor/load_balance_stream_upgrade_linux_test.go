//go:build linux

package executor

import (
	"context"
	"strings"
	"testing"
)

func TestLoadBalanceStreamUpgradeNativeUnitCensusNeverUsesPrefixExemption(t *testing.T) {
	a := "panel-lbstream-install@" + strings.Repeat("a", 32) + ".service"
	b := "panel-lbstream-account-create@" + strings.Repeat("a", 32) + ".service"
	c := "panel-lbstream-install@" + strings.Repeat("b", 32) + ".service"
	for _, v := range []struct {
		raw    string
		active map[string]bool
		ok     bool
	}{
		{"", nil, true}, {a + " loaded inactive dead old\n", nil, true},
		{a + " loaded active running own\n", map[string]bool{a: true}, true},
		{a + " loaded active running own\n" + b + " loaded active running own-child\n", map[string]bool{a: true, b: true}, true},
		{a + " loaded active running own\n", nil, false},
		{a + " loaded active running own\n" + c + " loaded active running other\n", map[string]bool{a: true}, false},
		{a + " loaded failed failed own\n", map[string]bool{a: true}, false},
		{a + " loaded activating start own\n", map[string]bool{a: true}, false},
		{a + " loaded active exited own\n", map[string]bool{a: true}, false},
		{a + " loaded inactive dead own\n", map[string]bool{a: true}, false},
		{"", map[string]bool{a: true}, false},
		{a + " loaded active running own\n" + a + " loaded active running duplicate\n", map[string]bool{a: true}, false},
		{strings.Replace(a, "@", "@alias-", 1) + " loaded inactive dead unknown\n", nil, false},
		{a + " not-found inactive dead unknown\n", nil, false},
	} {
		if got := decodeLoadBalanceStreamUpgradeUnits(v.raw, v.active); (got == nil) != v.ok {
			t.Fatal("native current ownership/states not closed", v.raw, got)
		}
	}
	for _, text := range []string{"1 " + a + " start running\n", "1 " + a + " start waiting\n", "1 " + b + " start running\n", "1 panel-lbstream-install@bad.service stop waiting\n", "01 other.service start running\n", "1 other.service start running\n1 other.service start running\n"} {
		if decodeLoadBalanceStreamUpgradeJobs(text) == nil {
			t.Fatal("queued own/other operation or malformed inventory exempted", text)
		}
	}
	if decodeLoadBalanceStreamUpgradeJobs("1 unrelated.service start running\n") != nil {
		t.Fatal("unrelated native job changed the scoped census")
	}
}

func TestLoadBalanceStreamUpgradeFabricatedOwnerHasNoSkipAuthority(t *testing.T) {
	ctx := context.Background()
	for _, owner := range []*loadBalanceStreamUpgradeOwner{nil, {}, {parent: &loadBalanceStreamInstallController{}}, {child: &loadBalanceStreamAccountParent{}}} {
		if owner.current(ctx) == nil {
			t.Fatal("bare owner/parent/child labels became effect authority")
		}
	}
}
