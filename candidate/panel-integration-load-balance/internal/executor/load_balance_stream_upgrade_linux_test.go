//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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

func TestLoadBalanceStreamUpgradeMissingModuleUnderSharedParentIsReadonly(t *testing.T) {
	for _, kind := range []string{"shared-0755", "shared-0700", "present", "writable-parent", "foreign-parent", "linked-parent", "appeared-after-observation"} {
		t.Run(kind, func(t *testing.T) {
			base := programQueueFixture(t)
			parent := filepath.Join(base, "etc/panel/security-apps/modules")
			if err := os.MkdirAll(parent, 0755); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "shared-0700":
				if err := os.Chmod(parent, 0700); err != nil {
					t.Fatal(err)
				}
			case "present":
				if err := os.Mkdir(filepath.Join(parent, "load-balance"), 0755); err != nil {
					t.Fatal(err)
				}
			case "writable-parent":
				if err := os.Chmod(parent, 0777); err != nil {
					t.Fatal(err)
				}
			case "foreign-parent":
				if err := os.Chown(parent, 988, 988); err != nil {
					t.Fatal(err)
				}
			case "linked-parent":
				if err := os.Rename(parent, parent+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+"-original", parent); err != nil {
					t.Fatal(err)
				}
			}
			before := programQueueTree(t, base)
			r := &programQueueReader{ctx: context.Background(), root: base}
			missing, err := streamUpgradeModuleNamespaceMissing(r)
			reject := kind == "writable-parent" || kind == "foreign-parent" || kind == "linked-parent"
			if (err != nil) != reject || !reject && missing != (kind != "present") {
				t.Fatal("missing module observation differs", missing, err)
			}
			if !reflect.DeepEqual(before, programQueueTree(t, base)) {
				t.Fatal("absence observer mutated shared parent or private state")
			}
			if kind == "appeared-after-observation" {
				if err := os.Mkdir(filepath.Join(parent, "load-balance"), 0700); err != nil {
					t.Fatal(err)
				}
				if r.unchanged() == nil {
					t.Fatal("appeared module was silently adopted as original absence")
				}
			} else if !reject && r.unchanged() != nil {
				t.Fatal("stable original observation changed")
			}
		})
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
