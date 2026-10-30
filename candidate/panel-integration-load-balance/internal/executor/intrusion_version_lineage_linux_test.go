//go:build linux

package executor

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
)

// Generated once by the pre-1.1.1 implementation on the owned native ARM
// guest. This is a root-owned test fixture, never an installed transaction.
//
//go:embed testdata/intrusion-plan-v110.json
var intrusionV110PlanFixture []byte

func TestIntrusionV110OriginalCanonicalPlanIsNotUpgradedWhenRead(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("fixed old root-owner canonical fixture; required by native root CI")
	}
	if len(intrusionV110PlanFixture) != 8971 || fmt.Sprintf("%x", sha256.Sum256(intrusionV110PlanFixture)) != "aa043bc10cd8dc42e5337eb87de488f3e1a05748f060847fbee7619f4c4978b4" {
		t.Fatal("immutable old fixture changed")
	}
	p, err := intrusionJournalDecode(intrusionV110PlanFixture)
	if err != nil || p.TargetVersion != "1.1.0" {
		t.Fatal("original110 plan refused or relabeled", err)
	}
	raw, err := intrusionJournalEncode(p)
	if err != nil || !bytes.Equal(raw, intrusionV110PlanFixture) {
		t.Fatal("original110 canonical bytes changed", err)
	}
	manifest, err := intrusionJournalManifest(p.Files[1].After)
	if err != nil || manifest.Version != "1.1.0" {
		t.Fatal("old plan borrowed current target", err)
	}
}

func intrusionManagedV110UpgradeFixture(t *testing.T) intrusionJournalPlan {
	t.Helper()
	p := intrusionJournalFixture(t)
	old, err := intrusionJournalManifest(p.Files[1].Before)
	if err != nil {
		t.Fatal(err)
	}
	old.Version = "1.1.0"
	jail, err := renderIntrusionManagedScope(old.Settings, p.BeforePolicy)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := intrusionJournalEncode(old)
	policy, _ := intrusionJournalEncode(p.BeforePolicy)
	for i, data := range [][]byte{[]byte(jail), manifest, policy} {
		owner := *p.Files[0].Before.Owner
		mode := uint32(0600)
		if i == 0 {
			mode = 0644
		}
		p.Files[i].Before = hardeningJournalFile{Exists: true, Mode: mode, Owner: &owner, Data: data}
	}
	p.ConfigurationBefore = intrusionJournalTreeFixture(p.Files[0].Before)
	p.TargetPorts = slices.Clone(p.BeforePolicy.Ports)
	p, err = intrusionJournalDerive(p)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIntrusionV110ToV111UpgradeKeepsPolicyLimitsAndInstallTime(t *testing.T) {
	p := intrusionManagedV110UpgradeFixture(t)
	old, _ := intrusionJournalManifest(p.Files[1].Before)
	after, err := intrusionJournalManifest(p.Files[1].After)
	if err != nil || p.TargetVersion != "1.1.1" || after.Version != "1.1.1" || old.Version != "1.1.0" || old.InstalledAt != after.InstalledAt || !reflect.DeepEqual(old.Settings, after.Settings) {
		t.Fatal("upgrade changed original limits/time or failed version binding", err)
	}
	for _, i := range []int{0, 2} {
		if !reflect.DeepEqual(p.Files[i].Before, p.Files[i].After) {
			t.Fatal("same-scope package upgrade changed Jail or policy", i)
		}
	}
	for _, scenario := range []string{"configure-before-update", "unknown-target", "missing-old-policy", "old-policy-drift", "downgrade"} {
		t.Run(scenario, func(t *testing.T) {
			bad := intrusionJournalClone(t, p)
			switch scenario {
			case "configure-before-update":
				bad.Action = "configure"
			case "unknown-target":
				bad.TargetVersion = "1.1.2"
			case "missing-old-policy":
				bad.Files[2].Before = hardeningJournalFile{}
			case "old-policy-drift":
				bad.Files[2].Before.Data = append(bad.Files[2].Before.Data, ' ')
			case "downgrade":
				newer := after
				bad.Files[1].Before.Data, _ = intrusionJournalEncode(newer)
				bad.TargetVersion = "1.1.0"
			}
			if _, err := intrusionJournalDerive(bad); err == nil {
				t.Fatal("unsafe version transition accepted")
			}
		})
	}
	// An already prepared old configure plan keeps its old exact target.
	p.Action, p.TargetVersion = "configure", "1.1.0"
	p, err = intrusionJournalDerive(p)
	if err != nil {
		t.Fatal("old configure recovery projection rejected", err)
	}
	manifest, err := intrusionJournalManifest(p.Files[1].After)
	if err != nil || manifest.Version != "1.1.0" {
		t.Fatal("old configure plan implicitly upgraded", err)
	}
}
