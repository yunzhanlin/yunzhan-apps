//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func intrusionJournalFixture(t *testing.T) intrusionJournalPlan {
	t.Helper()
	value, scope := intrusionNftFixture(t)
	intrusionNftOwnRule(value)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = float64(22)
	settings := map[string]any{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}
	manifest, err := intrusionJournalEncode(softwareManifest{ID: "intrusion-prevention", Version: "1.0", Settings: settings, InstalledAt: "2026-10-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	owner := &fileOwner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	p := intrusionJournalPlan{Format: 1, ID: core.ID(), Action: "update", StartedAt: "2026-10-20T00:00:00Z", BootID: "11111111-2222-3333-4444-555555555555", TargetVersion: intrusionTransactionVersion, TargetSettings: map[string]int{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}, TargetPorts: []int{2882}, BeforePolicy: intrusionManagedPolicy{Format: 1, Action: "nftables", Name: "probe_sshd", Table: scope.Table, Chain: scope.Chain, IPv4Set: scope.IPv4Set, IPv6Set: scope.IPv6Set, Ports: []int{22}}, KernelBefore: intrusionNftEncode(t, value), BansBefore: []string{"127.0.0.2"}, Files: []hardeningJournalChange{
		{Name: "jail", Before: hardeningJournalFile{Exists: true, Mode: 0644, Owner: owner, Data: []byte(renderIntrusion(settings))}},
		{Name: "manifest", Before: hardeningJournalFile{Exists: true, Mode: 0600, Owner: owner, Data: manifest}},
		{Name: "policy"},
	}}
	p.KernelState = "rules_observed"
	p.BeforePolicy.MaxMatches = 5
	if err := json.Unmarshal([]byte(intrusionActionRecipeFixture(t, p.BeforePolicy)), &p.ActionBefore); err != nil {
		t.Fatal(err)
	}
	p.ProcessBefore = "123"
	p.ProcessStartBefore = "10000" // Explicit declared model lifetime; not a measured process.
	p.JournalMatchBefore = "_SYSTEMD_UNIT=sshd.service + _COMM=sshd"
	p.EffectiveBefore = strings.Repeat("a", 64) // Pure model token, not a live dump assertion.
	p.ConfigurationBefore = intrusionJournalTreeFixture(p.Files[0].Before)
	p, err = intrusionJournalDerive(p)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Pure model metadata, not an installed-filesystem acceptance assertion.
func intrusionJournalTreeFixture(jail hardeningJournalFile) intrusionConfigurationTree {
	owner := *jail.Owner
	dir := intrusionConfigurationEntry{Kind: "directory", Mode: uint32(os.ModeDir | 0755), UID: owner.UID, GID: owner.GID, Device: 1, Inode: 1}
	child := dir
	child.Inode = 2
	leaf := intrusionConfigurationEntry{Kind: "file", Mode: jail.Mode, UID: owner.UID, GID: owner.GID, Device: 1, Inode: 3, Size: int64(len(jail.Data)), ModifiedNS: 1, ChangedNS: 1, SHA256: core.Hash(string(jail.Data))}
	return intrusionConfigurationTree{Entries: map[string]intrusionConfigurationEntry{".": dir, "jail.d": child, "jail.d/panel-intrusion.local": leaf}, Bytes: leaf.Size}
}

func intrusionJournalClone(t *testing.T, p intrusionJournalPlan) intrusionJournalPlan {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var out intrusionJournalPlan
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIntrusionJournalDerivesClosedMigrationAndKeepsOriginalInstallTime(t *testing.T) {
	p := intrusionJournalFixture(t)
	raw, err := intrusionJournalEncode(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := intrusionJournalDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := intrusionJournalEncode(got)
	if !bytes.Equal(raw, again) {
		t.Fatal("original canonical authority changed")
	}
	if !strings.Contains(string(got.Files[0].After.Data), "port = 2882\nprotocol = tcp\n") {
		t.Fatal("actual SSH scope not derived")
	}
	m, err := intrusionJournalManifest(got.Files[1].After)
	if err != nil || m.InstalledAt != "2026-10-01T00:00:00Z" || m.Version != intrusionTransactionVersion {
		t.Fatal(m, err)
	}
	for i, f := range got.Files {
		if f.After.Mode != []uint32{0644, 0600, 0600}[i] {
			t.Fatal("file mode changed", i)
		}
	}
}

func TestIntrusionJournalDoesNotMutateStoredAfterBeforeComparison(t *testing.T) {
	p := intrusionJournalFixture(t)
	p.Files[0].After.Data = []byte("foreign\n")
	before, _ := intrusionJournalEncode(p)
	if err := intrusionJournalValidate(p); err == nil {
		t.Fatal("forged target accepted")
	}
	after, _ := intrusionJournalEncode(p)
	if !bytes.Equal(before, after) {
		t.Fatal("validation silently repaired original record")
	}
}

func TestIntrusionJournalRefusesUnknownAuthorityOrTamperedDerivedTargets(t *testing.T) {
	for name, mutate := range map[string]func(*intrusionJournalPlan){
		"format":         func(p *intrusionJournalPlan) { p.Format = 2 },
		"job":            func(p *intrusionJournalPlan) { p.ID = "../../other" },
		"action":         func(p *intrusionJournalPlan) { p.Action = "reload --restart sshd" },
		"install":        func(p *intrusionJournalPlan) { p.Action = "install" },
		"remove":         func(p *intrusionJournalPlan) { p.Action = "uninstall" },
		"boot":           func(p *intrusionJournalPlan) { p.BootID = "other" },
		"timestamp":      func(p *intrusionJournalPlan) { p.StartedAt = "2026-10-20T08:00:00+08:00" },
		"target-version": func(p *intrusionJournalPlan) { p.TargetVersion = "1.2.0" },
		"path":           func(p *intrusionJournalPlan) { p.Files[0].Name = "/etc/ssh/sshd_config" },
		"order":          func(p *intrusionJournalPlan) { p.Files[0], p.Files[1] = p.Files[1], p.Files[0] },
		"missing-file":   func(p *intrusionJournalPlan) { p.Files = p.Files[:2] },
		"jail-drift": func(p *intrusionJournalPlan) {
			p.Files[0].Before.Data = append(p.Files[0].Before.Data, []byte("# manual\n")...)
		},
		"unregistered-policy":       func(p *intrusionJournalPlan) { p.Files[2].Before = p.Files[1].Before },
		"foreign-owner":             func(p *intrusionJournalPlan) { p.Files[0].Before.Owner.UID++ },
		"world-writable":            func(p *intrusionJournalPlan) { p.Files[0].Before.Mode = 0666 },
		"public-manifest":           func(p *intrusionJournalPlan) { p.Files[1].Before.Mode = 0644 },
		"missing-jail":              func(p *intrusionJournalPlan) { p.Files[0].Before = hardeningJournalFile{} },
		"wrong-old-port":            func(p *intrusionJournalPlan) { p.BeforePolicy.Ports = []int{2883} },
		"wrong-target-order":        func(p *intrusionJournalPlan) { p.TargetPorts = []int{2883, 22} },
		"service-alias":             func(p *intrusionJournalPlan) { p.BeforePolicy.Action = "iptables-multiport" },
		"option-injection":          func(p *intrusionJournalPlan) { p.BeforePolicy.Table = "--file" },
		"family-collision":          func(p *intrusionJournalPlan) { p.BeforePolicy.IPv6Set = p.BeforePolicy.IPv4Set },
		"changing-limits-in-update": func(p *intrusionJournalPlan) { p.TargetSettings["max_retry"] = 6 },
		"unknown-setting":           func(p *intrusionJournalPlan) { p.TargetSettings["command"] = 5 },
		"implicit-upgrade":          func(p *intrusionJournalPlan) { p.Action = "configure" },
		"kernel-missing":            func(p *intrusionJournalPlan) { p.KernelBefore = nil },
		"stale-ban-list":            func(p *intrusionJournalPlan) { p.BansBefore = []string{} },
		"duplicate-ban":             func(p *intrusionJournalPlan) { p.BansBefore = []string{"127.0.0.2", "127.0.0.2"} },
		"forged-jail":               func(p *intrusionJournalPlan) { p.Files[0].After.Data = []byte("[sshd]\nenabled=false\n") },
		"forged-owner":              func(p *intrusionJournalPlan) { p.Files[1].After.Owner.UID++ },
		"forged-policy":             func(p *intrusionJournalPlan) { p.Files[2].After.Data = []byte("{}\n") },
	} {
		t.Run(name, func(t *testing.T) {
			p := intrusionJournalClone(t, intrusionJournalFixture(t))
			mutate(&p)
			before, _ := intrusionJournalEncode(p)
			if err := intrusionJournalValidate(p); err == nil {
				t.Fatal("untrusted original authority accepted")
			}
			after, _ := intrusionJournalEncode(p)
			if !bytes.Equal(before, after) {
				t.Fatal("repaired rejected record")
			}
		})
	}
}

func TestIntrusionJournalStrictCanonicalDecoderRejectsUnknownDuplicateAndPartialRecords(t *testing.T) {
	p := intrusionJournalFixture(t)
	raw, _ := intrusionJournalEncode(p)
	for name, bad := range map[string][]byte{
		"unknown-root":   bytes.Replace(raw, []byte("{\n"), []byte("{\n  \"command\": \"reboot\",\n"), 1),
		"duplicate":      bytes.Replace(raw, []byte("\"format\": 1"), []byte("\"format\": 1, \"FORMAT\": 1"), 1),
		"unknown-nested": bytes.Replace(raw, []byte("\"action\": \"nftables\""), []byte("\"action\": \"nftables\", \"script\": \"flush ruleset\""), 1),
		"trailing":       append(bytes.Clone(raw), []byte("{}")...),
		"truncated":      raw[:len(raw)/2],
		"noncanonical":   bytes.TrimSpace(raw),
		"capacity":       bytes.Repeat([]byte(" "), intrusionJournalBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := intrusionJournalDecode(bad); err == nil {
				t.Fatal("untrusted record decoded")
			}
		})
	}
}

func TestIntrusionJournalConfigureRequiresExactPreviouslyManagedPolicy(t *testing.T) {
	p := intrusionJournalFixture(t)
	for i := range p.Files {
		p.Files[i].Before = p.Files[i].After
	}
	p.ConfigurationBefore = intrusionJournalTreeFixture(p.Files[0].Before)
	p.BeforePolicy.Ports = []int{2882}
	if err := json.Unmarshal([]byte(intrusionActionRecipeFixture(t, p.BeforePolicy)), &p.ActionBefore); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(p.KernelBefore, &value); err != nil {
		t.Fatal(err)
	}
	intrusionNftOwnRule(value)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = float64(2882)
	p.KernelBefore = intrusionNftEncode(t, value)
	p.Action = "configure"
	p.TargetSettings["max_retry"] = 6
	p.TargetPorts = []int{2882, 2883}
	var err error
	p, err = intrusionJournalDerive(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = intrusionJournalValidate(p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.TargetPorts, []int{2882, 2883}) {
		t.Fatal("target range changed")
	}
	// A policy that is internally well-formed but disagrees with the original
	// private record is not permission to adopt another action or rule handle.
	p.BeforePolicy.Name = "other_jail"
	if err = intrusionJournalValidate(p); err == nil {
		t.Fatal("foreign policy adopted")
	}
}
