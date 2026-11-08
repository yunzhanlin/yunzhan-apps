//go:build linux

package executor

import (
	"context"
	"maps"
	"testing"

	"local/panel/internal/core"
)

func TestHardeningOrdinaryConfigurationPreservesLegacyVersionUntilGenuineUpdate(t *testing.T) {
	f := newHardeningFixture(t)
	if err := f.apply("baseline", true); err != nil {
		t.Fatal(err)
	}
	m, err := f.s.readSoftwareManifest("system-hardening")
	if err != nil {
		t.Fatal(err)
	}
	m.Version = "1.0-compat1"
	installed := m.InstalledAt
	originals := maps.Clone(m.Previous)
	if err = f.s.writeSoftwareManifest(m); err != nil {
		t.Fatal(err)
	}
	if err = f.apply("baseline", false); err != nil {
		t.Fatal(err)
	}
	m, err = f.s.readSoftwareManifest("system-hardening")
	if err != nil || m.Version != "1.0-compat1" || !maps.Equal(originals, m.Previous) {
		t.Fatal("configure silently promoted capability", m, err)
	}
	job := core.ID()
	ctx := context.WithValue(context.Background(), hardeningJobContextKey{}, job)
	if err = f.s.updateSoftware(ctx, "system-hardening", core.HardeningAppVersion, func(string) {}); err != nil {
		t.Fatal(err)
	}
	m, err = f.s.readSoftwareManifest("system-hardening")
	if err != nil || m.Version != core.HardeningAppVersion || m.InstalledAt != installed || m.Settings["profile"] != "baseline" || !maps.Equal(originals, m.Previous) {
		t.Fatal("update lost original authority", m, err)
	}
	inv, err := f.s.hardeningJournalInventoryRead()
	terminal := inv.Records[job]
	if err != nil || terminal.State != "committed" || terminal.Plan.Action != "update" || terminal.Plan.TargetVersion != core.HardeningAppVersion {
		t.Fatal("update merely relabeled metadata", terminal, err)
	}
	writes := f.writes
	if err = f.s.updateSoftware(ctx, "system-hardening", core.HardeningAppVersion, func(string) {}); err != nil || f.writes != writes {
		t.Fatal("original update replayed", err)
	}
}

func TestHardeningVersionUpdateRefusesUnverifiedOriginalsDriftOrAlias(t *testing.T) {
	for _, mode := range []string{"originals", "drift", "alias"} {
		t.Run(mode, func(t *testing.T) {
			f := newHardeningFixture(t)
			if err := f.apply("baseline", true); err != nil {
				t.Fatal(err)
			}
			m, err := f.s.readSoftwareManifest("system-hardening")
			if err != nil {
				t.Fatal(err)
			}
			m.Version = "1.0"
			if mode == "originals" {
				delete(m.Previous, "kernel.dmesg_restrict")
			}
			if err = f.s.writeSoftwareManifest(m); err != nil {
				t.Fatal(err)
			}
			if mode == "drift" {
				f.values["kernel.dmesg_restrict"] = "0"
			}
			version := core.HardeningAppVersion
			if mode == "alias" {
				version += "-unreviewed"
			}
			before := hardeningGuardTree(t, f.s.Config.SystemRoot)
			values := maps.Clone(f.values)
			writes := f.writes
			if err = f.s.updateSoftware(context.Background(), "system-hardening", version, func(string) {}); err == nil {
				t.Fatal("unverified migration accepted")
			}
			if f.writes != writes || !maps.Equal(values, f.values) {
				t.Fatal("refusal changed kernel")
			}
			after := hardeningGuardTree(t, f.s.Config.SystemRoot)
			if len(before) != len(after) {
				t.Fatal("refusal created or deleted files")
			}
			for name, v := range before {
				if after[name] != v {
					t.Fatal("refusal changed files", name)
				}
			}
		})
	}
}

func TestHardeningJournalLegacyVersionAuthorityRemainsStableAndCannotDowngradeNewInstall(t *testing.T) {
	_, plan := hardeningJournalFixturePlan(t, "", "baseline")
	plan.TargetVersion = ""
	legacy, err := hardeningJournalDerive(plan)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hardeningJournalEncode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := hardeningJournalDecode(raw)
	if err != nil {
		t.Fatal("original format-1 grammar reinterpreted", err)
	}
	manifest, err := hardeningJournalManifest(decoded.Files[2].After)
	if err != nil || manifest.Version != "1.0" {
		t.Fatal(manifest, err)
	}
	_, current := hardeningJournalFixturePlan(t, "baseline", "strict")
	current.TargetVersion = ""
	if _, err = hardeningJournalDerive(current); err == nil {
		t.Fatal("legacy grammar downgraded newer installed authority")
	}
}
