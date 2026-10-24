//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"testing"

	"local/panel/internal/core"
)

func hardeningJournalFixturePlan(t *testing.T, from, to string) (*hardeningFixture, hardeningJournalPlan) {
	t.Helper()
	f := newHardeningFixture(t)
	action := "install"
	if from != "" {
		if err := f.apply(from, true); err != nil {
			t.Fatal(err)
		}
		action = "configure"
	}
	if to == "" {
		action = "uninstall"
	}
	config, err := f.s.hardeningConfigBackups()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := f.s.hardeningManifestBackup()
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	if from != "" {
		maps.Copy(keys, hardeningValues(from))
	}
	if to != "" {
		maps.Copy(keys, hardeningValues(to))
	}
	before := map[string]string{}
	for key := range keys {
		before[key] = f.values[key]
	}
	p := hardeningJournalPlan{Format: 1, ID: core.ID(), Action: action, StartedAt: core.Now(), BootID: "11111111-2222-3333-4444-555555555555", ToProfile: to, BeforeKernel: before, Files: []hardeningJournalChange{{Name: "current", Before: hardeningJournalFromBackup(config[0])}, {Name: "legacy", Before: hardeningJournalFromBackup(config[1])}, {Name: "manifest", Before: hardeningJournalFromBackup(manifest)}}}
	p.TargetVersion = core.HardeningAppVersion
	p, err = hardeningJournalDerive(p)
	if err != nil {
		t.Fatal(err)
	}
	return f, p
}

func hardeningJournalClone(t *testing.T, p hardeningJournalPlan) hardeningJournalPlan {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var result hardeningJournalPlan
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestHardeningJournalClosedPlansDeriveActualCapturedProfileTransitions(t *testing.T) {
	for _, pair := range [][2]string{{"", "baseline"}, {"", "strict"}, {"baseline", "strict"}, {"strict", "baseline"}, {"strict", ""}, {"baseline", ""}} {
		t.Run(pair[0]+"-to-"+pair[1], func(t *testing.T) {
			_, p := hardeningJournalFixturePlan(t, pair[0], pair[1])
			raw, err := hardeningJournalEncode(p)
			if err != nil {
				t.Fatal(err)
			}
			got, err := hardeningJournalDecode(raw)
			if err != nil {
				t.Fatal(err)
			}
			again, _ := hardeningJournalEncode(got)
			if !bytes.Equal(raw, again) {
				t.Fatal("canonical plan changed")
			}
			if got.FromProfile != pair[0] || got.ToProfile != pair[1] {
				t.Fatal("profile identity lost")
			}
			if pair[1] == "strict" && got.AfterKernel["kernel.unprivileged_bpf_disabled"] != "2" {
				t.Fatal("journal authorizes irreversible BPF")
			}
			if pair[1] == "" {
				for _, f := range got.Files {
					if f.After.Exists {
						t.Fatal("removal retains guessed target file")
					}
				}
			}
		})
	}
}

func TestHardeningJournalTamperCannotChoosePathsKeysTargetsOrRewriteAuthority(t *testing.T) {
	_, original := hardeningJournalFixturePlan(t, "baseline", "strict")
	cases := map[string]func(*hardeningJournalPlan){
		"foreign-file":        func(p *hardeningJournalPlan) { p.Files[0].Name = "../../etc/passwd" },
		"extra-kernel-key":    func(p *hardeningJournalPlan) { p.BeforeKernel["kernel.modules_disabled"] = "0" },
		"missing-before":      func(p *hardeningJournalPlan) { delete(p.BeforeKernel, "kernel.kptr_restrict") },
		"target-map":          func(p *hardeningJournalPlan) { p.AfterKernel["kernel.kptr_restrict"] = "0" },
		"target-config":       func(p *hardeningJournalPlan) { p.Files[0].After.Data = []byte("kernel.modules_disabled = 1\n") },
		"target-manifest":     func(p *hardeningJournalPlan) { p.Files[2].After.Data = []byte("{}\n") },
		"target-mode":         func(p *hardeningJournalPlan) { p.Files[0].After.Mode = 0666 },
		"target-owner":        func(p *hardeningJournalPlan) { p.Files[0].After.Owner.UID = uint32(os.Geteuid() + 1) },
		"before-owner":        func(p *hardeningJournalPlan) { p.Files[0].Before.Owner.UID = uint32(os.Geteuid() + 1) },
		"before-public-write": func(p *hardeningJournalPlan) { p.Files[0].Before.Mode = 0666 },
		"unknown-action":      func(p *hardeningJournalPlan) { p.Action = "run-script" },
		"wrong-from":          func(p *hardeningJournalPlan) { p.FromProfile = "strict" },
		"future-format":       func(p *hardeningJournalPlan) { p.Format = 2 },
		"permanent-latch":     func(p *hardeningJournalPlan) { p.BeforeKernel["kernel.unprivileged_bpf_disabled"] = "1" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := hardeningJournalClone(t, original)
			change(&p)
			raw, _ := hardeningJournalEncode(p)
			if err := hardeningJournalValidate(p); err == nil {
				t.Fatal("tampered plan accepted")
			}
			after, _ := hardeningJournalEncode(p)
			if !bytes.Equal(raw, after) {
				t.Fatal("validator rewrote original authority")
			}
		})
	}
}

func TestHardeningJournalTerminalCannotInventSuccessOrLoseOriginalPlanDigest(t *testing.T) {
	_, p := hardeningJournalFixturePlan(t, "", "baseline")
	raw, err := hardeningJournalEncode(p)
	if err != nil {
		t.Fatal(err)
	}
	r := hardeningJournalTerminal{Format: 1, State: "committed", PlanSHA256: hardeningJournalDigest(raw), Plan: p, FinishedAt: core.Now()}
	encoded, err := hardeningJournalEncode(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = hardeningJournalTerminalDecode(encoded, p.ID); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"pending", "succeeded", "unknown"} {
		bad := r
		bad.State = state
		b, _ := hardeningJournalEncode(bad)
		if _, err = hardeningJournalTerminalDecode(b, p.ID); err == nil {
			t.Fatal("nonclosed state accepted", state)
		}
	}
	bad := r
	bad.PlanSHA256 = core.Hash("foreign")
	b, _ := hardeningJournalEncode(bad)
	if _, err = hardeningJournalTerminalDecode(b, p.ID); err == nil {
		t.Fatal("foreign plan digest accepted")
	}
	if _, err = hardeningJournalTerminalDecode(encoded, core.ID()); err == nil {
		t.Fatal("foreign original job identity accepted")
	}
	if _, err = hardeningJournalDecode(append(raw, []byte("{}")...)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}

func TestHardeningJournalDecoderHasIndependentClosedGrammarWithoutChangingApache(t *testing.T) {
	_, plan := hardeningJournalFixturePlan(t, "", "baseline")
	raw, err := hardeningJournalEncode(plan)
	if err != nil {
		t.Fatal(err)
	}
	var old hardeningJournalPlan
	if err = decodeApacheWAFPrivateJSON(raw, &old, map[string]bool{"format": true, "id": true, "action": true, "started_at": true, "boot_id": true, "from_profile": true, "to_profile": true, "before_kernel": true, "after_kernel": true, "files": true}, 100000); err == nil {
		t.Fatal("Apache-specific format grammar unexpectedly accepted a foreign journal")
	}
	if _, err = hardeningJournalDecode(raw); err != nil {
		t.Fatal("independent exact journal did not round-trip", err)
	}
	for name, bad := range map[string][]byte{"duplicate": bytes.Replace(raw, []byte(`"format": 1`), []byte(`"format": 1,"format": 1`), 1), "unknown": bytes.Replace(raw, []byte(`"format": 1`), []byte(`"format": 1,"script": "not allowed"`), 1), "casefold": bytes.Replace(raw, []byte(`"format": 1`), []byte(`"Format": 1`), 1)} {
		t.Run(name, func(t *testing.T) {
			if _, err = hardeningJournalDecode(bad); err == nil {
				t.Fatal("foreign journal accepted")
			}
		})
	}
}
