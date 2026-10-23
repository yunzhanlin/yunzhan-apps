//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func wafBodyPlanFixture(t *testing.T) (*Service, core.WAFConfig, string) {
	t.Helper()
	s := wafPolicyFixture(t)
	id := core.ID()
	path := filepath.Join(s.Config.ConfDir, id+".conf")
	data := "# managed by panel; site=" + id + "\nserver {\n  listen 19101;\n}\n"
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := core.DefaultWAFConfig()
	cfg.Body = &core.WAFBodyConfig{EngineJobID: strings.Repeat("c", 32), Sites: []core.WAFBodySitePolicy{{SiteID: id, Policy: core.DefaultWAFBodyPolicy()}}}
	return s, cfg, id
}

func TestWAFBodyPlanNoWriteEnableDisableAndConflicts(t *testing.T) {
	s, cfg, id := wafBodyPlanFixture(t)
	main, _ := os.ReadFile(s.Config.NginxConf)
	plan, err := s.planWAFConfiguration(cfg, false)
	if err != nil || len(plan) < 6 {
		t.Fatal("body plan missing owned files", len(plan), err)
	}
	got, _ := os.ReadFile(s.Config.NginxConf)
	if string(got) != string(main) {
		t.Fatal("planning changed active configuration")
	}
	if plan[len(plan)-1].Path != s.softwareManifestPath("nginx-waf") {
		t.Fatal("manifest must be the last committed change")
	}
	tx, err := s.startWAFTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range plan {
		if err := wafApplyChange(c, true); err != nil {
			t.Fatal(err)
		}
	}
	tx.State = "committed"
	if err := s.finishWAFTransaction(tx); err != nil {
		t.Fatal(err)
	}
	manifest, _ := s.readSoftwareManifest("nginx-waf")
	current, _ := core.DecodeWAFConfig(manifest.Settings)
	if repeat, err := s.planWAFConfiguration(current, false); err != nil || len(repeat) != 0 {
		t.Fatal("deployed body files do not match manifest", len(repeat), err)
	}
	rulesPath := s.systemPath("/etc/panel/waf/body.d/" + id + ".conf")
	rules, _ := os.ReadFile(rulesPath)
	if err := os.WriteFile(rulesPath, append(rules, []byte("# manual edit\n")...), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.planWAFConfiguration(current, false); err == nil {
		t.Fatal("manually edited rules overwritten")
	}
	os.WriteFile(rulesPath, rules, 0640)
	current.Policy.Mode = "off"
	off, err := s.planWAFConfiguration(current, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range off {
		if c.Path == rulesPath && c.NextExists {
			t.Fatal("global off retained active body rule file")
		}
		if c.Path == s.Config.NginxConf && strings.Contains(string(c.NextData), "load_module ") {
			t.Fatal("global off retained loader")
		}
		if c.Path == filepath.Join(s.Config.ConfDir, id+".conf") && strings.Contains(string(c.NextData), wafBodySiteBegin) {
			t.Fatal("global off retained site protection directives")
		}
	}
}

func TestWAFBodyStoppedAndOptedOutSitesRetainPolicyWithoutActivation(t *testing.T) {
	for _, header := range []string{"; disabled", "; panel-waf-disabled"} {
		s, cfg, id := wafBodyPlanFixture(t)
		content := "# managed by panel; site=" + id + header + "\n"
		if header != "; disabled" {
			content += "server {\n listen 19101;\n}\n"
		}
		if err := os.WriteFile(filepath.Join(s.Config.ConfDir, id+".conf"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		plan, err := s.planWAFConfiguration(cfg, false)
		if err != nil {
			t.Fatal("paused site blocked WAF configuration", err)
		}
		foundRule := false
		for _, change := range plan {
			if change.Path == filepath.Join(s.Config.ConfDir, id+".conf") && strings.Contains(string(change.NextData), wafBodySiteBegin) {
				t.Fatal("paused site activated")
			}
			if change.Path == s.systemPath("/etc/panel/waf/body.d/"+id+".conf") && change.NextExists {
				foundRule = true
			}
		}
		if !foundRule {
			t.Fatal("saved policy unavailable for deliberate website re-enable")
		}
	}
}

func TestWAFPendingBlocksEveryWebsiteMutationBeforeAnyWrite(t *testing.T) {
	s, cfg, _ := wafBodyPlanFixture(t)
	plan, err := s.planWAFConfiguration(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.startWAFTransaction(plan); err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		site := core.Site{ID: core.ID(), Name: "new", Slug: "new-site", Domain: "waf-pending.localhost"}
		if _, err := s.Apply(context.Background(), core.ApplyRequest{Site: site, JobID: core.ID(), Enabled: enabled}); err == nil || !strings.Contains(err.Error(), "防火墙") {
			t.Fatal("pending WAF did not block early", enabled, err)
		}
		if _, err := os.Stat(filepath.Join(s.Config.SitesDir, site.ID)); !os.IsNotExist(err) {
			t.Fatal("site files created before pending recovery guard")
		}
	}
}

func TestWAFTransactionEveryInterruptionRestoresExactBytes(t *testing.T) {
	for cut := 0; cut <= 7; cut++ {
		t.Run(string(rune('A'+cut)), func(t *testing.T) {
			s, cfg, _ := wafBodyPlanFixture(t)
			plan, err := s.planWAFConfiguration(cfg, false)
			if err != nil || len(plan) != 7 {
				t.Fatal("unexpected fixture size", len(plan), err)
			}
			_, err = s.startWAFTransaction(plan)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range plan[:cut] {
				if err := wafApplyChange(c, true); err != nil {
					t.Fatal(err)
				}
			}
			// A fresh Service reads only durable state, not the interrupted
			// process's stack or in-memory fileBackup objects.
			fresh := New(s.Config)
			changed, err := fresh.recoverWAFTransaction()
			if err != nil || !changed {
				t.Fatal("durable recovery failed", cut, err)
			}
			for _, c := range plan {
				match, err := fresh.wafCurrentMatches(c, false)
				if err != nil || !match {
					t.Fatal("exact original content/mode/existence not restored", c.Path, err)
				}
			}
			if again, err := fresh.recoverWAFTransaction(); err != nil || again {
				t.Fatal("recovery not idempotent", err)
			}
		})
	}
}

func TestWAFTransactionRefusesExternalEditBeforeAnyRestore(t *testing.T) {
	s, cfg, _ := wafBodyPlanFixture(t)
	plan, _ := s.planWAFConfiguration(cfg, false)
	_, err := s.startWAFTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range plan[:2] {
		if err := wafApplyChange(c, true); err != nil {
			t.Fatal(err)
		}
	}
	c := plan[1]
	if err := os.WriteFile(c.Path, []byte("# own QA external change\n"), c.NextMode); err != nil {
		t.Fatal(err)
	}
	if _, err := s.recoverWAFTransaction(); err == nil {
		t.Fatal("external modification overwritten")
	}
	if match, _ := s.wafCurrentMatches(plan[0], true); !match {
		t.Fatal("partial rollback happened before all conflicts checked")
	}
	if _, err := os.Stat(s.wafPendingPath()); err != nil {
		t.Fatal("unresolved recovery evidence lost")
	}
	if err := wafApplyChange(c, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.recoverWAFTransaction(); err != nil {
		t.Fatal("explicit reinstatement did not permit safe recovery", err)
	}
}

func TestWAFTransactionDamagedBackupAndForeignPathsFailClosed(t *testing.T) {
	s, cfg, _ := wafBodyPlanFixture(t)
	plan, _ := s.planWAFConfiguration(cfg, false)
	tx, err := s.startWAFTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	tx.Changes[0].OldData = []byte("corrupt private backup")
	if err := wafWriteTransaction(s.wafPendingPath(), tx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.recoverWAFTransaction(); err == nil {
		t.Fatal("corrupt backup digest accepted")
	}
	tx.Changes[0].OldData = plan[0].OldData
	tx.Changes[0].Path = "/etc/passwd"
	if err := s.wafTransactionContract(tx); err == nil {
		t.Fatal("foreign system path admitted")
	}
	data, _ := json.Marshal(tx)
	if len(data) == 0 {
		t.Fatal("fixture is empty")
	}
}
