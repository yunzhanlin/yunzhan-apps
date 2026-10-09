//go:build linux

package executor

import (
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func threatIDSJournalFixture(t *testing.T) (*Service, []wafConfigChange, *threatIDSRecoveryState) {
	t.Helper()
	root := t.TempDir()
	s := New(Config{SystemRoot: root, SecurityDir: filepath.Join(root, "security"), NginxConf: filepath.Join(root, "nginx.conf")}).threatIDSTransactionService()
	paths := s.threatIDSConfigurationPaths()
	for _, path := range paths {
		if err := s.wafOwnedDirectory(filepath.Dir(path), true); err != nil {
			t.Fatal(err)
		}
	}
	old := threatIDSConfig{Revision: 1, Interface: "lo", HomeNetworks: []string{"127.0.0.1/32"}}
	next := threatIDSConfig{Revision: 2, Interface: "lo", HomeNetworks: []string{"127.0.0.1/32", "::1/128"}}
	oldYAML, err := threatIDSYAML(old, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil {
		t.Fatal(err)
	}
	nextYAML, err := threatIDSYAML(next, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(paths[0], []byte(oldYAML), 0644); err != nil {
		t.Fatal(err)
	}
	if err := moduleWrite(paths[1], old); err != nil {
		t.Fatal(err)
	}
	nextRecord, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	changes := []wafConfigChange{}
	for i, path := range paths {
		b, err := s.threatIDSStableBackup(path)
		if err != nil {
			t.Fatal(err)
		}
		data, mode := []byte(nextYAML), os.FileMode(0644)
		if i == 1 {
			data, mode = nextRecord, 0600
		}
		changes = append(changes, wafConfigChange{Path: path, OldData: b.data, OldExists: b.existed, OldMode: b.mode, OldOwner: b.owner, NextData: data, NextExists: true, NextMode: mode, NextOwner: b.owner})
	}
	owner, err := currentModuleApplyOwner()
	if err != nil {
		t.Fatal(err)
	}
	state := &threatIDSRecoveryState{WasActive: false, WasEnabled: false, UnitSHA: core.Hash("fixed unit"), RuntimeRecordSHA: core.Hash("fixed runtime"), ApplyOwner: owner}
	if err := atomicWrite(s.Config.NginxConf, []byte("unrelated nginx must survive\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return s, changes, state
}

func TestThreatIDSJournalMixedTwoFileRecoveryPreservesOwnerAndOtherApps(t *testing.T) {
	s, plan, state := threatIDSJournalFixture(t)
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	tx, err := s.startWAFTransactionState(plan, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := wafApplyChange(tx.Changes[0], true); err != nil {
		t.Fatal(err)
	}
	restored, err := s.recoverWAFTransaction()
	if err != nil || !restored {
		t.Fatal(restored, err)
	}
	for _, change := range tx.Changes {
		match, err := s.wafCurrentMatches(change, false)
		if err != nil || !match {
			t.Fatal("old bytes/mode/UID/GID not restored", err)
		}
	}
	pending, err := s.readWAFTransaction()
	if err != nil || pending.State != "recovered" || pending.IDS.UnitSHA != state.UnitSHA {
		t.Fatal("recovery evidence disappeared before native check", pending, err)
	}
	if err := s.finishWAFTransaction(pending); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(s.Config.NginxConf); err != nil || string(data) != "unrelated nginx must survive\n" {
		t.Fatal("IDS touched Nginx", err)
	}
	if s.wafPendingPath() == New(s.Config).wafPendingPath() || strings.Contains(s.wafPendingPath(), "waf-transactions") {
		t.Fatal("IDS inherited WAF namespace")
	}
}

func TestThreatIDSJournalExternalChangeRefusesWholeSetWithoutPartialRestore(t *testing.T) {
	s, plan, state := threatIDSJournalFixture(t)
	tx, err := s.startWAFTransactionState(plan, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := wafApplyChange(tx.Changes[0], true); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(tx.Changes[1].Path, []byte("external changed configuration\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if restored, err := s.recoverWAFTransaction(); err == nil || restored {
		t.Fatal("unknown external change was overwritten")
	}
	if err := s.threatIDSValidateRecoverySet(tx); err == nil {
		t.Fatal("start gate accepted private-record external edit")
	}
	match, err := s.wafCurrentMatches(tx.Changes[0], true)
	if err != nil || !match {
		t.Fatal("recovery partially rolled back first file", err)
	}
	if data, err := os.ReadFile(tx.Changes[1].Path); err != nil || string(data) != "external changed configuration\n" {
		t.Fatal("external edits overwritten", err)
	}
	if pending, err := s.readWAFTransaction(); err != nil || pending.State != "applying" {
		t.Fatal("failed recovery evidence lost", err)
	}
}

func TestThreatIDSJournalClosedPathsSemanticsRevisionAndNamespace(t *testing.T) {
	s, plan, state := threatIDSJournalFixture(t)
	tx, err := s.startWAFTransactionState(plan, state)
	if err != nil {
		t.Fatal(err)
	}
	clone := func() wafTransaction {
		data, _ := json.Marshal(tx)
		var v wafTransaction
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, mutate := range []func(*wafTransaction){
		func(v *wafTransaction) { v.Changes[0].Path = s.Config.NginxConf },
		func(v *wafTransaction) { v.IDS = nil },
		func(v *wafTransaction) { v.IDS.ApplyOwner.PID = 1 },
		func(v *wafTransaction) { v.IDS.UnitSHA = "invalid" },
		func(v *wafTransaction) { v.Changes[1].NextMode = 0644 },
		func(v *wafTransaction) { v.Changes[0].NextData = []byte("include: /tmp/unknown.yaml") },
		func(v *wafTransaction) {
			v.Changes[1].NextData = []byte(`{"revision":1,"interface":"lo","home_networks":["127.0.0.1/32"]}`)
		},
		func(v *wafTransaction) {
			v.Changes[1].NextData = []byte(`{"revision":2,"interface":"any","home_networks":["0.0.0.0/0"]}`)
		},
		func(v *wafTransaction) { v.Changes[1].OldExists = false },
		func(v *wafTransaction) { v.Changes[0].OldOwner = nil },
	} {
		bad := clone()
		mutate(&bad)
		if err := s.wafTransactionContract(bad); err == nil {
			t.Fatal("unsafe/incomplete IDS journal accepted")
		}
	}
	if err := New(s.Config).wafTransactionContract(tx); err == nil {
		t.Fatal("Nginx accepted IDS journal")
	}
	if s.wafChangePathAllowed(s.Config.NginxConf) || s.wafChangePathAllowed(filepath.Join(s.moduleDir("network-threat-detection"), "capture-account.json")) {
		t.Fatal("IDS journal path scope widened")
	}
	if _, err := s.startWAFTransaction(plan); err == nil {
		t.Fatal("unbound ordinary journal started as IDS")
	}
}
