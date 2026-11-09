//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func threatIDSRuntimeUpgradeFixture(t *testing.T) (*Service, threatIDSRuntimeUpgrade) {
	t.Helper()
	s := threatIDSRotationRootFixture(t)
	oldPackage, err := parseThreatAPTMetadata("1:7.0.10-1+deb13u4", "amd64", threatAPTFixture)
	if err != nil {
		t.Fatal(err)
	}
	nextPackage := oldPackage
	nextPackage.Version = "1:8.0.7-1~bpo13+1"
	nextPackage.Filename = "pool/main/s/suricata/suricata_8.0.7-1~bpo13+1_amd64.deb"
	nextPackage.SHA256 = core.Hash("original supported package")
	old := threatIDSRuntime{Format: 1, Prefix: threatIDSPackagePrefix(oldPackage), Platform: "debian-13", Package: oldPackage, Files: map[string]string{"bin/suricata": core.Hash("old native"), "licenses/GPL-2.txt": core.Hash("full GPL"), "licenses/suricata-copyright.txt": core.Hash("old copyright")}}
	next := threatIDSRuntime{Format: 2, Prefix: threatIDSPackagePrefix(nextPackage), Platform: "debian-13", Package: nextPackage, Files: map[string]string{"bin/suricata": core.Hash("supported native"), "licenses/GPL-2.txt": core.Hash("full GPL"), "licenses/suricata-copyright.txt": core.Hash("supported copyright")}, Source: &threatIDSPackageSource{URL: "https://deb.debian.org/debian", Suite: "trixie-backports", KeySHA: core.Hash("key"), CatalogSHA: core.Hash("signed catalog"), MetadataSHA: core.Hash("metadata")}}
	data := func(v threatIDSRuntime) [][]byte {
		unit, e := threatIDSGatedUnit(v.Prefix, "/opt/panel/current/bin/panel-executor")
		if e != nil {
			t.Fatal(e)
		}
		syntax, e := threatIDSSyntaxUnit(v.Prefix)
		if e != nil {
			t.Fatal(e)
		}
		recovery, e := threatIDSRecoveryUnit("/opt/panel/current/bin/panel-executor")
		if e != nil {
			t.Fatal(e)
		}
		record := threatIDSUnitRecord{Format: 1, Prefix: v.Prefix, Guard: "/opt/panel/current/bin/panel-executor", UnitSHA: core.Hash(unit), RecoverySHA: core.Hash(recovery)}
		vJSON, _ := json.Marshal(v)
		rJSON, _ := json.Marshal(record)
		return [][]byte{[]byte(unit), []byte(syntax), []byte(recovery), vJSON, rJSON}
	}
	tx := threatIDSRuntimeUpgrade{Format: 1, ID: core.ID(), State: "applying", CreatedAt: core.Now(), ConfigSHA: core.Hash("configuration"), YAMLSHA: core.Hash("yaml"), AccountSHA: core.Hash("account"), BackupSHA: map[string]string{}}
	before, after := data(old), data(next)
	for i, path := range s.threatIDSRuntimeUpgradePaths() {
		if err := s.wafOwnedDirectory(filepath.Dir(path), true); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0644)
		if i >= 3 {
			mode = 0600
		}
		if err := atomicWrite(path, before[i], mode); err != nil {
			t.Fatal(err)
		}
		b, e := s.threatIDSUpgradeBackup(path)
		if e != nil {
			t.Fatal(e)
		}
		tx.Changes = append(tx.Changes, wafConfigChange{Path: path, OldData: before[i], OldExists: true, OldMode: mode, OldOwner: b.owner, NextData: after[i], NextExists: true, NextMode: mode, NextOwner: b.owner})
		tx.BackupSHA[path] = core.Hash(string(before[i]))
	}
	return s, tx
}

func TestThreatIDSRuntimeUpgradeClosedFiveFileContractAndPrivatePendingGate(t *testing.T) {
	s, tx := threatIDSRuntimeUpgradeFixture(t)
	if _, _, err := s.threatIDSRuntimeUpgradeContract(tx); err != nil {
		t.Fatal(err)
	}
	if err := s.threatIDSUpgradeNoPending(); err != nil {
		t.Fatal(err)
	}
	if err := s.writeThreatIDSRuntimeUpgrade(tx); err != nil {
		t.Fatal(err)
	}
	if err := s.threatIDSUpgradeNoPending(); err == nil {
		t.Fatal("pending runtime migration did not block capture")
	}
	if v := s.observeThreatIDS(context.Background(), threatEVEFilter{}); v.State != "runtime-upgrade-pending" || v.RuntimeReady || v.ProcessVerified || v.Report.Stats != nil {
		t.Fatal("pending migration advertised verified runtime/counters", v)
	}
	if err := s.threatIDSUninstallPreflight(context.Background()); err == nil {
		t.Fatal("pending migration uninstall permitted")
	}
	if _, err := s.readThreatIDSRuntimeUpgrade(); err != nil {
		t.Fatal(err)
	}
	// A signed Core upgrade must still understand a pre-existing interrupted
	// five-file journal from the exact earlier 40s strict-parser generation.
	// This permits preserving/recovering that journal, NOT arbitrary overrides
	// or executing an old check as if it met the current parser policy.
	for _, index := range []int{0, 1, 2} {
		raw, _ := json.Marshal(tx)
		var legacy threatIDSRuntimeUpgrade
		if err := json.Unmarshal(raw, &legacy); err != nil {
			t.Fatal(err)
		}
		if index != 1 {
			legacy.Changes[1].OldData = []byte(strings.Replace(string(legacy.Changes[1].OldData), "TimeoutStartSec=90s\n", "TimeoutStartSec=40s\n", 1))
			legacy.BackupSHA[legacy.Changes[1].Path] = core.Hash(string(legacy.Changes[1].OldData))
		}
		if index != 0 {
			legacy.Changes[1].NextData = []byte(strings.Replace(string(legacy.Changes[1].NextData), "TimeoutStartSec=90s\n", "TimeoutStartSec=40s\n", 1))
		}
		if _, _, err := s.threatIDSRuntimeUpgradeContract(legacy); err != nil {
			t.Fatal("exact known prior interrupted journal became unreadable", index, err)
		}
		legacy.Changes[1].NextData = []byte(strings.Replace(string(legacy.Changes[1].NextData), "TimeoutStartSec=40s\n", "TimeoutStartSec=41s\n", 1))
		if index == 0 {
			legacy.Changes[1].NextData = []byte(strings.Replace(string(legacy.Changes[1].NextData), "TimeoutStartSec=90s\n", "TimeoutStartSec=91s\n", 1))
		}
		if _, _, err := s.threatIDSRuntimeUpgradeContract(legacy); err == nil {
			t.Fatal("arbitrary journal parser policy adopted", index)
		}
	}
	mutations := []func(*threatIDSRuntimeUpgrade){
		func(v *threatIDSRuntimeUpgrade) {
			var r threatIDSRuntime
			_ = json.Unmarshal(v.Changes[3].OldData, &r)
			r.Format = 99
			v.Changes[3].OldData, _ = json.Marshal(r)
			v.BackupSHA[v.Changes[3].Path] = core.Hash(string(v.Changes[3].OldData))
		},
		func(v *threatIDSRuntimeUpgrade) {
			var r threatIDSRuntime
			_ = json.Unmarshal(v.Changes[3].NextData, &r)
			r.Source.URL = "https://unreviewed.invalid"
			v.Changes[3].NextData, _ = json.Marshal(r)
		},
		func(v *threatIDSRuntimeUpgrade) {
			var r threatIDSRuntime
			_ = json.Unmarshal(v.Changes[3].NextData, &r)
			r.Files["bin/suricata"] = ""
			v.Changes[3].NextData, _ = json.Marshal(r)
		},
		func(v *threatIDSRuntimeUpgrade) { v.Format = 2 }, func(v *threatIDSRuntimeUpgrade) { v.ID = "../../other" }, func(v *threatIDSRuntimeUpgrade) { v.State = "unknown" }, func(v *threatIDSRuntimeUpgrade) { v.AccountSHA = "" },
		func(v *threatIDSRuntimeUpgrade) { v.Changes[0].Path = s.systemPath("/etc/nginx/nginx.conf") }, func(v *threatIDSRuntimeUpgrade) { v.Changes[0].NextData = []byte("foreign unit") },
		func(v *threatIDSRuntimeUpgrade) { v.Changes[3].NextMode = 0644 }, func(v *threatIDSRuntimeUpgrade) { v.Changes[3].NextExists = false }, func(v *threatIDSRuntimeUpgrade) { v.Changes[3].OldOwner.UID = 800 },
		func(v *threatIDSRuntimeUpgrade) { v.Changes[3].NextOwner.GID++ }, func(v *threatIDSRuntimeUpgrade) { v.BackupSHA[v.Changes[0].Path] = core.Hash("not original") },
		func(v *threatIDSRuntimeUpgrade) { v.Changes = v.Changes[:4] }, func(v *threatIDSRuntimeUpgrade) { v.Changes[3].NextData = v.Changes[3].OldData },
	}
	for i, change := range mutations {
		raw, _ := json.Marshal(tx)
		var v threatIDSRuntimeUpgrade
		if json.Unmarshal(raw, &v) != nil {
			t.Fatal("fixture cloning")
		}
		change(&v)
		if _, _, err := s.threatIDSRuntimeUpgradeContract(v); err == nil {
			t.Fatal("invalid migration contract accepted", i)
		}
	}
}

func TestThreatIDSRuntimeUpgradeMixedSetRollbackAndForeignEditRefusal(t *testing.T) {
	s, tx := threatIDSRuntimeUpgradeFixture(t)
	if err := s.writeThreatIDSRuntimeUpgrade(tx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := wafApplyChange(tx.Changes[i], true); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.threatIDSValidateUpgradeSet(tx); err != nil {
		t.Fatal("known interrupted mixed set refused", err)
	}
	foreign := tx.Changes[4].Path
	if err := atomicWrite(foreign, []byte("unknown administrator record"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.threatIDSValidateUpgradeSet(tx); err == nil {
		t.Fatal("unknown runtime record accepted")
	}
	actual, _ := os.ReadFile(foreign)
	if string(actual) != "unknown administrator record" {
		t.Fatal("validation overwrote external edit")
	}
	if err := wafApplyChange(tx.Changes[4], false); err != nil {
		t.Fatal(err)
	}
	for _, c := range tx.Changes {
		if err := wafApplyChange(c, false); err != nil {
			t.Fatal(err)
		}
	}
	tx.State = "rolled-back"
	if err := s.finishThreatIDSRuntimeUpgrade(tx); err != nil {
		t.Fatal(err)
	}
	if err := s.threatIDSUpgradeNoPending(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(filepath.Dir(s.threatIDSRuntimeUpgradePath()), tx.ID+"-rolled-back.json")
	b, err := ftpPrivateRead(archive, 128<<10)
	if err != nil || !strings.Contains(string(b), "rolled-back") {
		t.Fatal("complete private rollback backup missing", err)
	}
	for _, c := range tx.Changes {
		same, err := s.threatIDSUpgradeMatches(c, false)
		if err != nil || !same {
			t.Fatal("original file/mode/owner not preserved", c.Path, err)
		}
	}
}

func TestThreatIDSRecoveryRevisionGatePrecedesAllNamespacesAndDispatch(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint("runtime-pending-", pending), func(t *testing.T) {
			s, tx := threatIDSRuntimeUpgradeFixture(t)
			configuration := filepath.Join(s.moduleDir("network-threat-detection"), "ids-config.json")
			data, _ := json.Marshal(threatIDSConfig{Revision: 7, Interface: "lo", HomeNetworks: []string{"127.0.0.1/32", "::1/128"}})
			if err := atomicWrite(configuration, data, 0600); err != nil {
				t.Fatal(err)
			}
			if pending {
				if err := s.writeThreatIDSRuntimeUpgrade(tx); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
				calls++
				if name != "/usr/bin/systemctl" || strings.Join(args, " ") != "start --no-block panel-app-dependencies@network-threat-detection" {
					t.Fatal("recovery widened dispatch authority", name, args)
				}
				return "", nil
			}
			for _, revision := range []int64{-1, 0, 6, 8} {
				result, err := s.moduleThreatIDSControl(context.Background(), "ids-recover", core.AppModuleInput{ExpectedRevision: revision})
				if err == nil || !strings.Contains(err.Error(), "修订冲突") || result != nil || calls != 0 {
					t.Fatal("stale recovery reached a privileged command", revision, result, err, calls)
				}
			}
			actual, err := os.ReadFile(configuration)
			if err != nil || string(actual) != string(data) {
				t.Fatal("stale recovery changed configuration", err)
			}
			if pending {
				original, err := os.ReadFile(s.threatIDSRuntimeUpgradePath())
				if err != nil {
					t.Fatal(err)
				}
				value, err := s.moduleThreatIDSControl(context.Background(), "ids-recover", core.AppModuleInput{ExpectedRevision: 7})
				if err != nil || calls != 1 {
					t.Fatal("reviewed recovery did not dispatch", value, err, calls)
				}
				result := value.(map[string]any)
				if result["state"] != "recovering-runtime" || result["recovered"] != false || result["capture_started"] != false {
					t.Fatal("async dispatch advertised completed recovery or capture", result)
				}
				after, err := os.ReadFile(s.threatIDSRuntimeUpgradePath())
				if err != nil || string(after) != string(original) {
					t.Fatal("API rewrote migration journal", err)
				}
			}
		})
	}
}

func TestThreatIDSRecoveryRefusesMalformedCurrentRevisionBeforeDispatch(t *testing.T) {
	s, tx := threatIDSRuntimeUpgradeFixture(t)
	if err := s.writeThreatIDSRuntimeUpgrade(tx); err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(s.moduleDir("network-threat-detection"), "ids-config.json")
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("malformed current configuration reached root dispatch")
		return "", nil
	}
	for _, data := range []string{
		`null`,
		`{"revision":7,"interface":"lo","home_networks":["127.0.0.1/32"],"Revision":7}`,
		`{"revision":0,"interface":"lo","home_networks":["127.0.0.1/32"]}`,
		`{"revision":7,"interface":"lo","home_networks":null}`,
	} {
		if err := atomicWrite(configuration, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		value, err := s.moduleThreatIDSControl(context.Background(), "ids-recover", core.AppModuleInput{ExpectedRevision: 7})
		if err == nil || value != nil {
			t.Fatal("unknown saved configuration was treated as reviewed", data, value, err)
		}
		actual, err := os.ReadFile(configuration)
		if err != nil || string(actual) != data {
			t.Fatal("recovery repaired untrusted configuration", err)
		}
	}
}

func TestThreatIDSRuntimeUpgradeSameEngineBudgetPreservesExactProvenance(t *testing.T) {
	s, tx := threatIDSRuntimeUpgradeFixture(t)
	for i := range tx.Changes {
		tx.Changes[i].OldData = append([]byte(nil), tx.Changes[i].NextData...)
		tx.BackupSHA[tx.Changes[i].Path] = core.Hash(string(tx.Changes[i].OldData))
	}
	var record threatIDSUnitRecord
	if decodeThreatIDSPrivateJSON(tx.Changes[4].OldData, &record) != nil {
		t.Fatal("fixture record")
	}
	legacy, _ := threatIDSLegacyRecoveryUnit(record.Guard)
	tx.Changes[2].OldData = []byte(legacy)
	record.RecoverySHA = core.Hash(legacy)
	tx.Changes[4].OldData, _ = json.Marshal(record)
	for _, index := range []int{2, 4} {
		tx.BackupSHA[tx.Changes[index].Path] = core.Hash(string(tx.Changes[index].OldData))
	}
	if _, _, err := s.threatIDSRuntimeUpgradeContract(tx); err != nil {
		t.Fatal("exact same-engine bounded recovery migration rejected", err)
	}
	for _, mutation := range []func(*threatIDSRuntimeUpgrade){
		func(v *threatIDSRuntimeUpgrade) { v.Changes[3].NextData = append(v.Changes[3].NextData, '\n') },
		func(v *threatIDSRuntimeUpgrade) {
			v.Changes[2].OldData = []byte(strings.Replace(string(v.Changes[2].OldData), "TimeoutStartSec=60", "TimeoutStartSec=61", 1))
			v.BackupSHA[v.Changes[2].Path] = core.Hash(string(v.Changes[2].OldData))
			var r threatIDSUnitRecord
			_ = json.Unmarshal(v.Changes[4].OldData, &r)
			r.RecoverySHA = core.Hash(string(v.Changes[2].OldData))
			v.Changes[4].OldData, _ = json.Marshal(r)
			v.BackupSHA[v.Changes[4].Path] = core.Hash(string(v.Changes[4].OldData))
		},
		func(v *threatIDSRuntimeUpgrade) {
			v.Changes[2].NextData = v.Changes[2].OldData
			v.Changes[4].NextData = v.Changes[4].OldData
		},
	} {
		raw, _ := json.Marshal(tx)
		var changed threatIDSRuntimeUpgrade
		_ = json.Unmarshal(raw, &changed)
		mutation(&changed)
		if _, _, err := s.threatIDSRuntimeUpgradeContract(changed); err == nil {
			t.Fatal("same-engine migration adopted changed package data, custom recovery or no-op policy")
		}
	}
	// Earlier cross-engine journals used the exact 60s recovery on BOTH sides.
	previousService, previous := threatIDSRuntimeUpgradeFixture(t)
	for _, side := range []bool{false, true} {
		data := previous.Changes[4].OldData
		if side {
			data = previous.Changes[4].NextData
		}
		var r threatIDSUnitRecord
		_ = json.Unmarshal(data, &r)
		oldUnit, _ := threatIDSLegacyRecoveryUnit(r.Guard)
		r.RecoverySHA = core.Hash(oldUnit)
		encoded, _ := json.Marshal(r)
		if side {
			previous.Changes[2].NextData = []byte(oldUnit)
			previous.Changes[4].NextData = encoded
		} else {
			previous.Changes[2].OldData = []byte(oldUnit)
			previous.Changes[4].OldData = encoded
			for _, index := range []int{2, 4} {
				previous.BackupSHA[previous.Changes[index].Path] = core.Hash(string(previous.Changes[index].OldData))
			}
		}
	}
	if _, _, err := previousService.threatIDSRuntimeUpgradeContract(previous); err != nil {
		t.Fatal("pre-existing fixed recovery journal cannot be preserved or recovered", err)
	}
}
