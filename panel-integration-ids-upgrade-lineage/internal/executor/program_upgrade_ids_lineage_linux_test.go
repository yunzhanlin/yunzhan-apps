//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func idsLineageTestStep(t *testing.T, root string, old, next threatIDSConfig, input core.NetworkIDSOperationInput, action, begin, at, end string) (threatIDSOperationRecord, wafTransaction) {
	t.Helper()
	s := &Service{Config: Config{SystemRoot: root, SecurityDir: filepath.Join(root, "etc/panel/security-apps")}, fileTransactionApplication: "network-ids"}
	paths := s.threatIDSConfigurationPaths()
	before, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	oldYAML, err := threatIDSYAML(old, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil {
		t.Fatal(err)
	}
	newYAML, err := threatIDSYAML(next, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil {
		t.Fatal(err)
	}
	owner := &fileOwner{UID: 0, GID: 0}
	tx := wafTransaction{Format: 2, ID: core.ID(), State: "committed", CreatedAt: at, IDS: &threatIDSRecoveryState{UnitSHA: core.Hash("unit"), RuntimeRecordSHA: core.Hash("runtime"), ApplyOwner: &moduleApplyOwner{PID: 2, StartTime: 3}},
		Changes: []wafConfigChange{
			{Path: paths[0], OldExists: true, NextExists: true, OldData: []byte(oldYAML), NextData: []byte(newYAML), OldMode: 0644, NextMode: 0644, OldOwner: owner, NextOwner: owner},
			{Path: paths[1], OldExists: true, NextExists: true, OldData: before, NextData: after, OldMode: 0600, NextMode: 0600, OldOwner: owner, NextOwner: owner},
		},
		Digests: map[string]string{
			paths[0] + ":old": core.Hash(oldYAML), paths[0] + ":next": core.Hash(newYAML),
			paths[1] + ":old": core.Hash(string(before)), paths[1] + ":next": core.Hash(string(after)),
		},
	}
	if err := s.wafTransactionContract(tx); err != nil {
		t.Fatal(err)
	}
	o := threatIDSOperationRecord{Format: 1, Operation: core.NetworkIDSOperation{ID: core.ID(), Action: action, Input: input, State: "succeeded", CreatedAt: begin, UpdatedAt: end}}
	if err := validateThreatIDSOperation(o); err != nil {
		t.Fatal(err)
	}
	return o, tx
}

func idsLineageTestFixture(t *testing.T, root, action string) ([]threatIDSOperationRecord, []wafTransaction, time.Time) {
	t.Helper()
	records, now := programQueueIDSRecoveryFixture()
	old := threatIDSConfig{Revision: 2, Interface: "lo", HomeNetworks: []string{"192.0.2.0/30"}, CaptureFormat: 1, CaptureMTU: 1500}
	next := old
	next.Revision = 3
	input := core.NetworkIDSOperationInput{ExpectedRevision: 2}
	if action == "ids-config" {
		next.HomeNetworks = []string{"198.51.100.0/24"}
		input.Interface, input.HomeNetworks = next.Interface, append([]string{}, next.HomeNetworks...)
	} else {
		selection := &core.NetworkIDSRuleFeedSelection{FeedID: "et-open-web-20261021", AppVersion: "1.3.1", AppManifestSHA: core.Hash("application"), RuleManifestSHA: core.Hash("rules")}
		next.RuleFeed = selection
		input.RuleProfile = &core.NetworkIDSRuleProfileSelection{Source: "verified-feed", Selection: selection}
	}
	o, tx := idsLineageTestStep(t, root, old, next, input, action, "2026-10-21T20:00:04Z", "2026-10-21T20:00:05Z", "2026-10-21T20:00:06Z")
	return append(records, o), []wafTransaction{tx}, now.Add(10 * time.Second)
}

func TestProgramUpgradeIDSRecoveryLineageRequiresExactCommittedActionAndOriginalAnchor(t *testing.T) {
	for _, scenario := range []string{"valid-config", "valid-rules", "same-second-boundary", "no-recovery", "missing-transaction", "missing-action", "failed-action", "wrong-revision", "wrong-input", "wrong-rules", "recovered-not-committed", "missing-byte", "future-transaction", "outside-action", "duplicate-transaction", "ambiguous-action", "duplicate-operation"} {
		t.Run(scenario, func(t *testing.T) {
			action := "ids-config"
			if scenario == "valid-rules" || scenario == "wrong-rules" {
				action = "ids-rules"
			}
			records, transactions, now := idsLineageTestFixture(t, t.TempDir(), action)
			switch scenario {
			case "same-second-boundary":
				records[2].Operation.CreatedAt = records[1].Operation.UpdatedAt
				transactions[0].CreatedAt = records[1].Operation.UpdatedAt
			case "no-recovery":
				records = append(records[:1], records[2])
			case "missing-transaction":
				transactions = nil
			case "missing-action":
				records = records[:2]
			case "failed-action":
				records[2].Operation.State, records[2].Operation.Error = "failed", "not committed"
			case "wrong-revision":
				records[2].Operation.Input.ExpectedRevision = 3
			case "wrong-input":
				records[2].Operation.Input.HomeNetworks = []string{"203.0.113.0/24"}
			case "wrong-rules":
				selection := *records[2].Operation.Input.RuleProfile.Selection
				selection.RuleManifestSHA = core.Hash("other rules")
				records[2].Operation.Input.RuleProfile = &core.NetworkIDSRuleProfileSelection{Source: "verified-feed", Selection: &selection}
			case "recovered-not-committed":
				transactions[0].State = "recovered"
			case "missing-byte":
				transactions[0].Changes[1].NextData = nil
			case "future-transaction":
				transactions[0].CreatedAt = now.Add(time.Second).Format(time.RFC3339Nano)
			case "outside-action":
				transactions[0].CreatedAt = "2026-10-21T20:00:07Z"
			case "duplicate-transaction":
				tx := transactions[0]
				tx.ID = core.ID()
				transactions = append(transactions, tx)
			case "ambiguous-action":
				other := records[2]
				other.Operation.ID = core.ID()
				records = append(records, other)
			case "duplicate-operation":
				records = append(records, records[2])
			}
			before, _ := json.Marshal([]any{records, transactions})
			tip, err := programQueueIDSRecoveryLineage(records, transactions, now)
			valid := strings.HasPrefix(scenario, "valid-") || scenario == "same-second-boundary"
			if (err == nil) != valid || valid && (tip == nil || tip.revision != 3 || !reflect.DeepEqual(tip.config, transactions[0].Changes[1].NextData)) {
				t.Fatal(tip, err)
			}
			after, _ := json.Marshal([]any{records, transactions})
			if string(before) != string(after) {
				t.Fatal("lineage reader changed original inputs")
			}
		})
	}
}

func TestProgramUpgradeIDSRecoveryLineagePreservesOriginalNoTransitionAndRejectsBrokenHops(t *testing.T) {
	for _, scenario := range []string{"unchanged", "two-hops", "gap", "intermediate-bytes", "intermediate-owner", "time-inversion"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			records, transactions, now := idsLineageTestFixture(t, root, "ids-config")
			if scenario == "unchanged" {
				records, transactions = records[:2], nil
			} else {
				var old threatIDSConfig
				if err := json.Unmarshal(transactions[0].Changes[1].NextData, &old); err != nil {
					t.Fatal(err)
				}
				if scenario == "intermediate-bytes" {
					old.HomeNetworks = []string{"203.0.113.0/24"}
				}
				next := old
				next.Revision++
				next.HomeNetworks = []string{"203.0.113.128/25"}
				in := core.NetworkIDSOperationInput{ExpectedRevision: 3, Interface: "lo", HomeNetworks: append([]string{}, next.HomeNetworks...)}
				o, tx := idsLineageTestStep(t, root, old, next, in, "ids-config", "2026-10-21T20:00:07Z", "2026-10-21T20:00:08Z", "2026-10-21T20:00:09Z")
				if scenario == "intermediate-owner" {
					tx.Changes[1].OldOwner = &fileOwner{UID: 0, GID: 1}
				}
				if scenario == "time-inversion" {
					o.Operation.CreatedAt, o.Operation.UpdatedAt = "2026-10-21T20:00:04Z", "2026-10-21T20:00:05Z"
					tx.CreatedAt = "2026-10-21T20:00:04Z"
				}
				records, transactions = append(records, o), append(transactions, tx)
				if scenario == "gap" {
					records = append(records[:2], records[3])
					transactions = transactions[1:]
				}
			}
			tip, err := programQueueIDSRecoveryLineage(records, transactions, now)
			switch scenario {
			case "unchanged":
				if err != nil || tip != nil {
					t.Fatal(tip, err)
				}
			case "two-hops":
				if err != nil || tip == nil || tip.revision != 4 {
					t.Fatal(tip, err)
				}
			default:
				if err == nil {
					t.Fatal("incomplete, modified or out-of-order lineage accepted")
				}
			}
		})
	}
}

func TestProgramUpgradeIDSRecoveryLineageCurrentBytesAndRacesAreReadonly(t *testing.T) {
	for _, scenario := range []string{"valid-config", "valid-rules", "config-bytes", "yaml-bytes", "config-mode", "yaml-mode", "config-link", "yaml-hardlink", "foreign-transaction-path", "race-config", "race-yaml", "race-transaction", "scope-failure", "nil-lease"} {
		t.Run(scenario, func(t *testing.T) {
			root := programQueueFixture(t)
			action := "ids-config"
			if scenario == "valid-rules" {
				action = "ids-rules"
			}
			records, transactions, _ := idsLineageTestFixture(t, root, action)
			tx := transactions[0]
			directory := "etc/panel/security-apps/modules/network-threat-detection/config-transactions"
			if scenario == "foreign-transaction-path" {
				tx.Changes[0].Path = filepath.Join(root, "foreign.yaml")
			}
			journal := writeProgramQueueFixture(t, root, directory, tx.ID, tx)
			for _, record := range records {
				writeProgramQueueFixture(t, root, "var/lib/panel-executor/network-ids-operations", record.Operation.ID, record)
			}
			for _, c := range transactions[0].Changes {
				if err := os.MkdirAll(filepath.Dir(c.Path), 0750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(c.Path, c.NextData, c.NextMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(c.Path, c.NextMode); err != nil {
					t.Fatal(err)
				}
			}
			config, yaml := transactions[0].Changes[1].Path, transactions[0].Changes[0].Path
			switch scenario {
			case "config-bytes":
				if err := os.WriteFile(config, append(transactions[0].Changes[1].NextData, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "yaml-bytes":
				if err := os.WriteFile(yaml, append(transactions[0].Changes[0].NextData, '\n'), 0644); err != nil {
					t.Fatal(err)
				}
			case "config-mode":
				os.Chmod(config, 0644)
			case "yaml-mode":
				os.Chmod(yaml, 0600)
			case "config-link":
				os.Rename(config, config+".retained")
				os.Symlink(config+".retained", config)
			case "yaml-hardlink":
				os.Link(yaml, yaml+".retained")
			}
			before := programQueueTree(t, root)
			r := programQueueReader{ctx: context.Background(), root: root}
			lease, called := &programQueueIDSLease{}, 0
			err := r.idsOperations(func(_ context.Context, got string, revision int64) (io.Closer, error) {
				called++
				if got != root || revision != 3 {
					t.Fatal("current revision was not proved")
				}
				var target string
				if scenario == "race-config" {
					target = config
				}
				if scenario == "race-yaml" {
					target = yaml
				}
				if scenario == "race-transaction" {
					target = journal
				}
				if target != "" {
					raw, readErr := os.ReadFile(target)
					if readErr != nil {
						t.Fatal(readErr)
					}
					mode := os.FileMode(0600)
					if target == yaml {
						mode = 0644
					}
					temporary := target + ".replacement"
					if e := os.WriteFile(temporary, raw, mode); e != nil {
						t.Fatal(e)
					}
					if e := os.Rename(temporary, target); e != nil {
						t.Fatal(e)
					}
				}
				if scenario == "scope-failure" {
					return nil, errors.New("original native scope refused")
				}
				if scenario == "nil-lease" {
					return nil, nil
				}
				return lease, nil
			})
			valid := strings.HasPrefix(scenario, "valid-")
			if (err == nil) != valid {
				t.Fatal(err)
			}
			if valid && (called != 1 || len(r.readLeases) != 1 || lease.closed) {
				t.Fatal("native scope or held lease missing")
			}
			for _, l := range r.readLeases {
				l.Close()
			}
			if !strings.HasPrefix(scenario, "race-") && !reflect.DeepEqual(before, programQueueTree(t, root)) {
				t.Fatal("read-only validation changed native files")
			}
			if valid {
				raw, _ := os.ReadFile(filepath.Join(root, "var/lib/panel-executor/network-ids-operations", records[0].Operation.ID+".json"))
				if !strings.Contains(string(raw), "\"state\":\"needs-attention\"") {
					t.Fatal("original decline was relabelled")
				}
			}
		})
	}
}
