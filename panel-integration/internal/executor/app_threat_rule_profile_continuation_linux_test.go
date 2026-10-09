//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestThreatIDSRuleFeedCommittedUseNeverBecomesFreshActivationAuthority(t *testing.T) {
	for _, scenario := range []string{"expired-catalog", "aged-dataset", "modified-rule", "modified-signature", "wrong-app-binding", "future-clock", "private-mode", "missing-license"} {
		t.Run(scenario, func(t *testing.T) {
			version := core.SoftwareImplementationVersion("network-threat-detection")
			f := threatRuleDataFixtureVersion(t, version)
			store := threatRuleFeedTestStore(t, f.trust)
			record, err := store.install(context.Background(), f.in, version, f.appSHA)
			if err != nil {
				t.Fatal(err)
			}
			name := threatIDSRuleFeedName(record.FeedID, record.RuleManifestSHA)
			selection := core.NetworkIDSRuleFeedSelection{FeedID: record.FeedID, AppVersion: version, AppManifestSHA: f.appSHA, RuleManifestSHA: record.RuleManifestSHA}
			store.now = func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) }
			switch scenario {
			case "aged-dataset":
				store.now = func() time.Time { return time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC) }
			case "modified-rule", "modified-signature":
				file := "et-open.rules"
				if scenario == "modified-signature" {
					file = "rule-data-catalog.sig"
				}
				path := filepath.Join(store.base, name, file)
				raw, _ := os.ReadFile(path)
				raw[0] ^= 1
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-app-binding":
				selection.AppManifestSHA = core.Hash("foreign")
			case "future-clock":
				store.now = func() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) }
			case "private-mode":
				if err := os.Chmod(filepath.Join(store.base, name, "catalog.json"), 0644); err != nil {
					t.Fatal(err)
				}
			case "missing-license":
				if err := os.Rename(filepath.Join(store.base, name, "LICENSE"), filepath.Join(store.base, "retained-license")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.read(context.Background(), name, version, f.appSHA); err == nil {
				t.Fatal("expired or damaged data became current authority")
			}
			if _, err := store.ruleDataYAML(context.Background(), threatIDSConfig{Revision: 9, Interface: "lo", HomeNetworks: []string{"127.0.0.1/32"}}, selection); err == nil {
				t.Fatal("expired or damaged data newly activated")
			}
			profile, err := store.committedRuleProfile(context.Background(), selection)
			valid := scenario == "expired-catalog" || scenario == "aged-dataset"
			if (err == nil) != valid {
				t.Fatal("continuity integrity gate", scenario, err)
			}
			if valid {
				if profile.State != "verified-for-committed-use" || profile.CurrentForNewSelection || profile.Warning == "" || profile.AgeDays < 2 || *profile.Selection != selection {
					t.Fatal("staleness disguised", profile)
				}
				inventory := store.inventory(context.Background())
				if !inventory.StateKnown || len(inventory.Rows) != 1 || inventory.Rows[0].State != "verified-retained-data" || inventory.Rows[0].Selection != selection {
					t.Fatal("old trusted data blocks new installation", inventory)
				}
				if _, err := store.install(context.Background(), f.in, version, f.appSHA); err == nil {
					t.Fatal("continuity path renewed installation expiry")
				}
			}
		})
	}
}

func TestThreatIDSRuleFeedJournalDerivesBothPinnedProfilesWithoutScopeExpansion(t *testing.T) {
	s, changes, state := threatIDSJournalFixture(t)
	var next threatIDSConfig
	if decodeThreatIDSPrivateJSON(changes[1].NextData, &next) != nil {
		t.Fatal("fixture")
	}
	selection := core.NetworkIDSRuleFeedSelection{FeedID: "et-open-web-20261009", AppVersion: core.SoftwareImplementationVersion("network-threat-detection"), AppManifestSHA: core.Hash("signed app"), RuleManifestSHA: core.Hash("signed feed")}
	next.RuleFeed = &selection
	var err error
	changes[1].NextData, err = json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	yaml, err := threatIDSYAML(next, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil {
		t.Fatal(err)
	}
	changes[0].NextData = []byte(yaml)
	tx, err := s.startWAFTransactionState(changes, state)
	if err != nil {
		t.Fatal("closed original-to-feed journal", err)
	}
	if err := wafApplyChange(tx.Changes[0], true); err != nil {
		t.Fatal(err)
	}
	if restored, err := s.recoverWAFTransaction(); err != nil || !restored {
		t.Fatal("two-file restoration", err)
	}
	for _, change := range tx.Changes {
		if match, err := s.wafCurrentMatches(change, false); err != nil || !match {
			t.Fatal("original not restored", err)
		}
	}
	// A forged path in the root-owned selector is rejected before native use.
	next.RuleFeed.FeedID = "../../etc"
	if validateThreatIDSConfig(next) == nil {
		t.Fatal("selector became arbitrary rules path")
	}
}
