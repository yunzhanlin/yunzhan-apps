package core

import (
	"bytes"
	"encoding/json"
	"local/panel/internal/appcatalog"
	"strings"
	"testing"
)

func TestNetworkIDSRuleFeedManifestCompatibilityAndHandlerVersion(t *testing.T) {
	manifest := appcatalog.Manifest{ID: "network-threat-detection", Stage: "ready", Version: SoftwareImplementationVersion("network-threat-detection"), Delivery: appcatalog.Delivery{Provider: "panel-module", Target: "network-threat-detection"}, Compatibility: appcatalog.Compatibility{OS: []string{"debian-13", "ubuntu-24.04"}, Architectures: []string{"amd64", "arm64"}}}
	for _, platform := range []string{"debian-13", "ubuntu-24.04"} {
		for _, arch := range []string{"amd64", "arm64"} {
			if err := ValidateNetworkIDSRuleFeedManifestOn(manifest, platform, arch); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, scenario := range []string{"os", "arch", "id", "provider", "target", "stage", "future-version"} {
		candidate, platform, arch := manifest, "debian-13", "amd64"
		switch scenario {
		case "os":
			platform = "debian-12"
		case "arch":
			arch = "386"
		case "id":
			candidate.ID = "different"
		case "provider":
			candidate.Delivery.Provider = "compose"
		case "target":
			candidate.Delivery.Target = "different"
		case "stage":
			candidate.Stage = "design"
		case "future-version":
			candidate.Version = "99.0.0"
		}
		if err := ValidateNetworkIDSRuleFeedManifestOn(candidate, platform, arch); err == nil {
			t.Fatal("unsupported rule data accepted", scenario)
		}
	}
}

func networkRuleFeedSelectionFixture() NetworkIDSRuleFeedSelection {
	return NetworkIDSRuleFeedSelection{FeedID: "et-open-web-20261009", AppVersion: SoftwareImplementationVersion("network-threat-detection"), AppManifestSHA: strings.Repeat("a", 64), RuleManifestSHA: strings.Repeat("b", 64)}
}

func TestNetworkIDSRuleFeedQueueBindingLaneAndImmutableFailures(t *testing.T) {
	s := testStore(t)
	in := networkRuleFeedSelectionFixture()
	id, err := s.QueueNetworkIDSRuleFeed(in, "own-rule-data-job", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if again, err := s.QueueNetworkIDSRuleFeed(in, "own-rule-data-job", "admin"); err != nil || again != id {
		t.Fatal("lost reply duplicated job", err)
	}
	if _, err := s.QueueNetworkIDSRuleFeed(in, "own-rule-data-job", "different-admin"); err == nil {
		t.Fatal("another user adopted the first user's idempotency key")
	}
	for _, change := range []string{"feed", "version", "app-sha", "rules-sha"} {
		candidate := in
		switch change {
		case "feed":
			candidate.FeedID = "et-open-web-20261008"
		case "version":
			candidate.AppVersion = "99.0.0"
		case "app-sha":
			candidate.AppManifestSHA = strings.Repeat("c", 64)
		case "rules-sha":
			candidate.RuleManifestSHA = strings.Repeat("c", 64)
		}
		if _, err := s.QueueNetworkIDSRuleFeed(candidate, "own-rule-data-job", "admin"); err == nil {
			t.Fatal("idempotency key used with different selection", change)
		}
	}
	if _, err := s.QueueNetworkIDSRuleFeed(in, "other-key", "admin"); err == nil {
		t.Fatal("parallel same-module task accepted")
	}
	if _, err := s.nextRuntimeControlJob(); err == nil {
		t.Fatal("rule download assigned to website worker")
	}
	job, err := s.nextRuntimeInstallJob()
	if err != nil || job.ID != id || job.Kind != "network_ids_rulefeed_install" || len(job.Payload) > 1024 {
		t.Fatal("wrong task lane or retained data blob", job, err)
	}
	if err := s.FinishRuntime(job, "own failed data-only install", []Step{{Time: Now(), Message: "original failure proof"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.RetryRuntime(id, "admin"); err == nil {
		t.Fatal("original failed evidence made mutable")
	}
	if err := s.FinishRuntime(job, "", []Step{{Time: Now(), Message: "late success"}}); err != nil {
		t.Fatal(err)
	}
	var state, detail, steps string
	if err := s.DB.QueryRow(`SELECT state,error,steps FROM runtime_jobs WHERE id=?`, id).Scan(&state, &detail, &steps); err != nil || state != "failed" || detail != "own failed data-only install" || !strings.Contains(steps, "original failure proof") || strings.Contains(steps, "late success") {
		t.Fatal("late result erased failure", state, detail, steps, err)
	}
	if next, err := s.QueueNetworkIDSRuleFeed(in, "new-explicit-rule-job", "admin"); err != nil || next == id {
		t.Fatal("new explicit task unavailable", err)
	}
	var count int
	s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='network.ids.rules.install' AND target=?`, id).Scan(&count)
	if count != 1 {
		t.Fatal("replay duplicated audit", count)
	}
}

func TestNetworkIDSRuleFeedReplayPreservesActorAndDamagedEvidence(t *testing.T) {
	for _, scenario := range []string{"actor", "missing-audit", "duplicate-audit", "audit-result", "payload", "state", "type", "target"} {
		t.Run(scenario, func(t *testing.T) {
			s := testStore(t)
			in := networkRuleFeedSelectionFixture()
			id, err := s.QueueNetworkIDSRuleFeed(in, "own-retained-replay", "original-actor")
			if err != nil {
				t.Fatal(err)
			}
			actor := "original-actor"
			switch scenario {
			case "actor":
				actor = "different-actor"
			case "missing-audit":
				_, err = s.DB.Exec(`DELETE FROM audit_logs WHERE target=?`, id)
			case "duplicate-audit":
				_, err = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES('original-actor','network.ids.rules.install',?,'queued-data-only',?)`, id, Now())
			case "audit-result":
				_, err = s.DB.Exec(`UPDATE audit_logs SET result='verified' WHERE target=?`, id)
			case "payload":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET payload='{}' WHERE id=?`, id)
			case "state":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET state='invented' WHERE id=?`, id)
			case "type":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET kind='software_install' WHERE id=?`, id)
			case "target":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET target_id='other' WHERE id=?`, id)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := networkIDSRuleFeedReplay(s.DB, in, "own-retained-replay", actor); err == nil {
				t.Fatal("damaged or foreign binding replayed", scenario)
			}
			if _, err := s.QueueNetworkIDSRuleFeed(in, "own-retained-replay", actor); err == nil {
				t.Fatal("damaged evidence requeued", scenario)
			}
			var n int
			s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs`).Scan(&n)
			if n != 1 {
				t.Fatal("replay created another task", n)
			}
		})
	}
}

func TestNetworkIDSRuleFeedSelectionRejectsAmbiguity(t *testing.T) {
	in := networkRuleFeedSelectionFixture()
	raw, _ := json.Marshal(in)
	if got, err := decodeNetworkIDSRuleFeedSelection(raw); err != nil || got != in {
		t.Fatal(err)
	}
	for _, scenario := range []string{"duplicate", "case-alias", "escaped-duplicate", "alias-only", "extension", "null", "number", "missing", "trailing", "invalid-date", "path", "uppercase-sha", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			data := append([]byte(nil), raw...)
			switch scenario {
			case "duplicate":
				data = append([]byte(`{"feed_id":"other",`), data[1:]...)
			case "case-alias":
				data = append([]byte(`{"FEED_ID":"other",`), data[1:]...)
			case "escaped-duplicate":
				data = append([]byte(`{"feed\u005fid":"other",`), data[1:]...)
			case "alias-only":
				data = bytes.Replace(data, []byte(`"feed_id":`), []byte(`"FEED_ID":`), 1)
			case "extension":
				data = append([]byte(`{"repository":"https://foreign.invalid",`), data[1:]...)
			case "null":
				data = bytes.Replace(data, []byte(`"app_version":"`+in.AppVersion+`"`), []byte(`"app_version":null`), 1)
			case "number":
				data = bytes.Replace(data, []byte(`"app_version":"`+in.AppVersion+`"`), []byte(`"app_version":1`), 1)
			case "missing":
				var fields map[string]json.RawMessage
				json.Unmarshal(data, &fields)
				delete(fields, "rule_manifest_sha256")
				data, _ = json.Marshal(fields)
			case "trailing":
				data = append(data, []byte(`{}`)...)
			case "invalid-date":
				data = bytes.Replace(data, []byte("20261009"), []byte("20260230"), 1)
			case "path":
				data = bytes.Replace(data, []byte("et-open-web-20261009"), []byte("../../elsewhere"), 1)
			case "uppercase-sha":
				data = bytes.Replace(data, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("A", 64)), 1)
			case "oversize":
				data = bytes.Repeat([]byte(" "), 1025)
			}
			if _, err := decodeNetworkIDSRuleFeedSelection(data); err == nil {
				t.Fatal("ambiguous selection accepted", scenario)
			}
		})
	}
}

func TestNetworkIDSRuleFeedQueueBudgetPreservesRecords(t *testing.T) {
	s := testStore(t)
	in := networkRuleFeedSelectionFixture()
	payload, _ := json.Marshal(in)
	for i := 0; i < 64; i++ {
		id := ID()
		if _, err := s.DB.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,payload,error,idempotency_key,created_at,updated_at) VALUES(?,'network-threat-detection','network_ids_rulefeed_install','failed',?,'retained failure',?,?,?)`, id, string(payload), id, Now(), Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.QueueNetworkIDSRuleFeed(in, "over-budget", "admin"); err == nil {
		t.Fatal("retained jobs exceed budget")
	}
	var count int
	s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE target_id='network-threat-detection'`).Scan(&count)
	if count != 64 {
		t.Fatal("original records pruned", count)
	}
}
