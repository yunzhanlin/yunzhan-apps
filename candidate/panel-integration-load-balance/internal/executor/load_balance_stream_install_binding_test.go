package executor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func streamInstallBindingFixture(t *testing.T, action string) ([]byte, core.LoadBalanceStreamInstallAuthority) {
	t.Helper()
	empty, err := loadbalancestream.RenderRuntime([]loadbalancestream.Entry{}, loadbalancestream.ServiceRuntimePrefix,
		loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget})
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"settings":{},"version":"` + loadbalancestream.AppVersion + `"}`
	seed := loadbalancestream.InstallationSeed{Format: 1, Nonce: core.ID(), JobID: core.ID(), ActorID: core.ID(), Action: action,
		AppVersion: loadbalancestream.AppVersion, AccessRevision: 1, ActorObservationSHA256: strings.Repeat("1", 64),
		ManifestSHA256: strings.Repeat("2", 64), OriginalRequestSHA256: strings.Repeat("3", 64), KeySHA256: strings.Repeat("4", 64),
		JobCreatedAt: "2026-10-25T00:00:00Z", CatalogSHA256: strings.Repeat("5", 64), SubmissionSHA256: strings.Repeat("6", 64),
		ProgrammeInputsSHA256: strings.Repeat("7", 64), EmptyConfigurationSHA: empty.SHA256}
	if action == "update" {
		payload = `{"settings":null,"version":"` + loadbalancestream.AppVersion + `"}`
		seed.OriginalModuleVersion = "1.8.5"
		seed.OriginalModuleSHA256 = strings.Repeat("8", 64)
	}
	seed.PayloadSHA256 = core.Hash(payload)
	raw, err := loadbalancestream.InstallationSeedBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	grant := core.LoadBalanceStreamInstallAuthority{Format: 1, JobID: seed.JobID, ActorID: seed.ActorID, Action: action, AppVersion: seed.AppVersion,
		ManifestSHA256: seed.ManifestSHA256, PayloadSHA256: seed.PayloadSHA256, OriginalRequestSHA256: seed.OriginalRequestSHA256,
		KeySHA256: seed.KeySHA256, AccessRevision: seed.AccessRevision, ActorObservationSHA256: seed.ActorObservationSHA256, JobCreatedAt: seed.JobCreatedAt}
	return raw, grant
}

func TestLoadBalanceStreamInstallationBindingExactOriginalRecords(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		t.Run(action, func(t *testing.T) {
			raw, grant := streamInstallBindingFixture(t, action)
			before := bytes.Clone(raw)
			if !loadBalanceStreamInstallationGrantMatches(raw, grant) {
				t.Fatal("exact original mapping refused")
			}
			if !bytes.Equal(raw, before) {
				t.Fatal("binding modified retained original seed")
			}
		})
	}
}
func TestLoadBalanceStreamInstallationBindingEveryAuthorityFieldIsMandatory(t *testing.T) {
	fields := []string{"format", "job_id", "actor_id", "action", "app_version", "manifest_sha256", "payload_sha256", "original_request_sha256", "key_sha256", "access_revision", "actor_observation_sha256", "job_created_at"}
	for _, action := range []string{"install", "update"} {
		for _, field := range fields {
			t.Run(action+"/"+field, func(t *testing.T) {
				raw, grant := streamInstallBindingFixture(t, action)
				encoded, err := json.Marshal(grant)
				if err != nil {
					t.Fatal(err)
				}
				var values map[string]any
				if json.Unmarshal(encoded, &values) != nil {
					t.Fatal("grant fixture")
				}
				if field == "format" || field == "access_revision" {
					values[field] = float64(2)
				} else {
					values[field] = "different"
				}
				encoded, err = json.Marshal(values)
				if err != nil {
					t.Fatal(err)
				}
				var changed core.LoadBalanceStreamInstallAuthority
				if json.Unmarshal(encoded, &changed) != nil {
					t.Fatal("changed fixture")
				}
				if loadBalanceStreamInstallationGrantMatches(raw, changed) {
					t.Fatal("changed original authority field matched", field)
				}
			})
		}
	}
}
func TestLoadBalanceStreamInstallationBindingNeverNormalizesAnAmbiguousSeed(t *testing.T) {
	raw, grant := streamInstallBindingFixture(t, "install")
	for name, bad := range map[string][]byte{"empty": nil, "extra-space": append(bytes.Clone(raw), ' '), "two-values": append(bytes.Clone(raw), raw...), "unknown": bytes.Replace(raw, []byte(`"format":1`), []byte(`"unknown":1,"format":1`), 1), "duplicate": bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1)} {
		t.Run(name, func(t *testing.T) {
			if loadBalanceStreamInstallationGrantMatches(bad, grant) {
				t.Fatal("ambiguous seed normalized")
			}
		})
	}
}
