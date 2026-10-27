package executor

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func streamModuleProposalFixture(t *testing.T, original []byte) ([]byte, time.Time) {
	t.Helper()
	action := "install"
	if len(original) != 0 {
		action = "update"
	}
	raw, _ := streamInstallBindingFixture(t, action)
	seed, err := loadbalancestream.DecodeInstallationSeed(raw)
	if err != nil {
		t.Fatal(err)
	}
	if action == "update" {
		var record map[string]any
		if json.Unmarshal(original, &record) != nil {
			t.Fatal("invalid base fixture")
		}
		seed.OriginalModuleVersion, _ = record["version"].(string)
		seed.OriginalModuleSHA256 = core.Hash(string(original))
		raw, err = loadbalancestream.InstallationSeedBytes(seed)
		if err != nil {
			t.Fatal(err)
		}
	}
	created, _ := time.Parse(time.RFC3339, seed.JobCreatedAt)
	return raw, created.Add(time.Hour)
}

func TestLoadBalanceStreamModuleProposalPreservesCompleteLegacySettings(t *testing.T) {
	for _, version := range []string{"1.8.4", "1.8.5", loadbalancestream.AppVersion} {
		t.Run(version, func(t *testing.T) {
			epoch := ""
			if version == loadbalancestream.AppVersion {
				epoch = `,"installation_id":"` + core.ID() + `"`
			}
			original := []byte(`{"id":"load-balance","version":"` + version + `","settings":{"method":"least_conn","domain":"原有.example","nested":{"threshold":9007199254740993,"empty":null,"nodes":["127.0.0.1:19003"]}},"installed_at":"2026-10-24T00:00:00Z","updated_at":"2026-10-24T12:00:00Z"` + epoch + `}`)
			seed, now := streamModuleProposalFixture(t, original)
			before := bytes.Clone(original)
			proposal, err := loadBalanceStreamModuleProposal(seed, original, now)
			if err != nil {
				t.Fatal("complete retained legacy source refused", err)
			}
			old, err := decodeLoadBalanceStreamModule(original)
			if err != nil {
				t.Fatal(err)
			}
			next, err := decodeLoadBalanceStreamModule(proposal)
			if err != nil || next["version"] != loadbalancestream.AppVersion || !reflect.DeepEqual(old["settings"], next["settings"]) || old["installed_at"] != next["installed_at"] || !bytes.Equal(original, before) {
				t.Fatal("proposal changed original bytes, settings, exact numbers or first installation time", err)
			}
			decoded, _ := loadbalancestream.DecodeInstallationSeed(seed)
			wantEpoch := any(decoded.Nonce)
			if version == loadbalancestream.AppVersion {
				wantEpoch = old["installation_id"]
			}
			if next["installation_id"] != wantEpoch || next["updated_at"] != now.UTC().Format(time.RFC3339) || len(next) != 6 {
				t.Fatal("install instance or bounded closed publication changed")
			}
		})
	}
}

func TestLoadBalanceStreamModuleProposalFreshEmptyHasNoListeners(t *testing.T) {
	seed, now := streamModuleProposalFixture(t, nil)
	proposal, err := loadBalanceStreamModuleProposal(seed, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeLoadBalanceStreamModule(proposal)
	if err != nil || len(v["settings"].(map[string]any)) != 0 || v["version"] != loadbalancestream.AppVersion || len(v) != 6 {
		t.Fatal("fresh installation invented a listener or added effect authority", err)
	}
	if _, err = loadBalanceStreamModuleProposal(seed, []byte(`{}`), now); err == nil {
		t.Fatal("fresh installation adopted existing bytes")
	}
}

func TestLoadBalanceStreamModuleProposalOriginalDriftAndAmbiguityRefuse(t *testing.T) {
	original := []byte(`{"id":"load-balance","version":"1.8.5","settings":{"method":"round-robin"},"installed_at":"2026-10-24T00:00:00Z"}`)
	seed, now := streamModuleProposalFixture(t, original)
	for name, bad := range map[string][]byte{
		"missing":               nil,
		"changed-original-byte": append(bytes.Clone(original), ' '),
		"different-id":          bytes.Replace(original, []byte("load-balance"), []byte("nginx-waf"), 1),
		"different-version":     bytes.Replace(original, []byte("1.8.5"), []byte("1.8.4"), 1),
		"unbound-native-epoch":  bytes.Replace(original, []byte("1.8.5"), []byte("1.9.0"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			before := bytes.Clone(bad)
			if _, err := loadBalanceStreamModuleProposal(seed, bad, now); err == nil || !bytes.Equal(before, bad) {
				t.Fatal("unknown original adopted, normalized or modified")
			}
		})
	}
	for name, bad := range map[string][]byte{
		"top-null": []byte(`null`), "top-array": []byte(`[]`),
		"unknown":               []byte(`{"id":"load-balance","version":"1.8.5","extra":true}`),
		"duplicate":             []byte(`{"id":"load-balance","id":"load-balance","version":"1.8.5"}`),
		"escaped-duplicate":     []byte(`{"id":"load-balance","\u0069d":"load-balance","version":"1.8.5"}`),
		"case-alias":            []byte(`{"id":"load-balance","ID":"load-balance","version":"1.8.5"}`),
		"nested-duplicate":      []byte(`{"id":"load-balance","version":"1.8.5","settings":{"rate":1,"\u0072ate":1}}`),
		"nested-case-duplicate": []byte(`{"id":"load-balance","version":"1.8.5","settings":{"rate":1,"Rate":1}}`),
		"settings-array":        []byte(`{"id":"load-balance","version":"1.8.5","settings":[]}`),
		"settings-scalar":       []byte(`{"id":"load-balance","version":"1.8.5","settings":2}`),
		"clock-type":            []byte(`{"id":"load-balance","version":"1.8.5","installed_at":3}`),
		"clock-alias":           []byte(`{"id":"load-balance","version":"1.8.5","installed_at":"2026-10-24T00:00:00+00:00"}`),
		"future-clock":          []byte(`{"id":"load-balance","version":"1.8.5","installed_at":"2099-10-24T00:00:00Z"}`),
		"reversed-clock":        []byte(`{"id":"load-balance","version":"1.8.5","installed_at":"2026-10-24T00:00:00Z","updated_at":"2026-10-23T00:00:00Z"}`),
		"legacy-forged-epoch":   []byte(`{"id":"load-balance","version":"1.8.5","installation_id":"` + core.ID() + `"}`),
		"native-missing-epoch":  []byte(`{"id":"load-balance","version":"1.9.0"}`),
		"native-bad-epoch":      []byte(`{"id":"load-balance","version":"1.9.0","installation_id":"bad"}`),
		"unsupported-version":   []byte(`{"id":"load-balance","version":"1.8.3"}`),
		"version-type":          []byte(`{"id":"load-balance","version":1.85}`),
		"trailing-document":     append(bytes.Clone(original), original...),
		"over-limit":            []byte(strings.Repeat(" ", loadBalanceStreamModuleLimit+1)),
		"depth":                 []byte(`{"id":"load-balance","version":"1.8.5","settings":` + strings.Repeat(`{"a":`, 17) + `null` + strings.Repeat(`}`, 17) + `}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeLoadBalanceStreamModule(bad); err == nil {
				t.Fatal("ambiguous/incomplete module record accepted")
			}
		})
	}
	for name, clock := range map[string]time.Time{"zero": {}, "before-job": now.Add(-2 * time.Hour), "future": time.Now().Add(time.Hour)} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadBalanceStreamModuleProposal(seed, original, clock); err == nil {
				t.Fatal("unbound publication clock accepted")
			}
		})
	}
}
