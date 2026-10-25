package appcatalog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
)

const reviewedMemcachedRetirementFeature = "compose-memcached-retirement-v1"

func memcachedUnixRetirementFixture() Manifest {
	m := memcachedUnixFixture()
	m.RequiredPanelFeatures = []string{MemcachedDigestFeature, MemcachedUnixFeature, reviewedMemcachedRetirementFeature}
	return m
}

func TestMemcachedUnixRetirementRequiresItsIndependentlyCompiledHandler(t *testing.T) {
	m := memcachedUnixRetirementFixture()
	if !IsMemcachedUnixManifest(m) || validatePanelRequirements(m, func(string) bool { return true }) != nil {
		t.Fatal("the reviewed three-handler package is not recognized")
	}
	for _, missing := range m.RequiredPanelFeatures {
		if validatePanelRequirements(m, func(f string) bool { return f != missing }) == nil {
			t.Fatal("a missing independently compiled handler was accepted", missing)
		}
	}
}

func TestMemcachedUnixRetirementOldTwoHandlerPrototypeCannotClaimThePublishedPackage(t *testing.T) {
	m := memcachedUnixRetirementFixture()
	m.RequiredPanelFeatures = []string{MemcachedDigestFeature, MemcachedUnixFeature}
	if IsMemcachedUnixManifest(m) || validatePanelRequirements(m, func(string) bool { return true }) == nil {
		t.Fatal("an unpublished cache-only candidate can still claim the retirement-capable package")
	}
}

func TestMemcachedUnixRetirementFlagCannotBeBorrowedByForeignOrLegacyPackages(t *testing.T) {
	for _, m := range []Manifest{
		{ID: "redis", Version: "8.2.10-compat1", RequiredPanelFeatures: []string{reviewedMemcachedRetirementFeature}},
		{ID: "nginx-waf", Version: "2.5.2", RequiredPanelFeatures: []string{reviewedMemcachedRetirementFeature}},
		{ID: "memcached", Version: MemcachedDigestVersion, RequiredPanelFeatures: []string{reviewedMemcachedRetirementFeature}},
	} {
		if handled, err := validateMemcachedUnixRequirement(m, func(string) bool { return true }); !handled || err == nil {
			t.Fatal("retirement requirement escaped its exact independent package", m.ID)
		}
	}
}

func TestMemcachedUnixRetirementOrderDoesNotPermitDuplicateOrFutureFlags(t *testing.T) {
	m := memcachedUnixRetirementFixture()
	slices.Reverse(m.RequiredPanelFeatures)
	if !IsMemcachedUnixManifest(m) || validatePanelRequirements(m, func(string) bool { return true }) != nil {
		t.Fatal("canonical feature-set order was mistaken for a different package")
	}
	for _, flags := range [][]string{
		{MemcachedDigestFeature, MemcachedUnixFeature, MemcachedUnixFeature},
		{MemcachedDigestFeature, reviewedMemcachedRetirementFeature, reviewedMemcachedRetirementFeature},
		{MemcachedDigestFeature, MemcachedUnixFeature, "compose-memcached-retirement-v2"},
	} {
		m.RequiredPanelFeatures = flags
		if IsMemcachedUnixManifest(m) || validatePanelRequirements(m, func(string) bool { return true }) == nil {
			t.Fatal("duplicate or unreviewed flag authorized this package", flags)
		}
	}
}

func TestMemcachedUnixRetirementMissingHandlerRefusesBeforeAnySourceRequest(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "no source request is authorized", http.StatusInternalServerError)
	}))
	defer server.Close()
	client, in := memcachedUnixEnvelopeFixtureAt(t, server.URL, nil)
	client.HTTP = server.Client()
	_, err := client.fetchMemcachedUnixReleaseEnvelope(context.Background(), MemcachedUnixVersion, hashRuleFeedFile(in.AppManifest), func(f string) bool { return f != reviewedMemcachedRetirementFeature })
	if err == nil || requests.Load() != 0 {
		t.Fatal("cache-only capability reached a distribution source", requests.Load(), err)
	}
}

func TestMemcachedUnixRetirementCorrectSignatureCannotReenableTheOldTwoHandlerABI(t *testing.T) {
	client, in := memcachedUnixEnvelopeFixture(t, func(m *Manifest) {
		m.RequiredPanelFeatures = []string{MemcachedDigestFeature, MemcachedUnixFeature}
	})
	if _, err := verifyMemcachedUnixReleaseEnvelope(context.Background(), client, in, MemcachedUnixVersion, hashRuleFeedFile(in.AppManifest), func(string) bool { return true }); err == nil {
		t.Fatal("even a correctly signed package may not omit the retirement contract")
	}
}

func TestMemcachedUnixRetirementAvailabilityIsOnlyTheActualCompiledLinuxHandler(t *testing.T) {
	if panelFeatureAvailable(reviewedMemcachedRetirementFeature) != (runtime.GOOS == "linux") {
		t.Fatal("retirement availability is not tied to the compiled Linux implementation")
	}
	if panelFeatureAvailable("compose-memcached-retirement-v2") {
		t.Fatal("an unimplemented future retirement handler was advertised")
	}
}
