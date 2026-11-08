package appcatalog

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"runtime"
	"testing"
)

func TestOfficialCatalogueChannelsAreClosedAndKeepOriginalTrustRoot(t *testing.T) {
	for channel, want := range map[string]string{"stable": DefaultBaseURL, "candidate": CandidateBaseURL} {
		got, err := officialCatalogBaseURL(channel)
		if err != nil || got != want {
			t.Fatal("closed publisher channel changed", channel, got, err)
		}
	}
	for _, channel := range []string{"", "main", "Stable", " candidate", "candidate\n", "https://evil.invalid", "../main", "candidate/../../main"} {
		if got, err := officialCatalogBaseURL(channel); err == nil || got != "" {
			t.Fatal("unknown channel must fail without fallback", channel)
		}
	}
	for _, name := range []string{"YUNZHAN_APP_CHANNEL", "YUNZHAN_APP_CATALOG_URL", "YUNZHAN_APP_PUBLIC_KEY"} {
		t.Setenv(name, "https://untrusted.invalid/not-an-official-channel")
	}
	client := Default()
	want, err := officialCatalogBaseURL(officialCatalogChannel)
	if err != nil || client.BaseURL != want || OfficialCatalogChannel() != officialCatalogChannel {
		t.Fatal("environment selected a channel or replaced compiled provenance")
	}
	key, err := x509.MarshalPKIXPublicKey(client.PublicKey)
	if err != nil || base64.StdEncoding.EncodeToString(key) != "MCowBQYDK2VwAyEAq/Lp03Rt0HZlhJF6fac3sFsb2Tq2Q75cFL+tpRNWNvc=" {
		t.Fatal("channel replaced the original official Ed25519 trust root")
	}
	wantStream := runtime.GOOS == "linux" && officialCatalogChannel == "candidate"
	if LoadBalanceStreamAvailable() != wantStream {
		t.Fatal("unfinished stable handler or unsupported host was enabled")
	}
}

func TestStreamCandidateRequirementCannotBorrowOtherContracts(t *testing.T) {
	_, envelope := streamReleaseFixture(t, CandidateBaseURL, nil)
	var manifest Manifest
	if json.Unmarshal(envelope.AppManifest, &manifest) != nil {
		t.Fatal("fixture metadata unavailable")
	}
	if handled, err := validateLoadBalanceStreamRequirement(manifest, streamReleaseFixtureAvailable); !handled || err != nil {
		t.Fatal("exact candidate contract refused", handled, err)
	}
	for _, available := range []func(string) bool{nil, func(string) bool { return false }} {
		if handled, err := validateLoadBalanceStreamRequirement(manifest, available); !handled || err == nil {
			t.Fatal("manifest claimed a missing compiled handler")
		}
	}
	for _, version := range []string{"1.8.5", "1.9.0-compat1", "1.9.1", "2.0.0", "bad"} {
		changed := manifest
		changed.Version = version
		if handled, err := validateLoadBalanceStreamRequirement(changed, streamReleaseFixtureAvailable); !handled || err == nil {
			t.Fatal("legacy, alias or future version borrowed native delivery", version)
		}
	}
	legacy := manifest
	legacy.Version, legacy.RequiredPanelFeatures = "1.8.5", nil
	if handled, err := validateLoadBalanceStreamRequirement(legacy, nil); handled || err != nil {
		t.Fatal("ordinary legacy HTTP requirement was replaced")
	}
	foreign := manifest
	foreign.ID = "memcached"
	if handled, err := validateLoadBalanceStreamRequirement(foreign, streamReleaseFixtureAvailable); !handled || err == nil {
		t.Fatal("foreign application borrowed the stream feature")
	}
	foreign.RequiredPanelFeatures = nil
	if handled, err := validateLoadBalanceStreamRequirement(foreign, nil); handled || err != nil {
		t.Fatal("foreign application was selected")
	}
}
