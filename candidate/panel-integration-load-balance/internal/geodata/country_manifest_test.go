package geodata

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func countryManifestFixture(t *testing.T) (CountryManifest, ed25519.PublicKey, ed25519.PrivateKey, map[string][]byte) {
	t.Helper()
	snapshot := countryMixedFixture(t)
	_, pub, private, parent, parentSig := testAuthority(t, snapshot.authority.Manifest())
	shards, err := snapshot.CountryShards(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	assets := []CountryAsset{}
	m := CountryManifest{Format: 1, Channel: CountryChannel, Release: "2026-10", Revision: 1, BuildEpoch: snapshot.authority.manifest.BuildEpoch, ParentManifest: string(parent), ParentSignature: string(parentSig), GeneratorSHA256: strings.Repeat("c", 64), License: LicenseURL, AttributionURL: AttributionURL}
	for _, shard := range shards.Shards {
		var b bytes.Buffer
		metadata, err := EncodeCountryCIDR(context.Background(), shard.Data, &b)
		if err != nil {
			t.Fatal(err)
		}
		if metadata.ParentManifestSHA256 != hash(parent) {
			t.Fatal("synthetic original parent differs")
		}
		files[shard.Code] = append([]byte(nil), b.Bytes()...)
		assets = append(assets, CountryAsset{shard.Code, metadata.Bytes, metadata.SHA256, metadata.Networks})
		m.Bytes += metadata.Bytes
		m.Networks += metadata.Networks
	}
	raw, err := json.Marshal(assets)
	if err != nil {
		t.Fatal(err)
	}
	m.AssetsJSON = string(raw)
	return m, pub, private, files
}

func signCountryFixture(t *testing.T, m CountryManifest, private ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(CountrySignatureDomain), raw...))))
}

func TestCountryManifestDualSignaturesAndEveryIndependentAssetBindExactOriginalParent(t *testing.T) {
	m, pub, private, files := countryManifestFixture(t)
	raw, sig := signCountryFixture(t, m, private)
	a, err := VerifyCountryManifest(raw, sig, pub, fixtureNow, nil)
	if err != nil || a.SHA256() != hash(raw) || a.KeySHA256() != hash(pub) || !reflect.DeepEqual(a.Manifest(), m) {
		t.Fatal(a, err)
	}
	for code, data := range files {
		got, err := VerifyCountryAsset(context.Background(), a, code, bytes.NewReader(data))
		if err != nil || got.SHA256 != hash(data) || got.ParentManifestSHA256 != hash([]byte(m.ParentManifest)) || len(got.Countries) != 1 || got.Countries[0].Code != code {
			t.Fatal("signed per-country coverage lost provenance", code, got, err)
		}
	}
	assets := a.Assets()
	assets[0].Code = "ZZ"
	if a.Assets()[0].Code == "ZZ" {
		t.Fatal("caller mutated verified asset inventory")
	}
	selected, err := a.Select([]string{"CN", "US"})
	if err != nil || len(selected) != 2 || selected[0].Code != "CN" || selected[1].Code != "US" {
		t.Fatal(selected, err)
	}
	if _, err := VerifyCountryManifest(raw, sig, pub, fixtureNow, &a); err != nil {
		t.Fatal("identical signed revision not idempotent", err)
	}
}

func TestCountryManifestRejectsUnknownDuplicateCaseAliasedNullAndTrailingStructuresEvenWhenSigned(t *testing.T) {
	m, pub, private, _ := countryManifestFixture(t)
	raw, _ := signCountryFixture(t, m, private)
	cases := map[string]string{"duplicate": strings.Replace(string(raw), `"format":1`, `"format":1,"format":1`, 1), "alias": strings.Replace(string(raw), `"format":1`, `"Format":1`, 1), "unknown": strings.Replace(string(raw), `"format":1`, `"format":1,"unexpected":0`, 1), "null": strings.Replace(string(raw), `"format":1`, `"format":null`, 1), "nested": strings.Replace(string(raw), `"format":1`, `"format":{}`, 1), "trailing": string(raw) + ` {}`}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(CountrySignatureDomain), []byte(text)...))))
			got, err := VerifyCountryManifest([]byte(text), sig, pub, fixtureNow, nil)
			if err == nil || !reflect.DeepEqual(got, CountryAuthority{}) {
				t.Fatal("malformed signed object accepted", got, err)
			}
		})
	}
	for name, value := range map[string]string{"duplicate": strings.Replace(m.AssetsJSON, `"code":"AU"`, `"code":"AU","code":"AU"`, 1), "alias": strings.Replace(m.AssetsJSON, `"code":"AU"`, `"Code":"AU"`, 1), "unknown": strings.Replace(m.AssetsJSON, `"code":"AU"`, `"code":"AU","file":"/etc/passwd"`, 1), "null": "null", "nested": `[[{}]]`, "trailing": m.AssetsJSON + " []"} {
		t.Run("assets-"+name, func(t *testing.T) {
			copy := m
			copy.AssetsJSON = value
			r, s := signCountryFixture(t, copy, private)
			if got, err := VerifyCountryManifest(r, s, pub, fixtureNow, nil); err == nil || !reflect.DeepEqual(got, CountryAuthority{}) {
				t.Fatal("malformed asset inventory accepted", got, err)
			}
		})
	}
}

func TestCountryManifestRefusesCrossDomainParentMismatchRollbackAndSameRevisionReplacement(t *testing.T) {
	m, pub, private, _ := countryManifestFixture(t)
	raw, sig := signCountryFixture(t, m, private)
	original, err := VerifyCountryManifest(raw, sig, pub, fixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCountryManifest(raw, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(SignatureDomain), raw...)))), pub, fixtureNow, nil); err == nil {
		t.Fatal("city signature used as derived country authority")
	}
	for _, kind := range []string{"parent-signature", "parent-raw", "release", "epoch", "generator", "license", "revision-zero", "same-revision", "lower-revision"} {
		t.Run(kind, func(t *testing.T) {
			copy := m
			previous := &original
			switch kind {
			case "parent-signature":
				copy.ParentSignature = string(sig)
			case "parent-raw":
				copy.ParentManifest += " "
			case "release":
				copy.Release = "2026-11"
			case "epoch":
				copy.BuildEpoch++
			case "generator":
				copy.GeneratorSHA256 = "bad"
			case "license":
				copy.License = "proprietary"
			case "revision-zero":
				copy.Revision = 0
			case "same-revision":
				copy.GeneratorSHA256 = strings.Repeat("d", 64)
			case "lower-revision":
				higher := m
				higher.Revision = 2
				r, s := signCountryFixture(t, higher, private)
				a, e := VerifyCountryManifest(r, s, pub, fixtureNow, &original)
				if e != nil {
					t.Fatal(e)
				}
				previous = &a
			}
			r, s := signCountryFixture(t, copy, private)
			if got, e := VerifyCountryManifest(r, s, pub, fixtureNow, previous); e == nil || !reflect.DeepEqual(got, CountryAuthority{}) {
				t.Fatal("unqualified replacement accepted", got, e)
			}
		})
	}
	higher := m
	higher.Revision = 2
	r, s := signCountryFixture(t, higher, private)
	if _, err := VerifyCountryManifest(r, s, pub, fixtureNow, &original); err != nil {
		t.Fatal("explicit higher signed derivation revision refused", err)
	}
}

func TestCountryManifestSelectionRetainsOriginalConsumerBudgetsAndCannotInventCoverage(t *testing.T) {
	m, pub, private, _ := countryManifestFixture(t)
	raw, sig := signCountryFixture(t, m, private)
	a, err := VerifyCountryManifest(raw, sig, pub, fixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, codes := range [][]string{nil, {"US", "CN"}, {"US", "US"}, {"ZZ"}, {"GB"}, {"us"}} {
		if assets, err := a.Select(codes); err == nil || assets != nil {
			t.Fatal("selection invented or partially accepted coverage", codes, assets, err)
		}
	}
	assets := a.Assets()
	assets[0].Networks = maxCountryNetworks
	assets[1].Networks = 1
	v := m
	v.Networks = 0
	for _, asset := range assets {
		v.Networks += asset.Networks
	}
	b, _ := json.Marshal(assets)
	v.AssetsJSON = string(b)
	r, s := signCountryFixture(t, v, private)
	large, err := VerifyCountryManifest(r, s, pub, fixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if selected, err := large.Select([]string{assets[0].Code, assets[1].Code}); err == nil || selected != nil {
		t.Fatal("publisher capacity incorrectly granted to a panel activation", selected, err)
	}
}

func TestCountryAssetRejectsTruncationExtraBytesWrongCountryAndMissingSignedAuthority(t *testing.T) {
	m, pub, private, files := countryManifestFixture(t)
	raw, sig := signCountryFixture(t, m, private)
	a, err := VerifyCountryManifest(raw, sig, pub, fixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := files["US"]
	for _, bytes := range [][]byte{data[:len(data)-1], append(append([]byte(nil), data...), '\n'), files["CN"]} {
		got, err := VerifyCountryAsset(context.Background(), a, "US", strings.NewReader(string(bytes)))
		if err == nil || !reflect.DeepEqual(got, CountryCIDRMetadata{}) {
			t.Fatal("wrong signed asset accepted", got, err)
		}
	}
	if got, err := VerifyCountryAsset(context.Background(), CountryAuthority{}, "US", bytes.NewReader(data)); err == nil || !reflect.DeepEqual(got, CountryCIDRMetadata{}) {
		t.Fatal("format-only input or zero authority accepted", got, err)
	}
}
