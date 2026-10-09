package appcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"local/panel/internal/rulefeed"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type ruleDataFixture struct {
	client                                                            *Client
	server                                                            *httptest.Server
	private                                                           ed25519.PrivateKey
	manifest                                                          Manifest
	bundle                                                            *rulefeed.Bundle
	appCatalog, appSignature, appManifest, dataCatalog, dataSignature []byte
	catalog                                                           RuleDataCatalog
	requests                                                          []string
	cookies                                                           []string
	channelQuery                                                      string
	tamper, redirect                                                  string
}

var ruleDataFixtureNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func newRuleDataFixture(t *testing.T) *ruleDataFixture {
	t.Helper()
	manifest, bundle := ruleFeedFixture(t)
	feed := manifest.RuleFeeds[0]
	manifest.RuleFeeds = nil
	manifest.RuleDataChannel = &RuleDataChannel{ID: ruleDataChannelID, Format: 1, Engine: "suricata-8.0"}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &ruleDataFixture{private: private, manifest: manifest, bundle: bundle, catalog: RuleDataCatalog{SchemaVersion: 1, Channel: ruleDataChannelID, Sequence: 1, PublishedAt: "2026-10-09T10:00:00Z", ExpiresAt: "2026-10-10T10:00:00Z", Feed: feed}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.URL.Path)
		f.cookies = append(f.cookies, r.Header.Get("Cookie"))
		if r.URL.Path == "/signatures/catalog-v1.bundle.json" {
			data, _ := json.Marshal(catalogBundle{Catalog: string(f.appCatalog), Signature: string(f.appSignature)})
			w.Write(data)
			return
		}
		if r.URL.Path == "/dist/apps/network-threat-detection/"+f.manifest.Version+"/manifest.json" {
			w.Write(f.appManifest)
			return
		}
		if r.URL.Path == "/dist/apps/network-threat-detection/rule-data/"+ruleDataChannelID+"/catalog-v1.bundle.json" {
			f.channelQuery = r.URL.RawQuery
			if f.redirect != "" {
				http.Redirect(w, r, f.redirect, http.StatusFound)
				return
			}
			data, _ := json.Marshal(catalogBundle{Catalog: string(f.dataCatalog), Signature: string(f.dataSignature)})
			w.Write(data)
			return
		}
		prefix := "/dist/apps/network-threat-detection/rule-data/" + ruleDataChannelID + "/feeds/" + f.catalog.Feed.ID + "/" + f.catalog.Feed.ManifestSHA256 + "/"
		if strings.HasPrefix(r.URL.Path, prefix) {
			name := strings.TrimPrefix(r.URL.Path, prefix)
			data, ok := f.bundle.Files[name]
			if ok {
				if f.tamper == name {
					data = bytes.Clone(data)
					data[0] ^= 1
				}
				w.Write(data)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(f.server.Close)
	der, _ := x509.MarshalPKIXPublicKey(public)
	f.client, err = New(f.server.URL, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	f.appManifest, _ = json.Marshal(f.manifest)
	item := CatalogItem{ID: manifest.ID, Name: manifest.Name, Category: manifest.Category, Version: manifest.Version, Summary: manifest.Summary, Stage: manifest.Stage, Risk: manifest.Risk, Provider: manifest.Delivery.Provider, Target: manifest.Delivery.Target, ManageRoute: manifest.Delivery.ManageRoute, Capabilities: manifest.Capabilities, PackageURL: f.server.URL + "/dist/apps/network-threat-detection/" + manifest.Version + "/manifest.json", SHA256: hashRuleFeedFile(f.appManifest)}
	f.appCatalog, _ = json.Marshal(Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-09T10:00:00Z", Repository: "https://own.invalid", Apps: []CatalogItem{item}})
	f.appSignature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, f.appCatalog)))
	f.signData()
	return f
}

func (f *ruleDataFixture) signData() {
	f.dataCatalog, _ = json.Marshal(f.catalog)
	f.dataSignature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.private, append([]byte(ruleDataDomain), f.dataCatalog...))))
}
func (f *ruleDataFixture) verify(now time.Time, previous *RuleDataAuthority) (RuleDataAuthority, error) {
	return f.client.VerifyRuleDataAuthority(f.appCatalog, f.appSignature, f.appManifest, f.dataCatalog, f.dataSignature, f.manifest.Version, hashRuleFeedFile(f.appManifest), now, previous)
}

func TestRuleDataChannelIndependentMetadataAndOfflineReceiver(t *testing.T) {
	f := newRuleDataFixture(t)
	authority, err := f.client.FetchRuleDataAuthority(context.Background(), f.manifest.Version, hashRuleFeedFile(f.appManifest), ruleDataFixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 3 || f.channelQuery == "" || !strings.Contains(f.channelQuery, "check=") {
		t.Fatalf("metadata must use three requests and bypass cached mutable channel: %v", f.requests)
	}
	copy := authority.Catalog()
	copy.Feed.Assets[0].SHA256 = strings.Repeat("0", 64)
	if authority.Catalog().Feed.Assets[0].SHA256 == copy.Feed.Assets[0].SHA256 {
		t.Fatal("catalog getter aliases authority")
	}
	envelope, err := f.client.FetchRuleDataEnvelope(context.Background(), authority, ruleDataFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 9 || len(envelope.Files) != 6 {
		t.Fatal("explicit data must fetch only six closed files")
	}
	receiver := &Client{BaseURL: f.client.BaseURL, PublicKey: bytes.Clone(f.client.PublicKey)} // no HTTP available
	verified, data, err := receiver.VerifyRuleDataEnvelope(context.Background(), envelope, f.manifest.Version, hashRuleFeedFile(f.appManifest), f.catalog.Feed.ID, f.catalog.Feed.ManifestSHA256, ruleDataFixtureNow, &authority)
	if err != nil || data == nil || verified.CatalogSHA256() != authority.CatalogSHA256() {
		t.Fatalf("independent offline verification: %v", err)
	}
	// Updating signed rule metadata must not change the app manifest or version.
	appBefore := bytes.Clone(f.appManifest)
	f.catalog.Sequence++
	f.catalog.PublishedAt = "2026-10-09T11:00:00Z"
	f.catalog.ExpiresAt = "2026-10-10T11:00:00Z"
	f.signData()
	next, err := f.client.FetchRuleDataAuthority(context.Background(), f.manifest.Version, hashRuleFeedFile(f.appManifest), ruleDataFixtureNow, &authority)
	if err != nil || next.Catalog().Sequence != 2 || !bytes.Equal(appBefore, f.appManifest) || next.CatalogSHA256() == authority.CatalogSHA256() {
		t.Fatalf("independent data update: %v", err)
	}
}

func TestRuleDataChannelClosedSignedProtocol(t *testing.T) {
	for _, scenario := range []string{"wrong-domain", "bad-data-signature", "bad-app-signature", "bad-app-hash", "unknown-key", "duplicate-key", "case-alias", "null", "trailing", "wrong-channel", "zero-sequence", "future-schema", "duplicate-asset", "unknown-asset", "oversize-asset", "future", "expired", "long-ttl", "offset-time", "fractional-time", "old-feed", "future-feed", "oversize-catalog"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRuleDataFixture(t)
			now := ruleDataFixtureNow
			switch scenario {
			case "wrong-channel":
				f.catalog.Channel = "caller-channel"
			case "zero-sequence":
				f.catalog.Sequence = 0
			case "future-schema":
				f.catalog.SchemaVersion = 2
			case "duplicate-asset":
				f.catalog.Feed.Assets[1] = f.catalog.Feed.Assets[0]
			case "unknown-asset":
				f.catalog.Feed.Assets[1].Name = "run.sh"
			case "oversize-asset":
				f.catalog.Feed.Assets[1].Bytes = 9 << 20
			case "future":
				now = now.Add(-3 * time.Hour)
			case "expired":
				now = now.Add(24 * time.Hour)
			case "long-ttl":
				f.catalog.ExpiresAt = "2026-10-13T10:00:00Z"
			case "offset-time":
				f.catalog.PublishedAt = "2026-10-09T11:00:00+01:00"
			case "fractional-time":
				f.catalog.PublishedAt = "2026-10-09T10:00:00.1Z"
			case "old-feed":
				f.catalog.Feed.ID = "et-open-web-20261005"
			case "future-feed":
				f.catalog.Feed.ID = "et-open-web-20261010"
			}
			f.signData()
			switch scenario {
			case "unknown-key":
				f.dataCatalog = append(f.dataCatalog[:len(f.dataCatalog)-1], []byte(",\"url\":\"https://caller.invalid\"}")...)
			case "duplicate-key":
				f.dataCatalog = bytes.Replace(f.dataCatalog, []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":1`), 1)
			case "case-alias":
				f.dataCatalog = bytes.Replace(f.dataCatalog, []byte(`"sequence"`), []byte(`"Sequence"`), 1)
			case "null":
				f.dataCatalog = bytes.Replace(f.dataCatalog, []byte(`"sequence":1`), []byte(`"sequence":null`), 1)
			case "trailing":
				f.dataCatalog = append(f.dataCatalog, []byte(` {}`)...)
			case "oversize-catalog":
				f.dataCatalog = bytes.Repeat([]byte(" "), maxRuleDataCatalogBytes+1)
			}
			f.dataSignature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.private, append([]byte(ruleDataDomain), f.dataCatalog...))))
			switch scenario {
			case "wrong-domain":
				f.dataSignature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.private, f.dataCatalog)))
			case "bad-data-signature":
				f.dataSignature[0] ^= 1
			case "bad-app-signature":
				f.appSignature[0] ^= 1
			case "bad-app-hash":
				f.appManifest = append(f.appManifest, ' ')
			}
			if _, err := f.verify(now, nil); err == nil {
				t.Fatal("unsafe independently signed channel accepted")
			}
		})
	}
}

func TestRuleDataChannelProgressAndDetachedAuthority(t *testing.T) {
	for _, scenario := range []string{"lower-sequence", "same-sequence-rewrite", "older-publication", "older-feed", "unverified-progress", "foreign-progress"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRuleDataFixture(t)
			f.catalog.Sequence = 5
			f.signData()
			previous, err := f.verify(ruleDataFixtureNow, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.catalog.Sequence++
			switch scenario {
			case "lower-sequence":
				f.catalog.Sequence = 4
			case "same-sequence-rewrite":
				f.catalog.Sequence = 5
				f.catalog.ExpiresAt = "2026-10-10T11:00:00Z"
			case "older-publication":
				f.catalog.PublishedAt = "2026-10-09T09:00:00Z"
			case "older-feed":
				f.catalog.Feed.ID = "et-open-web-20261008"
			case "unverified-progress":
				previous = RuleDataAuthority{}
			case "foreign-progress":
				previous.baseURL = "https://foreign.invalid"
			}
			f.signData()
			if _, err := f.verify(ruleDataFixtureNow, &previous); err == nil {
				t.Fatal("damaged or rolled-back channel progress accepted")
			}
		})
	}
	f := newRuleDataFixture(t)
	authority, err := f.verify(ruleDataFixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.dataCatalog[0] ^= 1
	f.appManifest[0] ^= 1
	f.dataSignature[0] ^= 1
	if _, err := f.client.FetchRuleDataEnvelope(context.Background(), authority, ruleDataFixtureNow); err != nil {
		t.Fatalf("verified authority aliases request buffers: %v", err)
	}
}

func TestRuleDataChannelIndependentReceiverRejectsChangedMembers(t *testing.T) {
	for _, name := range []string{"manifest.json", "LICENSE", "BSD-License.txt", "classification.config", "reference.config", "et-open.rules"} {
		t.Run(name, func(t *testing.T) {
			f := newRuleDataFixture(t)
			authority, err := f.verify(ruleDataFixtureNow, nil)
			if err != nil {
				t.Fatal(err)
			}
			in, err := f.client.FetchRuleDataEnvelope(context.Background(), authority, ruleDataFixtureNow)
			if err != nil {
				t.Fatal(err)
			}
			in.Files[name][0] ^= 1
			if _, _, err := f.client.VerifyRuleDataEnvelope(context.Background(), in, f.manifest.Version, hashRuleFeedFile(f.appManifest), f.catalog.Feed.ID, f.catalog.Feed.ManifestSHA256, ruleDataFixtureNow, nil); err == nil {
				t.Fatal("changed data accepted offline")
			}
		})
	}
	for _, scenario := range []string{"feed-choice", "digest-choice", "extra-file", "missing-file", "wrong-key", "cancelled", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRuleDataFixture(t)
			authority, err := f.verify(ruleDataFixtureNow, nil)
			if err != nil {
				t.Fatal(err)
			}
			in, err := f.client.FetchRuleDataEnvelope(context.Background(), authority, ruleDataFixtureNow)
			if err != nil {
				t.Fatal(err)
			}
			feed, digest, now, ctx := f.catalog.Feed.ID, f.catalog.Feed.ManifestSHA256, ruleDataFixtureNow, context.Background()
			switch scenario {
			case "feed-choice":
				feed = "et-open-web-20261008"
			case "digest-choice":
				digest = strings.Repeat("0", 64)
			case "extra-file":
				in.Files["run.sh"] = []byte("ignored")
			case "missing-file":
				delete(in.Files, "LICENSE")
			case "wrong-key":
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				f.client.PublicKey = pub
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "expired":
				now = now.Add(24 * time.Hour)
			}
			if _, _, err := f.client.VerifyRuleDataEnvelope(ctx, in, f.manifest.Version, hashRuleFeedFile(f.appManifest), feed, digest, now, nil); err == nil {
				t.Fatal("receiver accepted invalid binding or context")
			}
		})
	}
}

func TestRuleDataChannelTransportNeverLeaksCookiesOrFollowsRedirect(t *testing.T) {
	f := newRuleDataFixture(t)
	jar, _ := cookiejar.New(nil)
	parsed, _ := url.Parse(f.server.URL)
	jar.SetCookies(parsed, []*http.Cookie{{Name: "own-private-fixture", Value: "not-a-production-secret", Path: "/"}})
	shared := f.client.HTTP
	shared.Jar = jar
	authority, err := f.client.FetchRuleDataAuthority(context.Background(), f.manifest.Version, hashRuleFeedFile(f.appManifest), ruleDataFixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.FetchRuleDataEnvelope(context.Background(), authority, ruleDataFixtureNow); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range f.cookies {
		if cookie != "" {
			t.Fatal("session cookie leaked to rules repository")
		}
	}
	if shared.Jar != jar || shared.CheckRedirect != nil || len(jar.Cookies(parsed)) != 1 {
		t.Fatal("shared transport mutated")
	}
	foreignCalls := 0
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignCalls++; w.Write([]byte("wrong repository")) }))
	defer foreign.Close()
	f.redirect = foreign.URL
	if _, err := f.client.FetchRuleDataAuthority(context.Background(), f.manifest.Version, hashRuleFeedFile(f.appManifest), ruleDataFixtureNow, nil); err == nil || foreignCalls != 0 {
		t.Fatal("redirect widened repository scope")
	}
	if _, err := f.client.FetchRuleDataEnvelope(context.Background(), authority, ruleDataFixtureNow.Add(24*time.Hour)); err == nil {
		t.Fatal("expired authority downloaded data")
	}
	if _, err := f.client.FetchRuleDataEnvelope(context.Background(), RuleDataAuthority{}, ruleDataFixtureNow); err == nil {
		t.Fatal("caller-assembled authority accepted")
	}
}

func TestRuleDataChannelAppDeclaresOnlyClosedABI(t *testing.T) {
	for _, scenario := range []string{"another-app", "provider", "target", "inline-conflict", "wrong-id", "wrong-format", "wrong-engine"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRuleDataFixture(t)
			m := f.manifest
			switch scenario {
			case "another-app":
				m.ID = "nginx-waf"
			case "provider":
				m.Delivery.Provider = "compose"
			case "target":
				m.Delivery.Target = "nginx-waf"
			case "inline-conflict":
				m.RuleFeeds = []RuleFeed{f.catalog.Feed}
			case "wrong-id":
				m.RuleDataChannel.ID = "caller-path"
			case "wrong-format":
				m.RuleDataChannel.Format = 2
			case "wrong-engine":
				m.RuleDataChannel.Engine = "suricata-7"
			}
			if err := validateRuleFeeds(m); err == nil {
				t.Fatal("unsupported data ABI declaration accepted")
			}
		})
	}
}

func TestRuleDataChannelRetainedHistoryIsNotFreshInstallAuthority(t *testing.T) {
	f := newRuleDataFixture(t)
	late := ruleDataFixtureNow.Add(7 * 24 * time.Hour)
	if _, err := f.verify(late, nil); err == nil {
		t.Fatal("expired catalog still fresh")
	}
	history, err := f.client.VerifyRetainedRuleDataAuthority(f.appCatalog, f.appSignature, f.appManifest, f.dataCatalog, f.dataSignature, f.manifest.Version, hashRuleFeedFile(f.appManifest), late)
	if err != nil || history.Catalog().Sequence != 1 {
		t.Fatalf("valid signed history lost: %v", err)
	}
	if _, err := f.client.FetchRuleDataEnvelope(context.Background(), history, late); err == nil {
		t.Fatal("expired history downloaded data")
	}
	if len(f.requests) != 0 {
		t.Fatal("history verification made a network request")
	}
	f.dataSignature[0] ^= 1
	if _, err := f.client.VerifyRetainedRuleDataAuthority(f.appCatalog, f.appSignature, f.appManifest, f.dataCatalog, f.dataSignature, f.manifest.Version, hashRuleFeedFile(f.appManifest), late); err == nil {
		t.Fatal("history accepted caller trust claim")
	}
}

func TestRuleDataChannelLegacyCarrierHasIndependentDualSignatures(t *testing.T) {
	f := newRuleDataFixture(t)
	authority, err := f.verify(ruleDataFixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := f.client.FetchRuleDataEnvelope(context.Background(), authority, ruleDataFixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	in := RuleFeedEnvelope{Catalog: data.AppCatalog, Signature: data.AppSignature, AppManifest: data.AppManifest, FeedID: f.catalog.Feed.ID, Files: data.Files, DataCatalog: data.DataCatalog, DataSignature: data.DataSignature}
	raw, _ := json.Marshal(in)
	decoded, err := DecodeRuleFeedEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, bundle, err := f.client.VerifyRuleFeedEnvelopeAt(context.Background(), decoded, f.manifest.Version, hashRuleFeedFile(f.appManifest), ruleDataFixtureNow); err != nil || bundle == nil {
		t.Fatalf("unified carrier: %v", err)
	}
	for _, scenario := range []string{"missing-signature", "empty-signature", "unknown-field", "data-signature", "data-catalog", "app-signature"} {
		t.Run(scenario, func(t *testing.T) {
			var fields map[string]json.RawMessage
			json.Unmarshal(raw, &fields)
			switch scenario {
			case "missing-signature":
				delete(fields, "rule_data_signature")
			case "empty-signature":
				fields["rule_data_signature"] = json.RawMessage(`""`)
			case "unknown-field":
				fields["public_key"] = json.RawMessage(`"caller-key"`)
			case "data-signature":
				fields["rule_data_signature"], _ = json.Marshal([]byte("not-a-signature"))
			case "data-catalog":
				fields["rule_data_catalog"], _ = json.Marshal([]byte(`{}`))
			case "app-signature":
				fields["signature"], _ = json.Marshal([]byte("not-an-app-signature"))
			}
			changed, _ := json.Marshal(fields)
			candidate, err := DecodeRuleFeedEnvelope(changed)
			if err == nil {
				_, _, err = f.client.VerifyRuleFeedEnvelopeAt(context.Background(), candidate, f.manifest.Version, hashRuleFeedFile(f.appManifest), ruleDataFixtureNow)
			}
			if err == nil {
				t.Fatal("unified carrier accepted damaged dual-signature authority")
			}
		})
	}
}

func TestRuleDataChannelExplicitCarrierDownloadPreservesAppAndDataBinding(t *testing.T) {
	f := newRuleDataFixture(t)
	in, err := f.client.FetchRuleFeedEnvelopeAt(context.Background(), f.manifest.Version, hashRuleFeedFile(f.appManifest), f.catalog.Feed.ID, ruleDataFixtureNow)
	if err != nil || len(f.requests) != 9 || len(in.Files) != 6 || len(in.DataCatalog) == 0 || len(in.DataSignature) == 0 {
		t.Fatalf("explicit carrier download: %v requests %v", err, f.requests)
	}
	if _, _, err := f.client.VerifyRuleFeedEnvelopeAt(context.Background(), in, f.manifest.Version, hashRuleFeedFile(f.appManifest), ruleDataFixtureNow); err != nil {
		t.Fatal(err)
	}
	f.requests = nil
	if _, err := f.client.FetchRuleFeedEnvelopeAt(context.Background(), f.manifest.Version, hashRuleFeedFile(f.appManifest), "et-open-web-20261008", ruleDataFixtureNow); err == nil || len(f.requests) != 3 {
		t.Fatal("changed data selection fetched assets")
	}
}
