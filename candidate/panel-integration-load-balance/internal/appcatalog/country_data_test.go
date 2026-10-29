package appcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"local/panel/internal/geodata"
)

// Explicitly synthetic availability isolates ABI/crypto/transport tests. The
// production feature remains UNAVAILABLE until the Root lifecycle is complete.
func countryChannelFixture(t *testing.T) (*Client, GeoDataEnvelope, string, []byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(raw []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))) }
	m := panelRequirementFixture()
	m.ID = "nginx-waf"
	m.Name = "Synthetic country WAF"
	m.Version = "2.6.0"
	m.Delivery = Delivery{Provider: "panel-module", Target: m.ID, ManageRoute: "security"}
	m.RequiredPanelFeatures = []string{CountryDataFeature}
	m.GeoDataChannel = nil
	m.CountryDataChannel = &GeoDataChannel{ID: geodata.CountryChannel, Format: 1}
	manifest, _ := json.Marshal(m)
	appSHA := hashRuleFeedFile(manifest)
	c := &Client{BaseURL: "https://owned-country-fixture.invalid", PublicKey: pub}
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: c.BaseURL + "/dist/apps/nginx-waf/2.6.0/manifest.json", SHA256: appSHA}
	catalog, _ := json.Marshal(Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-20T00:00:00Z", Apps: []CatalogItem{item}})
	parent := geodata.Manifest{Format: 1, Channel: geodata.Channel, Release: "2026-10", BuildEpoch: 1790818881, CompressedBytes: 1, CompressedSHA256: strings.Repeat("b", 64), Bytes: 1, SHA256: strings.Repeat("a", 64), Source: "https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz", License: geodata.LicenseURL, AttributionURL: geodata.AttributionURL}
	parentRaw, _ := json.Marshal(parent)
	parentSig := sign(append([]byte(geodata.SignatureDomain), parentRaw...))
	var payload bytes.Buffer
	metadata, err := geodata.EncodeCountryCIDR(context.Background(), geodata.CountryNetworkExport{ManifestSHA256: hashRuleFeedFile(parentRaw), DatabaseSHA256: parent.SHA256, RecordsVisited: 1, Networks: []geodata.CountryNetwork{{Prefix: netip.MustParsePrefix("8.8.8.0/24"), CountryCode: "US"}}}, &payload)
	if err != nil {
		t.Fatal(err)
	}
	assets, _ := json.Marshal([]geodata.CountryAsset{{Code: "US", Bytes: metadata.Bytes, SHA256: metadata.SHA256, Networks: 1}})
	data, _ := json.Marshal(geodata.CountryManifest{Format: 1, Channel: geodata.CountryChannel, Release: parent.Release, Revision: 1, BuildEpoch: parent.BuildEpoch, ParentManifest: string(parentRaw), ParentSignature: string(parentSig), GeneratorSHA256: strings.Repeat("c", 64), AssetsJSON: string(assets), Bytes: metadata.Bytes, Networks: 1, License: geodata.LicenseURL, AttributionURL: geodata.AttributionURL})
	return c, GeoDataEnvelope{catalog, sign(catalog), manifest, data, sign(append([]byte(geodata.CountrySignatureDomain), data...))}, appSHA, payload.Bytes()
}

func countryFixtureAuthority(t *testing.T, c *Client, in GeoDataEnvelope, appSHA string) CountryDataAuthority {
	t.Helper()
	a, err := c.verifyCountryDataEnvelope(in, "2.6.0", appSHA, time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), nil, func(f string) bool { return f == CountryDataFeature })
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCountryChannelClosedABIAndProductionUnavailableUntilRootLifecycle(t *testing.T) {
	c, in, sha, _ := countryChannelFixture(t)
	a := countryFixtureAuthority(t, c, in, sha)
	if a.AppVersion() != "2.6.0" || a.AppSHA256() != sha {
		t.Fatal("application binding differs")
	}
	if panelFeatureAvailable(CountryDataFeature) {
		t.Fatal("partial country implementation prematurely advertised")
	}
	if got, err := c.VerifyCountryDataEnvelope(in, "2.6.0", sha, time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), nil); err == nil || !reflect.DeepEqual(got, CountryDataAuthority{}) {
		t.Fatal("production accepted unfinished Root capability", got, err)
	}
	var m Manifest
	if json.Unmarshal(in.AppManifest, &m) != nil {
		t.Fatal("fixture")
	}
	if validateCountryDataChannel(m) != nil {
		t.Fatal("valid data-only fixture channel rejected")
	}
	for _, kind := range []string{"old", "alias", "future", "other-app", "provider", "target", "route", "channel", "format", "missing", "feature", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			v := m
			channel := *m.CountryDataChannel
			v.CountryDataChannel = &channel
			v.RequiredPanelFeatures = append([]string(nil), m.RequiredPanelFeatures...)
			switch kind {
			case "old":
				v.Version = "2.5.1"
			case "alias":
				v.Version = "2.6.0-build"
			case "future":
				v.Version = "2.7.0"
			case "other-app":
				v.ID = "apache-waf"
			case "provider":
				v.Delivery.Provider = "runtime"
			case "target":
				v.Delivery.Target = "apache-waf"
			case "route":
				v.Delivery.ManageRoute = "app-modules"
			case "channel":
				v.CountryDataChannel.ID = geodata.Channel
			case "format":
				v.CountryDataChannel.Format = 2
			case "missing":
				v.CountryDataChannel = nil
			case "feature":
				v.RequiredPanelFeatures = nil
			case "duplicate":
				v.RequiredPanelFeatures = append(v.RequiredPanelFeatures, CountryDataFeature)
			}
			if validateCountryDataChannel(v) == nil {
				t.Fatal("unimplemented/borrowed channel accepted", kind)
			}
		})
	}
}

func TestCountryEnvelopeBindsAllThreeSignaturesAndNeverAliasesCallerMaterials(t *testing.T) {
	c, in, sha, _ := countryChannelFixture(t)
	a := countryFixtureAuthority(t, c, in, sha)
	for _, kind := range []string{"app-catalog", "app-signature", "app-manifest", "data-manifest", "data-signature", "app-sha", "version", "key"} {
		t.Run(kind, func(t *testing.T) {
			v := cloneGeoEnvelope(in)
			client := &Client{BaseURL: c.BaseURL, PublicKey: bytes.Clone(c.PublicKey), HTTP: c.HTTP}
			version, digest := "2.6.0", sha
			switch kind {
			case "app-catalog":
				v.AppCatalog[0] ^= 1
			case "app-signature":
				v.AppSignature[0] ^= 1
			case "app-manifest":
				v.AppManifest[0] ^= 1
			case "data-manifest":
				v.DataManifest[0] ^= 1
			case "data-signature":
				v.DataSignature[0] ^= 1
			case "app-sha":
				digest = strings.Repeat("0", 64)
			case "version":
				version = "2.5.1"
			case "key":
				client.PublicKey = make(ed25519.PublicKey, 32)
			}
			got, err := client.verifyCountryDataEnvelope(v, version, digest, time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), nil, func(string) bool { return true })
			if err == nil || !reflect.DeepEqual(got, CountryDataAuthority{}) {
				t.Fatal("country authority escaped exact crypto/app binding", got, err)
			}
		})
	}
	copy := a.Envelope()
	copy.AppCatalog[0] ^= 1
	copy.DataManifest[0] ^= 1
	if bytes.Equal(copy.AppCatalog, a.Envelope().AppCatalog) || bytes.Equal(copy.DataManifest, a.Envelope().DataManifest) {
		t.Fatal("caller changed verified authority")
	}
}

type countryTransportFunc func(*http.Request) (*http.Response, error)

func (f countryTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCountryDownloaderFixedOriginNoCookiesNoRedirectNoResumeAndExactVerifiedFile(t *testing.T) {
	for _, kind := range []string{"valid", "unknown-length", "redirect", "error-status", "encoding", "duplicate-encoding", "wrong-length", "truncated", "extra", "wrong-hash", "occupied", "public-mode", "wrong-position", "wrong-key", "unknown-country", "no-authority"} {
		t.Run(kind, func(t *testing.T) {
			c, in, appSHA, payload := countryChannelFixture(t)
			a := countryFixtureAuthority(t, c, in, appSHA)
			calls := 0
			c.HTTP = &http.Client{Timeout: 12 * time.Second, Transport: countryTransportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				expected := c.BaseURL + "/data/geodata/" + geodata.CountryChannel + "/releases/2026-10-r1-" + a.Data().SHA256() + "/US.cidr"
				if r.URL.String() != expected || r.Method != "GET" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Range") != "" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("source/privacy/range boundary changed")
				}
				if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > 60*time.Second || time.Until(deadline) < 55*time.Second {
					t.Error("bounded shared download context missing")
				}
				body := bytes.Clone(payload)
				status := 200
				length := int64(len(body))
				headers := http.Header{}
				switch kind {
				case "unknown-length":
					length = -1
				case "redirect":
					status = 302
					headers.Set("Location", "https://foreign.invalid/cookie")
				case "error-status":
					status = 503
				case "encoding":
					headers.Set("Content-Encoding", "gzip")
				case "duplicate-encoding":
					headers["Content-Encoding"] = []string{"identity", "gzip"}
				case "wrong-length":
					length++
				case "truncated":
					body = body[:len(body)-1]
				case "extra":
					body = append(body, '\n')
				case "wrong-hash":
					body[len(body)-2] ^= 1
				}
				return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: length, Request: r}, nil
			})}
			jar, _ := cookiejar.New(nil)
			origin, _ := url.Parse(c.BaseURL)
			jar.SetCookies(origin, []*http.Cookie{{Name: "private", Value: "must-not-send"}})
			c.HTTP.Jar = jar
			file, err := os.OpenFile(filepath.Join(t.TempDir(), "new-shard.cidr"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			code := "US"
			switch kind {
			case "occupied":
				file.Write([]byte("retained original"))
			case "public-mode":
				file.Chmod(0644)
			case "wrong-position":
				file.Seek(4096, io.SeekStart)
			case "wrong-key":
				c.PublicKey = make(ed25519.PublicKey, 32)
			case "unknown-country":
				code = "CN"
			case "no-authority":
				a = CountryDataAuthority{}
			}
			err = c.DownloadCountryAssetFile(context.Background(), a, code, file)
			success := kind == "valid" || kind == "unknown-length"
			if (err == nil) != success {
				t.Fatal("unexpected country download acceptance", kind, err)
			}
			if calls > 1 {
				t.Fatal("partial/ambiguous download silently retried", calls)
			}
			if success {
				file.Seek(0, io.SeekStart)
				raw, _ := io.ReadAll(file)
				if !bytes.Equal(raw, payload) || calls != 1 {
					t.Fatal("accepted file differs from exact authenticated bytes")
				}
			}
			if kind == "occupied" {
				file.Seek(0, io.SeekStart)
				raw, _ := io.ReadAll(file)
				if string(raw) != "retained original" || calls != 0 {
					t.Fatal("old staging file overwritten")
				}
			}
			if kind == "wrong-position" {
				info, _ := file.Stat()
				if calls != 0 || info.Size() != 0 {
					t.Fatal("offset created an unbounded sparse destination")
				}
			}
		})
	}
}
