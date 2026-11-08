//go:build linux

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
	"strings"
	"testing"
	"time"

	"local/panel/internal/geodata"
)

func geoChannelFixture(t *testing.T) (*Client, GeoDataEnvelope, ed25519.PrivateKey, string, []byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := panelRequirementFixture()
	m.Version = "2.6.0"
	m.RequiredPanelFeatures = []string{StatisticsCursorRetirementFeature, StatisticsRequestIdentityFeature, StatisticsGeographyFeature}
	m.GeoDataChannel = &GeoDataChannel{ID: geodata.Channel, Format: 1}
	manifest, _ := json.Marshal(m)
	sha := hashRuleFeedFile(manifest)
	c := &Client{BaseURL: "https://owned-geo-fixture.invalid", PublicKey: pub}
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: c.BaseURL + "/dist/apps/website-statistics-v2/2.6.0/manifest.json", SHA256: sha}
	catalog, _ := json.Marshal(Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-13T00:00:00Z", Apps: []CatalogItem{item}})
	payload := []byte("explicit synthetic download bytes; not a valid city database")
	data := geodata.Manifest{Format: 1, Channel: geodata.Channel, Release: "2026-10", BuildEpoch: 1790818881, CompressedBytes: int64(len(payload)), CompressedSHA256: hashRuleFeedFile(payload), Bytes: 1, SHA256: strings.Repeat("a", 64), Source: "https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz", License: geodata.LicenseURL, AttributionURL: geodata.AttributionURL}
	raw, _ := json.Marshal(data)
	signed := func(b []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))) }
	return c, GeoDataEnvelope{catalog, signed(catalog), manifest, raw, signed(append([]byte(geodata.SignatureDomain), raw...))}, key, sha, payload
}
func TestGeoDataDoubleSignaturesBindingsAndDetachedAuthority(t *testing.T) {
	c, in, _, sha, _ := geoChannelFixture(t)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	a, err := c.VerifyGeoDataEnvelope(in, "2.6.0", sha, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Data().Manifest().Release != "2026-10" || a.AppSHA256() != sha || a.AppVersion() != "2.6.0" {
		t.Fatal("bad authority")
	}
	if _, err := c.VerifyGeoDataEnvelope(in, "2.6.0", sha, now, &a); err != nil {
		t.Fatal("same signed data cannot replay", err)
	}
	for _, kind := range []string{"app-catalog", "app-signature", "app-manifest", "data-manifest", "data-signature", "version", "app-sha", "key"} {
		t.Run(kind, func(t *testing.T) {
			changed := cloneGeoEnvelope(in)
			client := Client{BaseURL: c.BaseURL, PublicKey: bytes.Clone(c.PublicKey)}
			v, digest := "2.6.0", sha
			switch kind {
			case "app-catalog":
				changed.AppCatalog[0] ^= 1
			case "app-signature":
				changed.AppSignature[0] ^= 1
			case "app-manifest":
				changed.AppManifest[0] ^= 1
			case "data-manifest":
				changed.DataManifest[0] ^= 1
			case "data-signature":
				changed.DataSignature[0] ^= 1
			case "version":
				v = "2.5.0"
			case "app-sha":
				digest = strings.Repeat("0", 64)
			case "key":
				client.PublicKey = make(ed25519.PublicKey, 32)
			}
			if _, err := client.VerifyGeoDataEnvelope(changed, v, digest, now, nil); err == nil {
				t.Fatal("signature or app binding bypassed")
			}
		})
	}
	copy := a.Envelope()
	copy.AppCatalog[0] ^= 1
	in.DataManifest[0] ^= 1
	if !bytes.Equal(a.Envelope().AppCatalog, a.envelope.AppCatalog) || !bytes.Equal(a.Envelope().DataManifest, a.envelope.DataManifest) {
		t.Fatal("authority aliases exported envelope")
	}
}

type geoTransportFunc func(*http.Request) (*http.Response, error)

func (f geoTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestGeoDataDownloaderFixedSourceNoCookieRedirectOrEncodingAndBounds(t *testing.T) {
	c, in, _, sha, payload := geoChannelFixture(t)
	a, err := c.VerifyGeoDataEnvelope(in, "2.6.0", sha, time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"valid", "redirect", "error-status", "encoding", "wrong-length", "truncated", "extra", "wrong-hash", "write-error"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			c.HTTP = &http.Client{Timeout: 12 * time.Second, Transport: geoTransportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) < 235*time.Second || time.Until(deadline) > 240*time.Second {
					t.Fatal("large dataset inherited short catalog timeout", deadline)
				}
				if r.Method != "GET" || r.URL.String() != a.Data().Manifest().Source || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Fatal("untrusted URL or credentials", r.URL, r.Header)
				}
				body := bytes.Clone(payload)
				status := 200
				header := http.Header{}
				length := int64(len(body))
				switch kind {
				case "redirect":
					status = 302
					header.Set("Location", "https://evil.invalid/")
				case "error-status":
					status = 404
				case "encoding":
					header.Set("Content-Encoding", "gzip")
				case "wrong-length":
					length++
				case "truncated":
					body = body[:len(body)-1]
					length = -1
				case "extra":
					body = append(body, 1)
					length = -1
				case "wrong-hash":
					body[0] ^= 1
				}
				return &http.Response{StatusCode: status, Header: header, ContentLength: length, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
			})}
			var output bytes.Buffer
			var w io.Writer = &output
			if kind == "write-error" {
				w = geoBadWriter{}
			}
			err := c.DownloadGeoDatabase(context.Background(), a, w)
			if c.HTTP.Timeout != 12*time.Second {
				t.Fatal("download changed shared catalog timeout")
			}
			if (err == nil) != (kind == "valid") || calls != 1 {
				t.Fatal("failed response accepted or redirect followed", kind, calls, err)
			}
			if kind == "valid" && !bytes.Equal(output.Bytes(), payload) {
				t.Fatal("download bytes changed")
			}
		})
	}
}

type geoBadWriter struct{}

func (geoBadWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestGeoRepositorySelectionOnlyFetchesOriginalSigningMaterial(t *testing.T) {
	c, in, _, _, _ := geoChannelFixture(t)
	calls := []string{}
	c.HTTP = &http.Client{Transport: geoTransportFunc(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.String())
		var data []byte
		if r.URL.Scheme != "https" || r.URL.Host != "owned-geo-fixture.invalid" {
			t.Fatal("signing material host changed", r.URL)
		}
		for key := range r.URL.Query() {
			if key != "check" {
				t.Fatal("unexpected fetch query", r.URL)
			}
		}
		switch r.URL.Path {
		case "/signatures/catalog-v1.bundle.json":
			data, _ = json.Marshal(map[string]string{"catalog": string(in.AppCatalog), "signature": string(in.AppSignature)})
		case "/dist/apps/website-statistics-v2/2.6.0/manifest.json":
			data = in.AppManifest
		case "/data/geodata/" + geodata.Channel + "/catalog.signed.json":
			data, _ = json.Marshal(map[string]string{"manifest": string(in.DataManifest), "signature": string(in.DataSignature)})
		default:
			t.Fatal("small material fetch contacted dataset or arbitrary source", r.URL)
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Fatal("signing-material request carries credentials")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data)), Request: r}, nil
	})}
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	envelope, a, err := c.FetchGeoDataEnvelope(context.Background(), "", now)
	if err != nil || a.Data().Manifest().Release != "2026-10" || !bytes.Equal(envelope.DataManifest, in.DataManifest) || len(calls) != 3 {
		t.Fatal("fresh authority fetch failed", a.Data().Manifest(), calls, err)
	}
	if _, _, err = c.FetchGeoDataEnvelope(context.Background(), strings.Repeat("0", 64), now); err == nil {
		t.Fatal("changed preview silently replaced old selection")
	}
}
