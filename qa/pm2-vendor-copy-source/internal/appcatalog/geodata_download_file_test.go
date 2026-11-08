package appcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"local/panel/internal/geodata"
)

// Independent portable synthetic authority; no original/private release keys.
func geoFileChannelFixture(t *testing.T) (*Client, GeoDataEnvelope, ed25519.PrivateKey, string, []byte) {
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
	appSHA := hashRuleFeedFile(manifest)
	c := &Client{BaseURL: "https://owned-geo-file-fixture.invalid", PublicKey: pub}
	item := CatalogItem{ID: m.ID, Name: m.Name, Category: m.Category, Version: m.Version, Summary: m.Summary, Stage: m.Stage, Risk: m.Risk, Provider: m.Delivery.Provider, Target: m.Delivery.Target, ManageRoute: m.Delivery.ManageRoute, Capabilities: m.Capabilities, PackageURL: c.BaseURL + "/dist/apps/website-statistics-v2/2.6.0/manifest.json", SHA256: appSHA}
	catalog, _ := json.Marshal(Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-13T00:00:00Z", Apps: []CatalogItem{item}})
	payload := []byte("explicit synthetic parallel transfer; not a valid city database")
	data := geodata.Manifest{Format: 1, Channel: geodata.Channel, Release: "2026-10", BuildEpoch: 1790818881, CompressedBytes: int64(len(payload)), CompressedSHA256: hashRuleFeedFile(payload), Bytes: 1, SHA256: strings.Repeat("a", 64), Source: "https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz", License: geodata.LicenseURL, AttributionURL: geodata.AttributionURL}
	raw, _ := json.Marshal(data)
	signed := func(b []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))) }
	return c, GeoDataEnvelope{catalog, signed(catalog), manifest, raw, signed(append([]byte(geodata.SignatureDomain), raw...))}, key, appSHA, payload
}

type geoFileTransportFunc func(*http.Request) (*http.Response, error)

func (f geoFileTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func geoFileTransportAuthority(t *testing.T, c *Client, in GeoDataEnvelope, appSHA string) GeoDataAuthority {
	t.Helper()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	if runtime.GOOS == "linux" {
		// Native conformance MUST use the actual closed application ABI and
		// double signature checks. There is no production OS-check exemption.
		a, err := c.VerifyGeoDataEnvelope(in, "2.6.0", appSHA, now, nil)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	// Portable race tests isolate transport/file concurrency only. The real
	// application feature is intentionally Linux-only. An explicitly synthetic
	// in-package fixture cannot prove app authorization, native installation or
	// signed50 ABI acceptance; all of those have separate actual Linux gates.
	data, err := geodata.VerifyManifest(in.DataManifest, in.DataSignature, c.PublicKey, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GeoDataAuthority{data: data, appVersion: "2.6.0", appSHA: appSHA, keySHA: hashRuleFeedFile(c.PublicKey), envelope: cloneGeoEnvelope(in), verified: true}
}

func geoDownloadFreshFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "new-private-staging.gz"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestGeoDataFileDownloaderStrictRangesFallbackAndFullSignedHash(t *testing.T) {
	for _, mode := range []string{"valid", "unknown-length", "full-fallback", "full-fallback-range", "bad-first-range", "duplicate-range", "wrong-total", "late-range", "late-status", "wrong-length", "truncated", "extra", "wrong-hash", "encoded", "duplicate-encoding", "uncompressed", "multipart", "redirect", "network-error"} {
		t.Run(mode, func(t *testing.T) {
			c, envelope, _, appSHA, payload := geoFileChannelFixture(t)
			a := geoFileTransportAuthority(t, c, envelope, appSHA)
			var calls atomic.Int32
			c.HTTP = &http.Client{Timeout: 12 * time.Second, Transport: geoFileTransportFunc(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) < 235*time.Second || time.Until(deadline) > 240*time.Second {
					t.Error("unchanged shared download deadline missing")
				}
				if r.URL.String() != a.Data().Manifest().Source || r.Method != "GET" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("source or privacy boundary changed")
				}
				var start, end int64
				if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil || start < 0 || end < start || end >= int64(len(payload)) {
					t.Error("unbounded range")
					return nil, io.ErrUnexpectedEOF
				}
				body := bytes.Clone(payload[start : end+1])
				status := 206
				length := int64(len(body))
				header := http.Header{"Content-Range": {fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload))}}
				uncompressed := false
				switch mode {
				case "unknown-length":
					length = -1
				case "full-fallback", "full-fallback-range":
					status = 200
					body = bytes.Clone(payload)
					length = int64(len(body))
					if mode == "full-fallback" {
						header.Del("Content-Range")
					}
				case "bad-first-range":
					header.Set("Content-Range", "bytes 1-2/3")
				case "duplicate-range":
					header.Add("Content-Range", header.Get("Content-Range"))
				case "wrong-total":
					header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/*", start, end))
				case "late-range":
					if start > 0 {
						header.Set("Content-Range", "bytes 0-0/1")
					}
				case "late-status":
					if start > 0 {
						status = 200
					}
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
				case "encoded":
					header.Set("Content-Encoding", "gzip")
				case "duplicate-encoding":
					header["Content-Encoding"] = []string{"identity", "gzip"}
				case "uncompressed":
					uncompressed = true
				case "multipart":
					header.Set("Content-Type", "multipart/byteranges; boundary=not-supported")
				case "redirect":
					status = 302
					header.Set("Location", "https://untrusted.invalid/")
				case "network-error":
					return nil, io.ErrUnexpectedEOF
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: length, Uncompressed: uncompressed, Request: r}, nil
			})}
			jar, _ := cookiejar.New(nil)
			request, _ := http.NewRequest("GET", a.Data().Manifest().Source, nil)
			jar.SetCookies(request.URL, []*http.Cookie{{Name: "never-send", Value: "private"}})
			c.HTTP.Jar = jar
			file := geoDownloadFreshFile(t)
			err := c.DownloadGeoDatabaseFile(context.Background(), a, file)
			valid := mode == "valid" || mode == "unknown-length" || mode == "full-fallback"
			if (err == nil) != valid {
				t.Fatal("wrong result", mode, err)
			}
			if calls.Load() < 1 || calls.Load() > 4 || mode == "full-fallback" && calls.Load() != 1 {
				t.Fatal("request budget", calls.Load())
			}
			if mode == "valid" || mode == "unknown-length" {
				if calls.Load() != 4 {
					t.Fatal("missing exact four segments")
				}
			}
			if c.HTTP.Timeout != 12*time.Second || c.HTTP.Jar != jar {
				t.Fatal("mutated shared catalog transport")
			}
			if valid {
				raw, e := os.ReadFile(file.Name())
				if e != nil || !bytes.Equal(raw, payload) {
					t.Fatal("assembled bytes differ", e)
				}
			}
		})
	}
}

type geoDownloadGateBody struct {
	reader io.Reader
	gate   <-chan struct{}
	ctx    context.Context
	closed *atomic.Int32
}

func (b *geoDownloadGateBody) Read(p []byte) (int, error) {
	select {
	case <-b.gate:
		return b.reader.Read(p)
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	}
}
func (b *geoDownloadGateBody) Close() error { b.closed.Add(1); return nil }

func TestGeoDataFileDownloaderFourDisjointWorkersJoinAndNeverOverwritePartial(t *testing.T) {
	c, in, _, appSHA, payload := geoFileChannelFixture(t)
	a := geoFileTransportAuthority(t, c, in, appSHA)
	var calls, closed atomic.Int32
	gate := make(chan struct{})
	var once sync.Once
	var lock sync.Mutex
	ranges := [][2]int64{}
	c.HTTP = &http.Client{Transport: geoFileTransportFunc(func(r *http.Request) (*http.Response, error) {
		var start, end int64
		fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end)
		lock.Lock()
		ranges = append(ranges, [2]int64{start, end})
		lock.Unlock()
		if calls.Add(1) == 4 {
			once.Do(func() { close(gate) })
		}
		return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": {fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload))}}, ContentLength: end - start + 1, Body: &geoDownloadGateBody{bytes.NewReader(payload[start : end+1]), gate, r.Context(), &closed}, Request: r}, nil
	})}
	file := geoDownloadFreshFile(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.DownloadGeoDatabaseFile(ctx, a, file); err != nil {
		t.Fatal("workers did not overlap", err)
	}
	if calls.Load() != 4 || closed.Load() != 4 {
		t.Fatal("workers not all closed/joined", calls.Load(), closed.Load())
	}
	covered := make([]bool, len(payload))
	for _, s := range ranges {
		for i := s[0]; i <= s[1]; i++ {
			if covered[i] {
				t.Fatal("overlap")
			}
			covered[i] = true
		}
	}
	for _, v := range covered {
		if !v {
			t.Fatal("gap")
		}
	}
	before, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.DownloadGeoDatabaseFile(context.Background(), a, file); err == nil {
		t.Fatal("existing bytes adopted/overwritten")
	}
	after, _ := os.ReadFile(file.Name())
	if !bytes.Equal(before, after) || calls.Load() != 4 {
		t.Fatal("old partial/release bytes changed or new HTTP started")
	}
}

func TestGeoDataFileDownloaderCanceledOrUnsafeDestinationMakesNoRequest(t *testing.T) {
	for _, mode := range []string{"cancelled", "nonempty", "wrong-mode", "closed", "nil-file", "nil-context"} {
		t.Run(mode, func(t *testing.T) {
			c, in, _, appSHA, _ := geoFileChannelFixture(t)
			a := geoFileTransportAuthority(t, c, in, appSHA)
			calls := 0
			c.HTTP = &http.Client{Transport: geoFileTransportFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, io.ErrUnexpectedEOF })}
			file := geoDownloadFreshFile(t)
			ctx := context.Background()
			switch mode {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nonempty":
				file.WriteString("original remains")
			case "wrong-mode":
				file.Chmod(0644)
			case "closed":
				file.Close()
			case "nil-file":
				file = nil
			case "nil-context":
				ctx = nil
			}
			if err := c.DownloadGeoDatabaseFile(ctx, a, file); err == nil || calls != 0 {
				t.Fatal("unsafe/cancelled request", err, calls)
			}
			if mode == "nonempty" {
				raw, _ := os.ReadFile(file.Name())
				if string(raw) != "original remains" {
					t.Fatal("overwrote original")
				}
			}
		})
	}
}

func TestGeoDataFileDownloaderCancellationClosesAllStartedWorkers(t *testing.T) {
	c, in, _, appSHA, payload := geoFileChannelFixture(t)
	a := geoFileTransportAuthority(t, c, in, appSHA)
	var calls, closed atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	gate := make(chan struct{})
	c.HTTP = &http.Client{Transport: geoFileTransportFunc(func(r *http.Request) (*http.Response, error) {
		var start, end int64
		fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end)
		if calls.Add(1) == 4 {
			cancel()
		}
		return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": {fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload))}}, ContentLength: end - start + 1, Body: &geoDownloadGateBody{strings.NewReader(""), gate, r.Context(), &closed}, Request: r}, nil
	})}
	if err := c.DownloadGeoDatabaseFile(ctx, a, geoDownloadFreshFile(t)); err == nil || calls.Load() != 4 || closed.Load() != 4 {
		t.Fatal("cancellation did not join/close original workers", err, calls.Load(), closed.Load())
	}
}
