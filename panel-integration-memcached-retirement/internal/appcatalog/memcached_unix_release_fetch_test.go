package appcatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMemcachedUnixFetchExactSignedBytesWithoutCookiesRedirectsImagesOrArchives(t *testing.T) {
	var catalogs, manifests, other atomic.Int64
	var redirect, large atomic.Bool
	var envelope MemcachedUnixReleaseEnvelope
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			other.Add(1)
		}
		switch r.URL.Path {
		case "/signatures/catalog-v1.bundle.json":
			catalogs.Add(1)
			json.NewEncoder(w).Encode(catalogBundle{Catalog: string(envelope.Catalog), Signature: string(envelope.Signature)})
		case "/dist/apps/memcached/" + MemcachedUnixVersion + "/manifest.json":
			manifests.Add(1)
			if redirect.Load() {
				http.Redirect(w, r, "/not-allowed", http.StatusFound)
				return
			}
			if large.Load() {
				w.Write([]byte(strings.Repeat("x", maxManifestBytes+1)))
				return
			}
			w.Write(envelope.AppManifest)
		default:
			other.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, in := memcachedUnixEnvelopeFixtureAt(t, server.URL, nil)
	envelope = in
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(server.URL)
	jar.SetCookies(u, []*http.Cookie{{Name: "panel-session", Value: "own-fixture-must-not-leave-panel"}})
	client.HTTP = server.Client()
	client.HTTP.Jar = jar
	digest := hashRuleFeedFile(in.AppManifest)
	got, err := client.fetchMemcachedUnixReleaseEnvelope(context.Background(), MemcachedUnixVersion, digest, memcachedUnixEnvelopeFixtureHandlers)
	if err != nil || !bytes.Equal(got.Catalog, in.Catalog) || !bytes.Equal(got.Signature, in.Signature) || !bytes.Equal(got.AppManifest, in.AppManifest) {
		t.Fatal("exact independent signed source lost", err)
	}
	if catalogs.Load() != 1 || manifests.Load() != 1 || other.Load() != 0 || client.HTTP.Jar != jar {
		t.Fatal("download leaked panel credentials, mutated client, or fetched extra resources")
	}
	public, publicErr := client.FetchMemcachedUnixReleaseEnvelope(context.Background(), MemcachedUnixVersion, digest)
	if runtime.GOOS == "linux" {
		if publicErr != nil || !bytes.Equal(public.Catalog, in.Catalog) || !bytes.Equal(public.AppManifest, in.AppManifest) || catalogs.Load() != 2 || manifests.Load() != 2 || other.Load() != 0 {
			t.Fatal("compiled Unix fetch did not preserve the exact signed source", publicErr)
		}
	} else if publicErr == nil || catalogs.Load() != 1 || manifests.Load() != 1 {
		t.Fatal("non-Linux handler reached network or authorized the Unix package")
	}
	baseCatalogs, baseManifests := catalogs.Load(), manifests.Load()
	if _, err = client.fetchMemcachedUnixReleaseEnvelope(context.Background(), MemcachedUnixVersion, strings.Repeat("0", 64), memcachedUnixEnvelopeFixtureHandlers); err == nil || catalogs.Load() != baseCatalogs+1 || manifests.Load() != baseManifests {
		t.Fatal("changed binding fetched a manifest")
	}
	for _, version := range []string{MemcachedDigestVersion, "1.6.45-compat3", "1.6.45-compat5"} {
		if _, err = client.fetchMemcachedUnixReleaseEnvelope(context.Background(), version, digest, memcachedUnixEnvelopeFixtureHandlers); err == nil || catalogs.Load() != baseCatalogs+1 {
			t.Fatal("foreign version reached network")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = client.fetchMemcachedUnixReleaseEnvelope(ctx, MemcachedUnixVersion, digest, memcachedUnixEnvelopeFixtureHandlers); !errors.Is(err, context.Canceled) || catalogs.Load() != baseCatalogs+1 {
		t.Fatal("expired caller reached network", err)
	}
	redirect.Store(true)
	if _, err = client.fetchMemcachedUnixReleaseEnvelope(context.Background(), MemcachedUnixVersion, digest, memcachedUnixEnvelopeFixtureHandlers); err == nil || catalogs.Load() != baseCatalogs+2 || manifests.Load() != baseManifests+1 || other.Load() != 0 {
		t.Fatal("redirect followed or replayed")
	}
	redirect.Store(false)
	large.Store(true)
	if _, err = client.fetchMemcachedUnixReleaseEnvelope(context.Background(), MemcachedUnixVersion, digest, memcachedUnixEnvelopeFixtureHandlers); err == nil || catalogs.Load() != baseCatalogs+3 || manifests.Load() != baseManifests+2 || other.Load() != 0 {
		t.Fatal("oversized manifest accepted or replayed")
	}
}

func TestMemcachedUnixFetchRefusesUnsetOrIncompleteCompiledAuthorityBeforeNetwork(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); http.Error(w, "unexpected", 500) }))
	defer server.Close()
	client, in := memcachedUnixEnvelopeFixtureAt(t, server.URL, nil)
	client.HTTP = server.Client()
	digest := hashRuleFeedFile(in.AppManifest)
	for _, available := range []func(string) bool{nil, func(string) bool { return false }, func(s string) bool { return s != MemcachedUnixFeature }, func(s string) bool { return s != MemcachedDigestFeature }} {
		if _, err := client.fetchMemcachedUnixReleaseEnvelope(context.Background(), MemcachedUnixVersion, digest, available); err == nil {
			t.Fatal("incomplete capability reached source")
		}
	}
	if _, err := client.fetchMemcachedUnixReleaseEnvelope(nil, MemcachedUnixVersion, digest, memcachedUnixEnvelopeFixtureHandlers); err == nil {
		t.Fatal("nil context accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("rejected request touched network")
	}
}
