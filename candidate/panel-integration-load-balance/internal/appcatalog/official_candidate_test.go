package appcatalog

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCandidateGitHubUsesOnlyItsFixedRefAndImmutableNamespace(t *testing.T) {
	commit := strings.Repeat("c", 40)
	var paths []string
	client := &Client{BaseURL: CandidateBaseURL, HTTP: &http.Client{Transport: githubCatalogTransport(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.String())
		body := "candidate-metadata"
		if r.URL.String() == githubCandidateRefURL {
			body = `{"ref":"refs/heads/codex/app-candidate","object":{"type":"commit","sha":"` + commit + `"}}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	got, err := client.resolveCatalogCommit(context.Background())
	if err != nil || got != commit {
		t.Fatal("candidate reference not pinned", err)
	}
	if _, err := client.getCatalogAtCommit(context.Background(), got, "signatures/catalog-v1.bundle.json", 1024); err != nil {
		t.Fatal(err)
	}
	want := []string{githubCandidateRefURL, githubCatalogCommitBase + commit + "/candidate/signatures/catalog-v1.bundle.json"}
	if fmt.Sprint(paths) != fmt.Sprint(want) {
		t.Fatal("candidate used mutable/stable/foreign URL", paths)
	}
	for _, relative := range []string{"../dist/catalog-v1.json", "candidate/dist/catalog-v1.json", "dist/apps/x/1.0/manifest.json"} {
		if _, err := client.getCatalogAtCommit(context.Background(), commit, relative, 1024); err == nil {
			t.Fatal("unknown immutable metadata path accepted", relative)
		}
	}
	if _, err := client.getCatalogAtCommit(context.Background(), "", "dist/catalog-v1.json", 1024); err == nil {
		t.Fatal("candidate silently fell back to mutable branch")
	}
}

func TestCandidateOfflineCompatibilityIsOneWayUniformAndStillSigned(t *testing.T) {
	main, envelope := streamReleaseFixture(t, DefaultBaseURL, nil)
	candidate := &Client{BaseURL: CandidateBaseURL, PublicKey: main.PublicKey}
	if _, err := candidate.verifyCatalog(envelope.Catalog, envelope.Signature); err != nil {
		t.Fatal("existing stable signed records lost after candidate programme upgrade", err)
	}
	qa, candidateEnvelope := streamReleaseFixture(t, CandidateBaseURL, nil)
	stable := &Client{BaseURL: DefaultBaseURL, PublicKey: qa.PublicKey}
	if _, err := stable.verifyCatalog(candidateEnvelope.Catalog, candidateEnvelope.Signature); err == nil {
		t.Fatal("stable client accepted a candidate catalogue")
	}
	corrupt := append([]byte(nil), envelope.Catalog...)
	corrupt[0] ^= 1
	if _, err := candidate.verifyCatalog(corrupt, envelope.Signature); err == nil {
		t.Fatal("compatibility bypassed signature verification")
	}
	// A correctly signed cryptographic FIXTURE can still not mix namespaces.
	public, private := deterministicCandidateFixtureKey()
	var catalog Catalog
	if json.Unmarshal(envelope.Catalog, &catalog) != nil {
		t.Fatal("fixture JSON")
	}
	second := catalog.Apps[0]
	second.ID, second.Target = "other-fixture", "other-fixture"
	second.PackageURL = CandidateBaseURL + "/dist/apps/other-fixture/" + second.Version + "/manifest.json"
	catalog.Apps = append(catalog.Apps, second)
	raw, _ := json.Marshal(catalog)
	client := &Client{BaseURL: CandidateBaseURL, PublicKey: public}
	if _, err := client.verifyCatalog(raw, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw)))); err == nil {
		t.Fatal("signed mixed namespace accepted")
	}
}

func deterministicCandidateFixtureKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	// Public test vector only; never used by Default/Root or a published key.
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	return private.Public().(ed25519.PublicKey), private
}
