package appcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func TestRuleFeedEnvelopeIndependentOfflineVerification(t *testing.T) {
	manifest, bundle := ruleFeedFixture(t)
	client, server, requests := feedRepository(t, manifest, bundle, "")
	defer server.Close()
	manifestRaw, _ := json.Marshal(manifest)
	digest := hashRuleFeedFile(manifestRaw)
	in, err := client.FetchRuleFeedEnvelope(context.Background(), manifest.Version, digest, manifest.RuleFeeds[0].ID)
	if err != nil || requests.Load() != 6 {
		t.Fatal("closed explicit download failed", err)
	}
	encoded, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRuleFeedEnvelope(encoded)
	if err != nil || !bytes.Equal(decoded.Catalog, in.Catalog) || !bytes.Equal(decoded.AppManifest, manifestRaw) {
		t.Fatal("exact signed bytes did not survive transfer", err)
	}
	// Receiver has independently supplied signing key and repository scope, and
	// no HTTP client. Closing the server proves verification is offline.
	server.Close()
	receiver := &Client{BaseURL: client.BaseURL, PublicKey: append(ed25519.PublicKey(nil), client.PublicKey...)}
	authority, verified, err := receiver.VerifyRuleFeedEnvelope(context.Background(), decoded, manifest.Version, digest)
	if err != nil || !authority.verified || len(verified.Rules) != 1 || requests.Load() != 6 {
		t.Fatal("independent offline verification failed", err)
	}
	decoded.Files["et-open.rules"][0] ^= 1
	if !bytes.Equal(verified.Files["et-open.rules"], bundle.Files["et-open.rules"]) {
		t.Fatal("verified data shares mutable caller buffers")
	}
	for _, scenario := range []string{"catalog", "signature", "app-manifest", "rule", "size", "extra", "missing", "unlisted", "version", "binding", "foreign-key", "foreign-origin", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			candidate, err := DecodeRuleFeedEnvelope(encoded)
			if err != nil {
				t.Fatal(err)
			}
			version, sha := manifest.Version, digest
			recv := &Client{BaseURL: receiver.BaseURL, PublicKey: receiver.PublicKey}
			ctx := context.Background()
			switch scenario {
			case "catalog":
				candidate.Catalog[0] ^= 1
			case "signature":
				candidate.Signature[0] ^= 1
			case "app-manifest":
				candidate.AppManifest[0] ^= 1
			case "rule":
				candidate.Files["et-open.rules"][0] ^= 1
			case "size":
				candidate.Files["et-open.rules"] = append(candidate.Files["et-open.rules"], ' ')
			case "extra":
				candidate.Files["install.sh"] = []byte("untrusted")
			case "missing":
				delete(candidate.Files, "LICENSE")
			case "unlisted":
				candidate.FeedID = "et-open-web-20261008"
			case "version":
				version = "1.2.0"
			case "binding":
				sha = strings.Repeat("0", 64)
			case "foreign-key":
				recv.PublicKey = make(ed25519.PublicKey, 32)
			case "foreign-origin":
				recv.BaseURL += "/foreign"
			case "canceled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			if _, _, err := recv.VerifyRuleFeedEnvelope(ctx, candidate, version, sha); err == nil {
				t.Fatal("invalid transfer accepted", scenario)
			}
		})
	}
}

func TestRuleFeedEnvelopeRejectsAmbiguousWireData(t *testing.T) {
	manifest, bundle := ruleFeedFixture(t)
	client, server, requests := feedRepository(t, manifest, bundle, "")
	defer server.Close()
	manifestRaw, _ := json.Marshal(manifest)
	valid, err := client.FetchRuleFeedEnvelope(context.Background(), manifest.Version, hashRuleFeedFile(manifestRaw), manifest.RuleFeeds[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(valid)
	for _, scenario := range []string{"duplicate", "case-alias", "escaped-duplicate", "alias-only", "extra", "null", "trailing", "bad-base64", "member-case", "member-duplicate", "member-escaped-duplicate", "oversize", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			data := append([]byte(nil), encoded...)
			switch scenario {
			case "duplicate":
				data = append([]byte(`{"feed_id":"other",`), data[1:]...)
			case "case-alias":
				data = append([]byte(`{"FEED_ID":"other",`), data[1:]...)
			case "escaped-duplicate":
				data = append([]byte(`{"feed\u005fid":"other",`), data[1:]...)
			case "alias-only":
				data = bytes.Replace(data, []byte(`"feed_id":`), []byte(`"FEED_ID":`), 1)
			case "extra":
				data = append([]byte(`{"verified":true,`), data[1:]...)
			case "null":
				data = bytes.Replace(data, []byte(`"files":{`), []byte(`"files":null,"ignored":{`), 1)
			case "trailing":
				data = append(data, []byte(` {}`)...)
			case "bad-base64":
				data = bytes.Replace(data, []byte(`"signature":"`), []byte(`"signature":"!`), 1)
			case "member-case":
				data = bytes.Replace(data, []byte(`"LICENSE":`), []byte(`"License":`), 1)
			case "member-duplicate":
				data = bytes.Replace(data, []byte(`"files":{`), []byte(`"files":{"LICENSE":"YQ==",`), 1)
			case "member-escaped-duplicate":
				data = bytes.Replace(data, []byte(`"files":{`), []byte(`"files":{"LICE\u004eSE":"YQ==",`), 1)
			case "oversize":
				data = bytes.Repeat([]byte(" "), MaxRuleFeedEnvelopeBytes+1)
			case "missing":
				var fields map[string]json.RawMessage
				json.Unmarshal(data, &fields)
				delete(fields, "signature")
				data, _ = json.Marshal(fields)
			}
			if _, err := DecodeRuleFeedEnvelope(data); err == nil {
				t.Fatal("ambiguous wire envelope accepted", scenario)
			}
		})
	}
	if _, err := client.FetchRuleFeedEnvelope(context.Background(), "1.2.0", hashRuleFeedFile(manifestRaw), valid.FeedID); err == nil || requests.Load() != 6 {
		t.Fatal("changed app binding downloaded assets")
	}
}
