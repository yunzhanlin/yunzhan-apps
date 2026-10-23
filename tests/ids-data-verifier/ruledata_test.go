package verification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"local/panel/internal/appcatalog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const appSHA = "2a49e71578193d1e2af1af9364559dda0b8f8ac524f01117cb69de89aea18ebe"
const ruleSHA = "37a4214bf8b08dc717215f1afab3da207b9202d0224577beacb3b284e7ab1c03"

func publishedEnvelope(t *testing.T) (*appcatalog.Client, appcatalog.RuleDataEnvelope, time.Time) {
	t.Helper()
	// The original publication remains independently verifiable after another
	// application advances the current catalog. Never change historical bytes.
	return publishedEnvelopeFrom(t, "registry/reviewed-catalogs/before-pm2-readiness24bjlj/signatures/catalog-v1.bundle.json", "00aac65cd0405b56b866485a9ee59f62f60c520c8af27ef9a72470ec5ebb40aa")
}

func publishedEnvelopeFrom(t *testing.T, appBundlePath, appCatalogSHA string) (*appcatalog.Client, appcatalog.RuleDataEnvelope, time.Time) {
	t.Helper()
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join("../..", n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	decode := func(b []byte) (string, string) {
		var v struct {
			Catalog   string `json:"catalog"`
			Signature string `json:"signature"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		return v.Catalog, v.Signature
	}
	app, sig := decode(read(appBundlePath))
	prefix := "dist/apps/network-threat-detection/rule-data/et-open-web-bsd-v1/"
	data, dataSig := decode(read(prefix + "catalog-v1.bundle.json"))
	for text, want := range map[string]string{app: appCatalogSHA, data: "391843d9da2ece79c61e30c28f5d515f6c5cad8ac0ded64e2cb45bf4feb35d82"} {
		sum := sha256.Sum256([]byte(text))
		if hex.EncodeToString(sum[:]) != want {
			t.Fatal("immutable publication bytes changed")
		}
	}
	files := map[string][]byte{}
	for _, n := range []string{"manifest.json", "LICENSE", "BSD-License.txt", "classification.config", "reference.config", "et-open.rules"} {
		files[n] = read(prefix + "feeds/et-open-web-20261021/" + ruleSHA + "/" + n)
	}
	env := appcatalog.RuleDataEnvelope{AppCatalog: []byte(app), AppSignature: []byte(sig), AppManifest: read("dist/apps/network-threat-detection/1.3.1/manifest.json"), DataCatalog: []byte(data), DataSignature: []byte(dataSig), Files: files}
	// Deliberately a publication-time fixture, not a claim that a historical
	// 72-hour channel remains fresh forever. Live consumers use their own clock.
	now := time.Date(2026, 10, 21, 21, 51, 0, 0, time.UTC)
	return appcatalog.Default(), env, now
}

func TestCurrentPM2CatalogPreservesActualFrozenIDSConsumerAuthorityAndAll1510Rules(t *testing.T) {
	// Keep the genuine PM2 publication and every original assertion. An
	// unrelated mobile publication is tested independently below, never used
	// as a hash alias or a reason to renew the signed rule cohort.
	c, in, now := publishedEnvelopeFrom(t, "registry/reviewed-catalogs/before-native-mobile132-24bkep/signatures/catalog-v1.bundle.json", "0432d210df255b06a1ce258546579f4bfa666d0b661b54fd2572e356549d5f4d")
	authority, bundle, err := c.VerifyRuleDataEnvelope(context.Background(), in, "1.3.1", appSHA, "et-open-web-20261021", ruleSHA, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authority.CatalogSHA256() != "391843d9da2ece79c61e30c28f5d515f6c5cad8ac0ded64e2cb45bf4feb35d82" || authority.Catalog().Sequence != 1 || len(bundle.Rules) != 1510 || bundle.Manifest.DependencyRuleCount != 2 {
		t.Fatal("current app catalog changed the signed IDS data cohort")
	}
	if _, _, err := c.VerifyRuleDataEnvelope(context.Background(), in, "1.3.1", appSHA, "et-open-web-20261021", ruleSHA, time.Date(2026, 10, 24, 21, 50, 0, 0, time.UTC), &authority); err == nil {
		t.Fatal("unrelated PM2 publication renewed IDS rule validity")
	}
}

func TestCurrentMobileCatalogPreservesActualFrozenIDSConsumerAuthorityAndAll1510Rules(t *testing.T) {
	c, in, now := publishedEnvelopeFrom(t, "signatures/catalog-v1.bundle.json", "bc0dcdbcd0bcd5e75c889471a9e26168c951f943f772e0400d328af8d3e5f84f")
	authority, bundle, err := c.VerifyRuleDataEnvelope(context.Background(), in, "1.3.1", appSHA, "et-open-web-20261021", ruleSHA, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authority.CatalogSHA256() != "391843d9da2ece79c61e30c28f5d515f6c5cad8ac0ded64e2cb45bf4feb35d82" || authority.Catalog().Sequence != 1 || len(bundle.Rules) != 1510 || bundle.Manifest.EnabledRuleCount != 1510 || bundle.Manifest.DependencyRuleCount != 2 {
		t.Fatal("mobile publication changed the independently signed IDS data cohort")
	}
	if _, _, err := c.VerifyRuleDataEnvelope(context.Background(), in, "1.3.1", appSHA, "et-open-web-20261021", ruleSHA, time.Date(2026, 10, 24, 21, 50, 0, 0, time.UTC), &authority); err == nil {
		t.Fatal("unrelated mobile publication renewed IDS rule validity")
	}
}

func TestPublishedIDSRuleDataActualFrozenConsumerVerifiesBothOriginalKeySignaturesAndAll1510Rules(t *testing.T) {
	c, in, now := publishedEnvelope(t)
	authority, bundle, err := c.VerifyRuleDataEnvelope(context.Background(), in, "1.3.1", appSHA, "et-open-web-20261021", ruleSHA, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Catalog().Sequence != 1 || authority.CatalogSHA256() != "391843d9da2ece79c61e30c28f5d515f6c5cad8ac0ded64e2cb45bf4feb35d82" || len(bundle.Rules) != 1510 || bundle.Manifest.EnabledRuleCount != 1510 || bundle.Manifest.DependencyRuleCount != 2 {
		t.Fatal("wrong real cohort")
	}
	if bundle.Manifest.NativeSyntaxVerified || bundle.Manifest.PublisherSignatureVerified {
		t.Fatal("offline artifact was relabelled as an upstream/native certification")
	}
}

func TestPublishedIDSRuleDataActualFrozenConsumerRejectsEveryAssetSignatureAndAppBindingTamper(t *testing.T) {
	for _, scenario := range []string{"manifest.json", "LICENSE", "BSD-License.txt", "classification.config", "reference.config", "et-open.rules", "app-signature", "data-signature", "signature-domain", "app-manifest", "unknown-file", "missing-file", "wrong-app-version", "wrong-app-sha", "wrong-feed", "wrong-rule-sha"} {
		t.Run(scenario, func(t *testing.T) {
			c, in, now := publishedEnvelope(t)
			version, app, feed, rule := "1.3.1", appSHA, "et-open-web-20261021", ruleSHA
			if b, ok := in.Files[scenario]; ok {
				in.Files[scenario] = bytes.Clone(b)
				in.Files[scenario][0] ^= 1
			} else {
				switch scenario {
				case "app-signature":
					in.AppSignature = bytes.Repeat([]byte("A"), len(in.AppSignature))
				case "data-signature":
					in.DataSignature = bytes.Repeat([]byte("A"), len(in.DataSignature))
				case "signature-domain":
					in.DataSignature = bytes.Clone(in.AppSignature)
				case "app-manifest":
					in.AppManifest = bytes.Replace(in.AppManifest, []byte("1.3.1"), []byte("1.3.2"), 1)
				case "unknown-file":
					in.Files["extra.rules"] = []byte("untrusted")
				case "missing-file":
					delete(in.Files, "LICENSE")
				case "wrong-app-version":
					version = "1.3.0"
				case "wrong-app-sha":
					app = ruleSHA
				case "wrong-feed":
					feed = "et-open-web-20261020"
				case "wrong-rule-sha":
					rule = appSHA
				}
			}
			if _, _, err := c.VerifyRuleDataEnvelope(context.Background(), in, version, app, feed, rule, now, nil); err == nil {
				t.Fatal("tampered actual publication accepted")
			}
		})
	}
}

func TestPublishedIDSRuleDataExpiryIsNotRenewedByRetainedHistoryOrPublicationFixtureClock(t *testing.T) {
	c, in, now := publishedEnvelope(t)
	a, _, err := c.VerifyRuleDataEnvelope(context.Background(), in, "1.3.1", appSHA, "et-open-web-20261021", ruleSHA, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, clock := range []time.Time{time.Date(2026, 10, 21, 21, 44, 59, 0, time.UTC), time.Date(2026, 10, 24, 21, 50, 0, 0, time.UTC), now.Add(30 * 24 * time.Hour)} {
		if _, _, err := c.VerifyRuleDataEnvelope(context.Background(), in, "1.3.1", appSHA, "et-open-web-20261021", ruleSHA, clock, &a); err == nil {
			t.Fatal("future or expired data gained new activation authority")
		}
	}
	retained, err := c.VerifyRetainedRuleDataAuthority(in.AppCatalog, in.AppSignature, in.AppManifest, in.DataCatalog, in.DataSignature, "1.3.1", appSHA, now.Add(30*24*time.Hour))
	if err != nil {
		t.Fatal("authentic retained history became unreadable", err)
	}
	if retained.Catalog().PublishedAt != a.Catalog().PublishedAt || retained.Catalog().ExpiresAt != a.Catalog().ExpiresAt {
		t.Fatal("retained history renewed validity")
	}
}
