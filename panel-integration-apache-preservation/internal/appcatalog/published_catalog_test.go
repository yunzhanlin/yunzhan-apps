package appcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
)

// Exact original-key-signed public data from the current50 application catalog.
// This is an offline ABI regression, not installation or native app acceptance.
func TestPublishedSignedCatalogManifestsKeepCurrentHandlerABI(t *testing.T) {
	raw, err := os.ReadFile("testdata/published-catalog-20261015.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Format       int               `json:"format"`
		SourceCommit string            `json:"source_commit"`
		Catalog      string            `json:"catalog"`
		Signature    string            `json:"signature"`
		Manifests    map[string]string `json:"manifests"`
	}
	if err = strictJSON(raw, &fixture); err != nil || fixture.Format != 1 || fixture.SourceCommit != "5a13173151f1083b777774db65c265f16a0a52b9" {
		t.Fatal("published fixture identity", err)
	}
	digest := sha256.Sum256([]byte(fixture.Catalog))
	if hex.EncodeToString(digest[:]) != "53a3fa58943042b91709571904d4274f4af11639ef31560806d2a3c3dc7a57ad" {
		t.Fatal("original signed catalog changed")
	}
	client := Default()
	catalog, err := client.verifyCatalog([]byte(fixture.Catalog), []byte(fixture.Signature))
	if err != nil || len(catalog.Apps) != 50 || len(fixture.Manifests) != 50 {
		t.Fatal("original key signature and exact50 inventory", err)
	}
	for _, item := range catalog.Apps {
		t.Run(item.ID, func(t *testing.T) {
			body, found := fixture.Manifests[item.ID]
			if !found {
				t.Fatal("actual published manifest missing")
			}
			var manifest Manifest
			if err := json.Unmarshal([]byte(body), &manifest); err != nil {
				t.Fatal(err)
			}
			// The pure shape/identity gate must remain compatible even when
			// local Darwin correctly has no compiled Linux native features.
			if err := validatePanelRequirements(manifest, func(feature string) bool {
				return feature == StatisticsCursorRetirementFeature || feature == StatisticsRequestIdentityFeature || feature == StatisticsGeographyFeature || feature == PlatformMaintenanceFeature || feature == DiskInodeUsageFeature || feature == DiskHostJobsFeature || feature == MemcachedDigestFeature
			}); err != nil {
				t.Fatal("current published application rejected by candidate ABI", item.Version, err)
			}
			_, err := client.verifyManifestData(item, []byte(body))
			if runtime.GOOS == "linux" || len(manifest.RequiredPanelFeatures) == 0 {
				if err != nil {
					t.Fatal("current signed bytes rejected", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "请先升级面板") {
				t.Fatal("non-Linux feature availability must remain explicit", err)
			}
		})
	}
}
