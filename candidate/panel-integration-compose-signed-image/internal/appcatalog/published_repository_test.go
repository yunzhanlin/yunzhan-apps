package appcatalog

import (
	"flag"
	"path/filepath"
	"runtime"
	"testing"
)

// This flag exists only in a test binary. It cannot alter runtime trust,
// compiled feature availability, installation policy, URLs or public keys.
var publishedAppRegistryRoot = flag.String("published-app-registry-root", "", "explicit read-only repository root for current signed manifest ABI regression")

func TestPublishedRepositoryCurrentSignedManifestABI(t *testing.T) {
	if *publishedAppRegistryRoot == "" {
		t.Skip("explicit current application repository required; normal fixed signed fixture is checked separately")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("explicit current repository acceptance requires an actual Linux-compiled test binary; do not substitute a skipped non-Linux gate")
	}
	root, err := filepath.Abs(*publishedAppRegistryRoot)
	if err != nil {
		t.Fatal(err)
	}
	body, err := boundedRead(filepath.Join(root, "signatures", "catalog-v1.bundle.json"), 3*maxCatalogBytes)
	if err != nil {
		t.Fatal(err)
	}
	var bundle catalogBundle
	if err = strictJSON(body, &bundle); err != nil || len(bundle.Catalog) > maxCatalogBytes || len(bundle.Signature) > 4096 {
		t.Fatal("current bounded atomic catalog bundle", err)
	}
	client := Default()
	catalog, err := client.verifyCatalog([]byte(bundle.Catalog), []byte(bundle.Signature))
	if err != nil || len(catalog.Apps) != 50 {
		t.Fatal("current original-key signature and exact50 inventory", err)
	}
	for _, item := range catalog.Apps {
		t.Run(item.ID, func(t *testing.T) {
			// verifyCatalog already validated fixed ID/version/URL identities;
			// only the exact signed local package path may be read, no fetch.
			if item.PackageURL != DefaultBaseURL+"/dist/apps/"+item.ID+"/"+item.Version+"/manifest.json" {
				t.Fatal("unexpected current package URL")
			}
			raw, err := boundedRead(filepath.Join(root, "dist", "apps", item.ID, item.Version, "manifest.json"), maxManifestBytes)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := client.verifyManifestData(item, raw)
			if err != nil {
				t.Fatal("actual compiled handler rejects current signed manifest", err)
			}
			if manifest.ID != item.ID || manifest.Version != item.Version {
				t.Fatal("manifest identity changed")
			}
		})
	}
}
