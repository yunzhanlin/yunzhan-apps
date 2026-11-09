//go:build linux

package appcatalog

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"local/panel/internal/loadbalancestream"
)

var publishedCandidateRoot = flag.String("published-candidate-app-registry-root", "", "test ELF only: read-only exact signed candidate catalogue ABI; no native app authority")

func TestPublishedCandidateRepositoryCurrentSignedManifestABI(t *testing.T) {
	if *publishedCandidateRoot == "" {
		t.Skip("explicit signed candidate files and candidate-compiled Linux ELF required; no install acceptance")
	}
	client := Default()
	client.HTTP = nil
	if client.BaseURL != CandidateBaseURL || OfficialCatalogChannel() != "candidate" || !LoadBalanceStreamAvailable() {
		t.Fatal("test cannot replace the actual compiled channel or feature")
	}
	root, err := filepath.Abs(*publishedCandidateRoot)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	stat, e2 := os.Lstat(root)
	if err != nil || e2 != nil || resolved != root || !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		t.Fatal("candidate root must be an existing canonical ordinary directory")
	}
	raw, err := boundedRead(filepath.Join(root, "signatures/catalog-v1.bundle.json"), 3*maxCatalogBytes)
	if err != nil {
		t.Fatal(err)
	}
	var bundle catalogBundle
	if strictJSON(raw, &bundle) != nil {
		t.Fatal("candidate atomic signed bundle is invalid")
	}
	catalog, err := client.verifyCatalog([]byte(bundle.Catalog), []byte(bundle.Signature))
	if err != nil || len(catalog.Apps) != 50 {
		t.Fatal("actual original-key signature and exact50 inventory required", err)
	}
	stream := false
	for _, item := range catalog.Apps {
		t.Run(item.ID, func(t *testing.T) {
			if item.PackageURL != CandidateBaseURL+"/dist/apps/"+item.ID+"/"+item.Version+"/manifest.json" {
				t.Fatal("candidate ABI cannot silently use stable or mixed catalogue bytes")
			}
			body, err := boundedRead(filepath.Join(root, "dist/apps", item.ID, item.Version, "manifest.json"), maxManifestBytes)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := client.verifyManifestData(item, body)
			if err != nil || manifest.ID != item.ID || manifest.Version != item.Version {
				t.Fatal("actual compiled verifier rejects the candidate manifest", err)
			}
			if item.ID == "load-balance" {
				stream = manifest.Version == loadbalancestream.AppVersion && isLoadBalanceStreamManifest(manifest)
			}
		})
	}
	if !stream {
		t.Fatal("new stream delivery was not actually verified")
	}
	t.Log("actual Linux candidate signed50 manifest ABI verified; no network, database writes, installation or all50 commercial claim")
}
