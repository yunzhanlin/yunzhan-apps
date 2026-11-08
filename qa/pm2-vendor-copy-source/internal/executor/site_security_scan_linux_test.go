//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSiteSecurityScanFindsOnlyExistingRootClues(t *testing.T) {
	f, site := fileFixture(t)
	root := filepath.Join(site, "public")
	for _, name := range []string{".env", "backup.sql", "phpinfo.php", ".env.example"} {
		if e := os.WriteFile(filepath.Join(root, name), []byte("fixture"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Mkdir(filepath.Join(root, ".git"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(".env", filepath.Join(root, "linked.env")); e != nil {
		t.Fatal(e)
	}
	scan, e := inspectSiteFiles(f)
	if e != nil {
		t.Fatal(e)
	}
	if scan.Status != "attention" || len(scan.Findings) != 4 {
		t.Fatalf("unexpected scan: %+v", scan)
	}
	for _, finding := range scan.Findings {
		if finding.Path == ".env.example" || finding.Path == "linked.env" {
			t.Fatalf("false positive: %+v", finding)
		}
	}
}

func TestSiteSecurityScanNestedCluesAndTraversalBoundary(t *testing.T) {
	f, site := fileFixture(t)
	root := filepath.Join(site, "public")
	if e := os.MkdirAll(filepath.Join(root, "assets", "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "assets", "nested", ".env"), []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "assets", "server.key"), []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Join(site, "private"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(site, "private", "backup.sql"), []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(site, "private"), filepath.Join(root, "linked-private")); e != nil {
		t.Fatal(e)
	}
	scan, e := inspectSiteFiles(f)
	if e != nil {
		t.Fatal(e)
	}
	if scan.Status != "attention" || len(scan.Findings) != 2 {
		t.Fatalf("unexpected nested scan: %+v", scan)
	}
	seen := map[string]bool{}
	for _, finding := range scan.Findings {
		seen[finding.Path] = true
	}
	if !seen["assets/nested/.env"] || !seen["assets/server.key"] || seen["linked-private/backup.sql"] {
		t.Fatalf("scan crossed boundary or missed nested risk: %+v", scan.Findings)
	}
}
