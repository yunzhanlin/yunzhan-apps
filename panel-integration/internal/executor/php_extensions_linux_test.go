//go:build linux

package executor

import (
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestPHPPoolManifestRejectsMismatchedIdentity(t *testing.T) {
	p := core.DefaultPHPSettings()
	p.Extensions = []string{"redis-6.3.0"}
	site := core.Site{ID: core.ID(), PHPVersionID: "php-8.4.25", Settings: core.SiteSettings{PHP: &p}}
	m := phpPoolManifest{SiteID: site.ID, ReleaseID: site.PHPVersionID, PHP: &p}
	b, _ := json.Marshal(m)
	got, e := decodePHPPoolManifest(core.PHPInstanceID(site), b)
	if e != nil || len(got.Extensions) != 1 {
		t.Fatal(got, e)
	}
	site.PHPVersionID = "php-8.5.10"
	if _, e = decodePHPPoolManifest(core.PHPInstanceID(site), b); e == nil {
		t.Fatal("pool manifest crossed PHP version")
	}
	if _, e = decodePHPPoolManifest("../escape", b); e == nil {
		t.Fatal("pool accepted arbitrary identity")
	}
	if _, e = readPHPPoolSettings("bad"); e == nil {
		t.Fatal("short identity accepted")
	}
}
func TestExtensionELFArchitectureAndType(t *testing.T) {
	// Linux test executable is ELF but not a PHP shared module for both architectures.
	path, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	if verifyModuleELF(path, "invalid") == nil {
		t.Fatal("unrecognized architecture accepted")
	}
	f := filepath.Join(t.TempDir(), "redis.so")
	if e = os.WriteFile(f, []byte("not an ELF module"), 0600); e != nil {
		t.Fatal(e)
	}
	if verifyModuleELF(f, "arm64") == nil {
		t.Fatal("non-ELF module accepted")
	}
}
