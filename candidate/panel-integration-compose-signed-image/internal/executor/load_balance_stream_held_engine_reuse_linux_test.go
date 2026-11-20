//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"testing"

	"local/panel/internal/runtimecatalog"
)

func TestCommittedEngineWitnessStillRequiresOriginalNamesBytesAndRelease(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the native engine witness requires trusted root-owned parents")
	}
	root, err := os.MkdirTemp("/run", "panel-held-engine-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	release, found := runtimecatalog.Find("nginx-1.30.6")
	if !found {
		t.Fatal("known stream release missing")
	}
	pinned := func(name, raw string) *loadBalanceStreamEngineFile {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		w, _, err := holdLoadBalanceStreamEngineFile(p, false)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { w.file.Close() })
		return w
	}
	engine := &loadBalanceStreamHeldEngine{release: release, binary: pinned("held-elf", "validated native file"), manifest: pinned("held-manifest", "validated manifest")}
	receipt := loadBalanceStreamInstallationReceipt{NginxReleaseID: release.ID, NginxSHA256: engine.binary.sha, NginxManifestSHA256: engine.manifest.sha}
	if !streamCommittedEngineMatches(engine, receipt) {
		t.Fatal("intact original held pair refused")
	}
	wrong := receipt
	wrong.NginxReleaseID = "nginx-1.31.5"
	if streamCommittedEngineMatches(engine, wrong) {
		t.Fatal("unrelated release accepted")
	}
	wrong = receipt
	wrong.NginxSHA256 = receipt.NginxManifestSHA256
	if streamCommittedEngineMatches(engine, wrong) {
		t.Fatal("unrelated digest accepted")
	}
	if err := os.WriteFile(engine.binary.path, []byte("substituted native file"), 0600); err != nil {
		t.Fatal(err)
	}
	if streamCommittedEngineMatches(engine, receipt) {
		t.Fatal("in-place change accepted")
	}
	engine.binary = pinned("second-elf", "validated native file")
	if !streamCommittedEngineMatches(engine, receipt) {
		t.Fatal("new independently held fixture refused")
	}
	path := engine.manifest.path
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("validated manifest"), 0600); err != nil {
		t.Fatal(err)
	}
	if streamCommittedEngineMatches(engine, receipt) {
		t.Fatal("equal-byte renamed replacement accepted")
	}
}
