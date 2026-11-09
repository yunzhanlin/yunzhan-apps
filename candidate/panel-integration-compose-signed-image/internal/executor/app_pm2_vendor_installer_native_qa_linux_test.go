//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/runtimecatalog"
)

// Explicit disposable GitHub native-runner fixture only. Normal tests skip
// this network/package installation case. It is separate from signed release,
// systemd service installation and Main store acceptance.
func TestPM2RootVendorNativeRealFixedDependencyBuilder(t *testing.T) {
	if os.Getenv("PANEL_PM2_VENDOR_INSTALLER_QA") != "1" {
		t.Skip("explicit native fixed npm builder fixture required")
	}
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("GITHUB_REPOSITORY") != "yunzhanlin/yunzhan-apps" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Fatal("not the explicitly selected owned disposable native Root runner")
	}
	for _, name := range []string{"/opt/panel", "/etc/panel", "/var/lib/panel"} {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			t.Fatal("refusing any preexisting panel or user state", name, err)
		}
	}
	if err := os.Mkdir("/opt/panel", 0755); err != nil {
		t.Fatal(err)
	}
	if err := InstallAppDependencies("pm2-manager"); err != nil {
		t.Fatal("actual fixed dependency builder failed; original workspace retained", err)
	}
	s := New(Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.pm2RootVendorReady(ctx); err != nil {
		t.Fatal(err)
	}
	var result struct {
		OK         bool
		LockSHA256 string `json:"lock_sha256"`
	}
	if err := moduleRead(filepath.Join(s.moduleDir("pm2-manager"), "dependency-result.json"), &result); err != nil || !result.OK || result.LockSHA256 != pm2VendorHash(pm2Lock) {
		t.Fatal("fixed unit did not retain its actual successful dependency result", result, err)
	}
	public := filepath.Join(appNativeRoot, "pm2")
	for name, want := range map[string][]byte{"package.json": pm2Package, "package-lock.json": pm2Lock} {
		got, err := os.ReadFile(filepath.Join(public, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("actual npm inputs differ from compiled lock", name, err)
		}
	}
	pointerRaw, err := os.ReadFile(filepath.Join(public, pm2VendorIndexName))
	if err != nil {
		t.Fatal(err)
	}
	var pointer pm2VendorPointer
	if err = json.Unmarshal(pointerRaw, &pointer); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(appNativeRoot, pointer.Workspace)
	anchorRaw, err := os.ReadFile(filepath.Join(private, "vendor-anchor.json"))
	if err != nil || pm2VendorHash(anchorRaw) != pointer.AnchorSHA256 {
		t.Fatal("actual private seal mismatch", err)
	}
	var anchor pm2VendorAnchor
	if err = json.Unmarshal(anchorRaw, &anchor); err != nil || len(anchor.Entries) < 1000 {
		t.Fatal("minimal stub cannot stand for a real npm runtime", err, len(anchor.Entries))
	}
	publicInfo, err := os.Lstat(public)
	if err != nil {
		t.Fatal(err)
	}
	before := publicInfo.Sys().(*syscall.Stat_t)
	reused, err := s.buildPM2RootVendor(ctx)
	if err != nil || !reused.VerifiedExisting || !reused.IndependentRoot || reused.Publication.Published {
		t.Fatal("readiness replayed a build or publication", reused, err)
	}
	afterInfo, err := os.Lstat(public)
	if err != nil {
		t.Fatal(err)
	}
	after := afterInfo.Sys().(*syscall.Stat_t)
	if before.Dev != after.Dev || before.Ino != after.Ino {
		t.Fatal("verified runtime was exchanged again")
	}
	home := pm2VendorKernelParent(t)
	if err = os.Chown(home, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, pm2NodeBinaryOn(runtimecatalog.HostPlatform()), filepath.Join(public, "node_modules/pm2/bin/pm2-runtime"), "--version")
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "LANG=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{65534}}}
	output, err := command.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "7.0.4" {
		t.Fatal("actual PM2 CLI failed as an unprivileged UID", err, string(output))
	}
	if err = s.pm2RootVendorReady(ctx); err != nil {
		t.Fatal("ordinary unprivileged version read changed the Root runtime", err)
	}
	t.Logf("PM2_REAL_FIXED_NPM_BUILDER_ACCEPTED arch=%s Root_entries=%d upstream=7.0.4 unprivileged_CLI_UID=65534 scripts_disabled=true original_workspace=%s verified_reuse_publication_replayed=false", runtime.GOARCH, len(anchor.Entries), private)
}
