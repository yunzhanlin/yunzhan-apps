//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

// Test-only Root-owned namespace. No check is injected or bypassed: project
// state tests exercise the actual read-only inode/ctime check on a minimal
// non-executed fixture. Native installer tests separately use real npm bytes.
func pm2FixtureRootVendor(t *testing.T, s *Service) {
	t.Helper()
	root := pm2VendorKernelParent(t)
	s.Config.SystemRoot = root
	parent := s.systemPath(appNativeRoot)
	if err := os.MkdirAll(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if runtimecatalog.HostPlatform() == "ubuntu-22.04" {
		w, source := pm2VendorKernelBuild(t, parent)
		pm2VendorKernelWrite(t, filepath.Join(source, "package.json"), pm2Package, 0644)
		pm2VendorKernelWrite(t, filepath.Join(source, "package-lock.json"), pm2Lock, 0644)
		pm2VendorKernelWrite(t, filepath.Join(source, "node_modules/pm2/package.json"), []byte(`{"name":"pm2","version":"7.0.4"}`), 0644)
		pm2VendorKernelWrite(t, filepath.Join(source, "node/bin/node"), []byte("fixture Node inode, never executed\n"), 0755)
		entries, err := w.copyIndependent(context.Background(), "build", "candidate")
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := w.sealCandidate(context.Background(), "candidate", entries)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.publishIndependent(context.Background(), "candidate", sealed); err != nil {
			t.Fatal(err)
		}
	} else {
		pm2VendorKernelSealedAt(t, parent)
		pm2VendorKernelWrite(t, s.systemPath("/usr/bin/node"), []byte("fixture Node inode, never executed\n"), 0755)
	}
	if err := s.pm2RootVendorReady(context.Background()); err != nil {
		t.Fatal("original sealed fixture failed the actual production check", err)
	}
}

func TestPM2RootVendorKernelUnsealedRuntimeRefusesBeforeServiceAndOriginalWrites(t *testing.T) {
	s, app, originalPath := pm2StateAppFixture(t)
	s.Config.SystemRoot = pm2VendorKernelParent(t)
	pm2VendorKernelWrite(t, s.systemPath(appNativeRoot+"/pm2/node_modules/pm2/runtime.js"), []byte("unsealed original\n"), 0644)
	original, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("unsealed runtime dispatched a service command or dependency builder")
		return "", nil
	}
	for _, action := range []string{"start", "restart"} {
		if _, err := s.controlPM2(context.Background(), app, action, "panel-pm2@"+app.ID+".service"); err == nil {
			t.Fatal("unsealed runtime accepted control", action)
		}
	}
	if _, err := s.modulePM2(context.Background(), "create", core.AppModuleInput{ResourceID: "new-project", SiteID: app.SiteID, Entry: "app.js", Port: 24432}); err == nil {
		t.Fatal("unsealed runtime created or started a project")
	}
	if _, err := s.queuePM2Dependencies(context.Background(), app, app.Revision); err == nil {
		t.Fatal("unsealed runtime queued a dependency deployment")
	}
	next := app
	next.Revision++
	if _, err := s.applyPM2Configuration(context.Background(), core.AppModuleInput{}, original, next, pm2TestState("active", "enabled")); err == nil {
		t.Fatal("unsealed runtime rewrote an active project")
	}
	after, err := os.ReadFile(originalPath)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("unsealed runtime changed original encrypted configuration", err)
	}
	for _, name := range []string{"configuration-transactions", "deployments"} {
		if _, err := os.Lstat(filepath.Join(s.moduleDir("pm2-manager"), name)); !os.IsNotExist(err) {
			t.Fatal("failed runtime check persisted a transaction or job", name, err)
		}
	}
	entries, err := os.ReadDir(s.systemPath(appNativeRoot))
	if err != nil || len(entries) != 1 || entries[0].Name() != "pm2" {
		t.Fatal("failed runtime check implicitly rebuilt or repaired the vendor", err)
	}
}

func TestPM2RootVendorKernelTrustedSystemProgramRejectsOwnerTypeAndEscapingLink(t *testing.T) {
	root := pm2VendorKernelParent(t)
	name := filepath.Join(root, "usr/bin/node")
	pm2VendorKernelWrite(t, name, []byte("fixture, never executed\n"), 0755)
	if err := pm2VendorTrustedSystemProgramOn(root, "/usr/bin/node"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(name, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := pm2VendorTrustedSystemProgramOn(root, "/usr/bin/node"); err == nil {
		t.Fatal("unprivileged system program accepted")
	}
	if err := os.Rename(name, name+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", name); err != nil {
		t.Fatal(err)
	}
	if err := pm2VendorTrustedSystemProgramOn(root, "/usr/bin/node"); err == nil || !strings.Contains(err.Error(), "根目录") {
		t.Fatal("system program link escaped the bound root", err)
	}
	if err := pm2VendorTrustedSystemProgramOn(root, "/bin/sh"); err == nil {
		t.Fatal("unbound executable path accepted")
	}
}
