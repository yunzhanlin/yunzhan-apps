//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func ftpRuntimeFixture(t *testing.T) *Service {
	t.Helper()
	s, _ := ftpServiceFixture(t)
	dir := s.systemPath(filepath.Join(appNativeRoot, "pure-ftpd", ftpRuntimeVersion))
	if e := os.MkdirAll(dir, 0755); e != nil {
		t.Fatal(e)
	}
	m := ftpRuntimeManifest{ftpRuntimeVersion, runtime.GOARCH, ftpRuntimeSourceSHA, ftpRuntimePatchSHA(), map[string]string{}, core.Now()}
	for _, name := range []string{"pure-ftpd", "pure-pw", "pure-ftpwho", "COPYING"} {
		b := []byte("reviewed-test-fixture-" + name)
		mode := os.FileMode(0755)
		if name == "COPYING" {
			mode = 0644
		}
		if e := atomicWrite(filepath.Join(dir, name), b, mode); e != nil {
			t.Fatal(e)
		}
		m.Files[name] = core.Hash(string(b))
	}
	if e := moduleWrite(filepath.Join(dir, "manifest.json"), m); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestFTPPrivateRuntimeTrustAndSelection(t *testing.T) {
	s := ftpRuntimeFixture(t)
	dir := s.moduleDir("pure-ftpd")
	if e := s.validateFTPRuntime(); e != nil {
		t.Fatal(e)
	}
	legacy, e := s.ftpBinary("pure-pw")
	if e != nil || !strings.HasSuffix(legacy, "/usr/bin/pure-pw") {
		t.Fatal(legacy, e)
	}
	if e = moduleWrite(filepath.Join(dir, "runtime.json"), map[string]string{"version": ftpRuntimeVersion}); e != nil {
		t.Fatal(e)
	}
	binary, e := s.ftpBinary("pure-pw")
	if e != nil || !strings.Contains(binary, ftpRuntimeVersion) {
		t.Fatal(binary, e)
	}
	if e = atomicWrite(binary, []byte("external-change"), 0755); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ftpBinary("pure-pw"); e == nil {
		t.Fatal("changed runtime accepted or fell back silently")
	}
	if e = moduleWrite(filepath.Join(dir, "runtime.json"), map[string]string{"version": "../../usr/bin"}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ftpBinary("pure-pw"); e == nil {
		t.Fatal("runtime path injection accepted")
	}
	if _, e = s.ftpBinary("arbitrary-shell"); e == nil {
		t.Fatal("arbitrary program accepted")
	}
}
func TestFTPPrivateRuntimeInterruptedSelection(t *testing.T) {
	for _, phase := range []string{"before-selection", "after-selection", "external", "committed"} {
		t.Run(phase, func(t *testing.T) {
			s := ftpRuntimeFixture(t)
			dir := s.moduleDir("pure-ftpd")
			path := filepath.Join(dir, "runtime.json")
			next := []byte("{\"version\":\"" + ftpRuntimeVersion + "\"}\n")
			txn := ftpRuntimeTransaction{ID: core.ID(), State: "applying", NextSHA: core.Hash(string(next)), WasActive: true}
			if phase != "before-selection" {
				if e := atomicWrite(path, next, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if phase == "external" {
				atomicWrite(path, []byte("external-value"), 0600)
			}
			if phase == "committed" {
				txn.State = "committed"
			}
			moduleWrite(filepath.Join(dir, "pending-runtime.json"), txn)
			active, e := s.recoverFTPRuntime()
			if phase == "external" {
				b, _ := os.ReadFile(path)
				if e == nil || string(b) != "external-value" || !s.ftpRecoveryPending() {
					t.Fatal("external selection overwritten", e)
				}
				return
			}
			if e != nil || s.ftpRecoveryPending() {
				t.Fatal(e)
			}
			if phase == "committed" {
				b, _ := os.ReadFile(path)
				if string(b) != string(next) || active {
					t.Fatal("committed selection reverted")
				}
			} else if exists(path) || !active {
				t.Fatal("uncommitted selection not restored")
			}
		})
	}
}
func TestFTPPrivateRuntimeSwitchFailureRestoresLegacy(t *testing.T) {
	s := ftpRuntimeFixture(t)
	s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "is-active" {
			return "active", nil
		}
		if len(args) > 0 && args[0] == "restart" {
			return "", os.ErrPermission
		}
		return "", nil
	}
	e := s.activateFTPRuntime(context.Background())
	if e == nil || exists(filepath.Join(s.moduleDir("pure-ftpd"), "runtime.json")) || s.ftpRecoveryPending() {
		t.Fatal("failed runtime remained selected", e)
	}
}

func TestFTPStoppedRuntimeUpdatePreservesStoppedState(t *testing.T) {
	s := ftpRuntimeFixture(t)
	dir := s.moduleDir("pure-ftpd")
	cert, e := generateLocalFTPCertificate()
	if e != nil {
		t.Fatal(e)
	}
	atomicWrite(filepath.Join(dir, "server.pem"), cert, 0600)
	atomicWrite(filepath.Join(dir, "users.passwd"), nil, 0600)
	atomicWrite(filepath.Join(dir, "users.pdb"), []byte("test-index"), 0600)
	moduleWrite(filepath.Join(dir, "installed.json"), map[string]any{"id": "pure-ftpd", "version": "1.0.50-compat4", "installed_at": "original-install", "settings": map[string]any{}})
	s.Config.Run = func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "is-active" {
			return "inactive", os.ErrNotExist
		}
		if len(args) > 0 && args[0] == "is-enabled" {
			return "disabled", os.ErrNotExist
		}
		t.Fatal("stopped service changed", args)
		return "", nil
	}
	if e = s.updateSoftware(context.Background(), "pure-ftpd", "1.0.54-compat5", func(string) {}); e != nil {
		t.Fatal(e)
	}
	var m map[string]any
	moduleRead(filepath.Join(dir, "installed.json"), &m)
	if m["installed_at"] != "original-install" || m["version"] != "1.0.54-compat5" {
		t.Fatal(m)
	}
	if _, e = s.ftpBinary("pure-ftpd"); e != nil {
		t.Fatal(e)
	}
}
