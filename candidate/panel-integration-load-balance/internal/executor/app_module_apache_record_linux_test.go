//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func TestApacheModuleTransactionDirectoryMatchesPrivateRecordReader(t *testing.T) {
	// Match the managed executor's0027 umask and invoke its actual directory
	// producer. Merely chmodding a hand-written fixture misses the mismatch.
	old := unix.Umask(0027)
	defer unix.Umask(old)
	root := t.TempDir()
	s := New(Config{SystemRoot: root, SecurityDir: filepath.Join(root, "security"), ConfDir: filepath.Join(root, "nginx/sites"), StateDir: filepath.Join(root, "state")})
	lock, err := s.apacheWAFTransactionService().lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	dir := s.moduleDir("apache-waf")
	before, err := os.Lstat(dir)
	if err != nil || before.Mode().Perm() != 0750 {
		t.Fatal("actual transaction producer did not create0750", before, err)
	}
	if status := s.appModuleStatus(context.Background(), "apache-waf"); status.StateUnknown || status.Installed || status.Healthy {
		t.Fatal("build-before-install must have known absent application state", status)
	}
	path := filepath.Join(dir, "installed.json")
	if _, err := s.moduleInstalledRecord("apache-waf"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("actual missing record must stay missing", err)
	}
	if err := moduleWrite(path, map[string]any{"id": "apache-waf", "version": core.ApacheWAFVersion, "settings": core.WAFSettings(core.DefaultApacheWAFConfig())}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Lstat(path)
	if err != nil || file.Mode().Perm() != 0600 {
		t.Fatal("record confidentiality changed", err)
	}
	record, err := s.moduleInstalledRecord("apache-waf")
	if err != nil || record["id"] != "apache-waf" || record["version"] != core.ApacheWAFVersion {
		t.Fatal("private record under the actual transaction directory was unreadable", record, err)
	}
	after, err := os.Lstat(dir)
	actual, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() || string(actual) != string(raw) {
		t.Fatal("read adopted or modified existing directory/record")
	}
}

func TestApacheModuleDirectoryAdmissionDoesNotRelaxOtherPermissions(t *testing.T) {
	for _, c := range []struct {
		name, id        string
		directory, file os.FileMode
	}{
		{"Apache-public", "apache-waf", 0755, 0600},
		{"Apache-group-write", "apache-waf", 0770, 0600},
		{"Apache-other-execute", "apache-waf", 0751, 0600},
		{"Apache-unrecognized-group-mode", "apache-waf", 0710, 0600},
		{"Apache-setgid", "apache-waf", 0750 | os.ModeSetgid, 0600},
		{"Apache-public-record", "apache-waf", 0750, 0640},
		{"ordinary-module0750", "task-manager", 0750, 0600},
		{"network-module0750", "network-threat-detection", 0750, 0600},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := New(Config{SecurityDir: filepath.Join(t.TempDir(), "security")})
			path := filepath.Join(s.moduleDir(c.id), "installed.json")
			if err := moduleWrite(path, map[string]any{"id": c.id, "settings": map[string]any{}}); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Dir(path), c.directory); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, c.file); err != nil {
				t.Fatal(err)
			}
			if _, err := s.moduleInstalledRecord(c.id); err == nil || errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe mode became known installation/absence", c, err)
			}
		})
	}
}

func TestApacheModuleOpenedDirectoryIdentityRemainsBound(t *testing.T) {
	s := New(Config{SecurityDir: filepath.Join(t.TempDir(), "security")})
	dir := s.moduleDir("apache-waf")
	if err := moduleWrite(filepath.Join(dir, "installed.json"), map[string]any{"id": "apache-waf", "settings": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	opened, err := s.moduleRecordDirectory("apache-waf")
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if !opened.current() {
		t.Fatal("approved actual directory cannot be rechecked")
	}
	retained := dir + "-retained"
	if err := os.Rename(dir, retained); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatal(err)
	}
	if opened.current() {
		t.Fatal("detached old Apache directory was accepted after replacement")
	}
}
