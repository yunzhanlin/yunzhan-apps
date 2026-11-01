//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func TestApacheModuleHistoryUsesActualTransactionDirectory(t *testing.T) {
	old := unix.Umask(0027)
	defer unix.Umask(old)
	for _, c := range []struct {
		name string
		mode os.FileMode
	}{{"legacy0700", 0700}, {"producer0750", 0750}} {
		t.Run(c.name, func(t *testing.T) {
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
			initial, err := os.Lstat(dir)
			if err != nil || initial.Mode().Perm() != 0750 {
				t.Fatal("real producer mode missing", err)
			}
			if c.mode == 0700 {
				if err := os.Chmod(dir, c.mode); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := moduleWrite(filepath.Join(dir, "installed.json"), map[string]any{"id": "apache-waf", "version": core.ApacheWAFVersion, "settings": core.WAFSettings(core.DefaultApacheWAFConfig())}); err != nil {
				t.Fatal(err)
			}
			if err := s.moduleRetrospectivePreflight("apache-waf"); err != nil {
				t.Fatal("known absent history must be read-only", err)
			}
			private := "owned-raw-operation-value-must-not-be-an-event"
			if err := s.appendModuleEvent("apache-waf", "run", "manual", core.AppModuleInput{Token: private}, map[string]any{"raw": private}, nil); err != nil {
				t.Fatal("history ledger must accept the actual Apache transaction directory", err)
			}
			var ring []moduleEvent
			if err := s.moduleRetrospectiveRecord("apache-waf", "history.json", &ring); err != nil || len(ring) != 1 || ring[0].Action != "run" || ring[0].Outcome != "succeeded" {
				t.Fatal("compatible JSON ring not retained", ring, err)
			}
			if err := s.writeModuleRetrospectiveRecord("apache-waf", "last-report.json", map[string]any{"time": core.Now(), "action": "run", "result": map[string]any{"checked": true}, "error": ""}); err != nil {
				t.Fatal(err)
			}
			files := map[string][]byte{}
			identities := map[string]os.FileInfo{}
			for _, name := range []string{"installed.json", "history.json", "last-report.json", "history.sqlite"} {
				path := filepath.Join(dir, name)
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				owner, ok := info.Sys().(*syscall.Stat_t)
				if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
					t.Fatal("private history/installation file boundary changed", name)
				}
				raw, err := os.ReadFile(path)
				if err != nil || bytes.Contains(raw, []byte(private)) {
					t.Fatal("raw operation leaked into private summary", name, err)
				}
				files[name], identities[name] = raw, info
			}
			out, err := s.moduleHistory("apache-waf", core.AppModuleInput{Limit: 1})
			if err != nil {
				t.Fatal("read-only history failed", err)
			}
			raw, err := json.Marshal(out)
			var page struct {
				History  []moduleEvent `json:"history"`
				Total    int           `json:"total"`
				ReadOnly bool          `json:"read_only"`
				Source   string        `json:"source"`
			}
			if err != nil || json.Unmarshal(raw, &page) != nil || page.Total != 1 || len(page.History) != 1 || page.History[0].ID != ring[0].ID || !page.ReadOnly || page.Source != "private-sqlite" {
				t.Fatal("actual SQLite history differs from original JSON event", page, err)
			}
			for name, original := range files {
				path := filepath.Join(dir, name)
				actual, err := os.ReadFile(path)
				info, statErr := os.Lstat(path)
				if err != nil || statErr != nil || !bytes.Equal(original, actual) || !os.SameFile(info, identities[name]) || info.Mode() != identities[name].Mode() {
					t.Fatal("read-only history mutated original evidence", name, err, statErr)
				}
			}
			after, err := os.Lstat(dir)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("history rewrote or normalized its directory", err)
			}
		})
	}
}

func TestApacheModuleHistoryWriterDoesNotRelaxOtherDirectories(t *testing.T) {
	for _, c := range []struct {
		name, id string
		mode     os.FileMode
	}{
		{"task0750", "task-manager", 0750},
		{"network0750", "network-threat-detection", 0750},
		{"ApachePublic", "apache-waf", 0755},
		{"ApacheGroupWritable", "apache-waf", 0770},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := New(Config{SecurityDir: filepath.Join(t.TempDir(), "security")})
			dir := s.moduleDir(c.id)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, c.mode); err != nil {
				t.Fatal(err)
			}
			db, err := s.openModuleLedger(context.Background(), c.id)
			if db != nil {
				db.Close()
			}
			if err == nil {
				t.Fatal("history writer admitted unsafe/other module directory", c.name)
			}
			if _, err := os.Lstat(filepath.Join(dir, "history.sqlite")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal created/repaired a database", err)
			}
		})
	}
}

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
