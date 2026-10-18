//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func securityManifestFixture(t *testing.T, id string) (*Service, string, []byte) {
	t.Helper()
	s := New(Config{SecurityDir: filepath.Join(t.TempDir(), "security"), SystemRoot: t.TempDir()})
	manifest := softwareManifest{ID: id, Version: core.SoftwareImplementationVersion(id), Settings: map[string]any{"fixture": "private-value-not-returned"}, InstalledAt: core.Now()}
	if err := s.writeSoftwareManifest(manifest); err != nil {
		t.Fatal(err)
	}
	path := s.softwareManifestPath(id)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return s, path, raw
}

func TestSecurityManifestKnownAbsenceAndLegacyPrivateMode(t *testing.T) {
	for _, id := range []string{"nginx-waf", "system-hardening", "intrusion-prevention"} {
		for _, mode := range []os.FileMode{0600, 0640} {
			t.Run(id+"/"+mode.String(), func(t *testing.T) {
				s, path, raw := securityManifestFixture(t, id)
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
				before, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				manifest, err := s.readSoftwareManifest(id)
				if err != nil || manifest.ID != id || manifest.Version != core.SoftwareImplementationVersion(id) {
					t.Fatal(manifest, err)
				}
				after, err := os.Lstat(path)
				actual, readErr := os.ReadFile(path)
				if err != nil || readErr != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() || !bytes.Equal(raw, actual) {
					t.Fatal("read rewrote private legacy record")
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if _, err := s.readSoftwareManifest(id); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("known absence lost", err)
				}
				if status := s.softwareStatus(context.Background(), id); status.StateUnknown || status.Installed {
					t.Fatal(status)
				}
			})
		}
	}
}

func TestSecurityManifestUntrustedRecordsFreezeAllActions(t *testing.T) {
	modes := []string{"public-file", "group-writable", "writable-anchor", "foreign-owner", "foreign-group", "foreign-anchor", "symlink-file", "symlink-anchor", "hardlink", "fifo", "directory", "oversized", "malformed", "duplicate", "escaped-duplicate", "case-duplicate", "nested-duplicate", "wrong-id", "future-version", "unknown-field", "trailing-json", "deep-json", "node-budget"}
	for _, id := range []string{"nginx-waf", "system-hardening", "intrusion-prevention"} {
		for _, mode := range modes {
			t.Run(id+"/"+mode, func(t *testing.T) {
				s, path, raw := securityManifestFixture(t, id)
				outside := filepath.Join(t.TempDir(), "owned-sentinel.json")
				if err := os.WriteFile(outside, raw, 0600); err != nil {
					t.Fatal(err)
				}
				must := func(err error) {
					t.Helper()
					if err != nil {
						t.Fatal(err)
					}
				}
				write := func(data string) { must(os.WriteFile(path, []byte(data), 0600)) }
				inspectRecord := func() (os.FileInfo, error) { return os.Lstat(path) }
				switch mode {
				case "public-file":
					must(os.Chmod(path, 0644))
				case "group-writable":
					must(os.Chmod(path, 0660))
				case "writable-anchor":
					must(os.Chmod(s.Config.SecurityDir, 0777))
				case "foreign-owner", "foreign-group", "foreign-anchor":
					if os.Geteuid() != 0 {
						t.Skip("actual root fixture required for foreign UID/GID")
					}
					if mode == "foreign-owner" {
						must(os.Chown(path, 1, -1))
					}
					if mode == "foreign-group" {
						must(os.Chmod(path, 0640))
						must(os.Chown(path, -1, 1))
					}
					if mode == "foreign-anchor" {
						// No DAC override is granted to this native fixture. Pin the
						// owned leaf before removing traversal permission, so metadata
						// checks themselves do not require bypassing that protection.
						pinned, err := os.Open(path)
						must(err)
						inspectRecord = pinned.Stat
						t.Cleanup(func() {
							pinned.Close()
							if err := os.Chown(s.Config.SecurityDir, os.Geteuid(), -1); err != nil {
								t.Error(err)
							}
						})
						must(os.Chown(s.Config.SecurityDir, 1, -1))
					}
				case "symlink-file":
					must(os.Remove(path))
					must(os.Symlink(outside, path))
				case "symlink-anchor":
					retained := s.Config.SecurityDir + ".owned-retained"
					must(os.Rename(s.Config.SecurityDir, retained))
					must(os.Symlink(retained, s.Config.SecurityDir))
				case "hardlink":
					must(os.Remove(path))
					must(os.Link(outside, path))
				case "fifo":
					must(os.Remove(path))
					must(unix.Mkfifo(path, 0600))
				case "directory":
					must(os.Remove(path))
					must(os.Mkdir(path, 0700))
				case "oversized":
					must(os.Truncate(path, softwareManifestRecordBytes+1))
				case "malformed":
					write("{")
				case "duplicate":
					write(`{"id":"` + id + `","id":"` + id + `","version":"1.0"}`)
				case "escaped-duplicate":
					write(`{"id":"` + id + `","\u0069d":"` + id + `","version":"1.0"}`)
				case "case-duplicate":
					write(`{"id":"` + id + `","ID":"` + id + `","version":"1.0"}`)
				case "nested-duplicate":
					write(`{"id":"` + id + `","version":"1.0","settings":{"profile":"baseline","profile":"strict"}}`)
				case "wrong-id":
					write(`{"id":"foreign-app","version":"1.0"}`)
				case "future-version":
					write(`{"id":"` + id + `","version":"99.0"}`)
				case "unknown-field":
					write(`{"id":"` + id + `","version":"1.0","future":"unsupported"}`)
				case "trailing-json":
					write(string(raw) + "{}")
				case "deep-json":
					write(`{"id":"` + id + `","version":"1.0","settings":{"deep":` + strings.Repeat("[", 20) + "0" + strings.Repeat("]", 20) + "}}")
				case "node-budget":
					write(`{"id":"` + id + `","version":"1.0","settings":{"large":[` + strings.Repeat("0,", 100001) + "0]}}")
				}
				before, err := inspectRecord()
				must(err)
				anchorBefore, err := os.Lstat(s.Config.SecurityDir)
				must(err)
				commands := 0
				s.Config.Run = func(context.Context, string, ...string) (string, error) {
					commands++
					return "", errors.New("unexpected external command")
				}
				if _, err := s.readSoftwareManifest(id); err == nil || errors.Is(err, os.ErrNotExist) {
					t.Fatal("untrusted record became readable or absent", mode, err)
				}
				status := s.softwareStatus(context.Background(), id)
				if !status.StateUnknown || status.Installed || status.Healthy || status.Settings != nil {
					t.Fatal("untrusted status certified installation", status)
				}
				for _, action := range []string{"install", "configure", "uninstall", "update"} {
					w := httptest.NewRecorder()
					s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/software/"+id+"/"+action, strings.NewReader(`{"settings":{},"version":"1.0"}`)))
					var response map[string]any
					must(json.Unmarshal(w.Body.Bytes(), &response))
					if w.Code != 409 || response["state_unknown"] != true || strings.Contains(w.Body.String(), "private-value-not-returned") {
						t.Fatal("unknown action was dispatched or exposed", action, w.Code, w.Body.String())
					}
				}
				if id == "system-hardening" {
					if err := s.applyHardening(context.Background(), map[string]any{"profile": "baseline"}, true, func(string) {}); err == nil {
						t.Fatal("direct hardening installed over unknown record")
					}
				}
				if id == "intrusion-prevention" {
					if err := s.applyIntrusion(context.Background(), map[string]any{}, true, func(string) {}); err == nil {
						t.Fatal("direct intrusion installed over unknown record")
					}
				}
				if id == "nginx-waf" {
					for _, request := range []struct{ method, path, body string }{{"GET", "/v1/software/nginx-waf/events", ""}, {"POST", "/v1/software/nginx-waf/preview", `{}`}} {
						w := httptest.NewRecorder()
						s.Handler().ServeHTTP(w, httptest.NewRequest(request.method, request.path, strings.NewReader(request.body)))
						var response map[string]any
						must(json.Unmarshal(w.Body.Bytes(), &response))
						if w.Code != 409 || response["state_unknown"] != true {
							t.Fatal("unknown WAF record was treated as absent", request.path, w.Code, w.Body.String())
						}
					}
					if err := s.applyWAF(context.Background(), map[string]any{}, true, func(string) {}); err == nil {
						t.Fatal("direct WAF installed over unknown record")
					}
				}
				if commands != 0 {
					t.Fatal("untrusted record executed commands", commands)
				}
				after, err := inspectRecord()
				must(err)
				anchorAfter, err := os.Lstat(s.Config.SecurityDir)
				must(err)
				ownerBefore, ownerAfter := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
				if !os.SameFile(before, after) || !os.SameFile(anchorBefore, anchorAfter) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || ownerBefore.Uid != ownerAfter.Uid || ownerBefore.Gid != ownerAfter.Gid || ownerBefore.Nlink != ownerAfter.Nlink {
					t.Fatal("untrusted record identity or metadata changed")
				}
				actual, err := os.ReadFile(outside)
				must(err)
				if !bytes.Equal(actual, raw) {
					t.Fatal("owned outside sentinel changed")
				}
			})
		}
	}
}
