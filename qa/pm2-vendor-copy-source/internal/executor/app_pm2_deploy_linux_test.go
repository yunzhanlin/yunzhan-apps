//go:build linux

package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func testPM2LockFile(t *testing.T, resolved string, link bool) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"lockfileVersion": 3, "packages": map[string]any{"": map[string]any{}, "node_modules/is-number": map[string]any{"resolved": resolved, "integrity": "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64)), "link": link}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPM2DependencyValidationFrozenQueueAndCrossProcessLock(t *testing.T) {
	s, site, _ := appReliabilityFixture(t)
	s.Config.Run = func(context.Context, string, ...string) (string, error) { return "activating", nil }
	manifest := []byte("{\n \"dependencies\": {\"is-number\": \"7.0.0\"}, \"private\": true\n}")
	valid := testPM2LockFile(t, "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz", false)
	if err := validatePM2Packages(manifest, valid); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"https://user:secret@registry.npmjs.org/a.tgz", "https://evil.example/a.tgz", "http://registry.npmjs.org/a.tgz", "file:../other", "git+https://github.com/user/repo", "https://registry.npmjs.org/a.tgz?token=secret"} {
		if validatePM2Packages(manifest, testPM2LockFile(t, source, false)) == nil {
			t.Fatal("unsafe source accepted", source)
		}
	}
	if validatePM2Packages(manifest, testPM2LockFile(t, "https://registry.npmjs.org/a.tgz", true)) == nil {
		t.Fatal("local link accepted")
	}
	fixtureWrite(t, s, site, "package.json", string(manifest))
	fixtureWrite(t, s, site, "package-lock.json", string(valid))
	app := pm2App{ID: "qa-dependencies", SiteID: site, Revision: 2}
	if _, err := s.queuePM2Dependencies(context.Background(), app, 1); err == nil {
		t.Fatal("stale revision accepted")
	}
	result, err := s.queuePM2Dependencies(context.Background(), app, 2)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(result)
	if strings.Contains(string(public), "\"dependencies\":") || strings.Contains(string(public), "is-number") {
		t.Fatal("private manifest exposed", string(public))
	}
	job, err := s.pm2LastDeployment(app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(job.Package) != string(manifest) || string(job.Lock) != string(valid) || core.Hash(string(job.Package)) != job.PackageSHA {
		t.Fatal("JSON storage changed frozen manifest bytes")
	}
	if _, err := s.queuePM2Dependencies(context.Background(), app, 2); err == nil {
		t.Fatal("queued job replaced")
	}
	first, err := s.lockPM2Project(app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := s.lockPM2Project(app.ID); err == nil {
		second.Close()
		t.Fatal("concurrent project mutation accepted")
	}
	first.Close()
	third, err := s.lockPM2Project(app.ID)
	if err != nil {
		t.Fatal("released lock retained", err)
	}
	third.Close()
}

func TestPM2DependencyInterruptedSwitchRecoveryAndNoClobber(t *testing.T) {
	for _, phase := range []string{"before-switch", "old-moved", "new-moved", "user-replacement", "first-install"} {
		t.Run(phase, func(t *testing.T) {
			base := t.TempDir()
			publicPath := filepath.Join(base, "public")
			stagePath := filepath.Join(base, "stage")
			for _, path := range []string{publicPath, stagePath, filepath.Join(stagePath, "node_modules")} {
				if err := os.MkdirAll(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			newInfo, _ := os.Stat(filepath.Join(stagePath, "node_modules"))
			newStat := newInfo.Sys().(*syscall.Stat_t)
			job := pm2Deployment{NewDevice: uint64(newStat.Dev), NewInode: newStat.Ino}
			if phase != "first-install" {
				if err := os.Mkdir(filepath.Join(publicPath, "node_modules"), 0755); err != nil {
					t.Fatal(err)
				}
				oldInfo, _ := os.Stat(filepath.Join(publicPath, "node_modules"))
				oldStat := oldInfo.Sys().(*syscall.Stat_t)
				job.OldDevice = uint64(oldStat.Dev)
				job.OldInode = oldStat.Ino
			}
			public, err := os.OpenRoot(publicPath)
			if err != nil {
				t.Fatal(err)
			}
			defer public.Close()
			stage, err := os.OpenRoot(stagePath)
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Close()
			p, _ := public.Open(".")
			defer p.Close()
			d, _ := stage.Open(".")
			defer d.Close()
			if phase != "before-switch" && phase != "first-install" {
				if err := unix.Renameat2(int(p.Fd()), "node_modules", int(d.Fd()), "previous-node_modules", unix.RENAME_NOREPLACE); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "new-moved" || phase == "first-install" {
				if err := unix.Renameat2(int(d.Fd()), "node_modules", int(p.Fd()), "node_modules", unix.RENAME_NOREPLACE); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "user-replacement" {
				if err := public.Mkdir("node_modules", 0755); err != nil {
					t.Fatal(err)
				}
				if recoverPM2DependencyDirectories(public, stage, job) == nil {
					t.Fatal("user replacement overwritten")
				}
				if _, err := stage.Stat("previous-node_modules"); err != nil {
					t.Fatal("old backup lost")
				}
				return
			}
			if err := recoverPM2DependencyDirectories(public, stage, job); err != nil {
				t.Fatal(err)
			}
			if phase == "first-install" {
				if _, err := public.Stat("node_modules"); !os.IsNotExist(err) {
					t.Fatal("failed first dependencies remain live")
				}
			} else if matches, err := pm2DirectoryIdentity(public, "node_modules", job.OldDevice, job.OldInode); err != nil || !matches {
				t.Fatal("old dependency identity not restored", err)
			}
			if phase == "new-moved" || phase == "first-install" {
				if _, err := stage.Stat("failed-node_modules"); err != nil {
					t.Fatal("failed dependencies discarded", err)
				}
			}
		})
	}
}
