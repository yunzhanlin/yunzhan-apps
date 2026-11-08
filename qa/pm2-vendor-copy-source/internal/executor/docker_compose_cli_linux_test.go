//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func composeCLIModelFixture(t *testing.T) dockerMutationStore {
	t.Helper()
	base := os.Getenv("PANEL_QA_MEMCACHED_MODEL_ROOT")
	if base == "" {
		return dockerMutationFixture(t)
	}
	if os.Geteuid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/memcached-sandbox24bksf-(arm64|amd64)\.[a-f0-9]{32}$`).MatchString(base) || threatIDSTrustedParents(base, false) != nil {
		t.Fatal("explicit trusted private CLI model fixture required")
	}
	root, err := os.MkdirTemp(base, "cli-model-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if filepath.Dir(root) != base || !strings.HasPrefix(filepath.Base(root), "cli-model-") {
			t.Error("refuse broad model cleanup")
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	state := filepath.Join(root, "state")
	if os.Mkdir(state, 0700) != nil || os.Mkdir(filepath.Join(state, "docker-jobs"), 0700) != nil || os.WriteFile(filepath.Join(state, "runtime-lifecycle.lock"), nil, 0600) != nil {
		t.Fatal("private CLI model initialization")
	}
	return dockerMutationStore{state: state}
}

func TestComposeCLIPrivateConfigIndependentOfHiddenPersonalHome(t *testing.T) {
	s := composeCLIModelFixture(t)
	env, err := composeCLIEnvironmentAt(s.state)
	if err != nil || !slices.Equal(env, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "DOCKER_CONFIG=" + filepath.Join(s.state, "docker-jobs", "cli-config")}) {
		t.Fatal("closed CLI environment", err)
	}
	name := filepath.Join(s.state, "docker-jobs", "cli-config", "config.json")
	before, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(name)
	if err != nil || string(raw) != "{}" || before.Mode().Perm() != 0600 {
		t.Fatal("private empty CLI config")
	}
	again, err := composeCLIEnvironmentAt(s.state)
	after, _ := os.Lstat(name)
	if err != nil || !slices.Equal(again, env) || !geoStoreStableInfo(before, after) {
		t.Fatal("readonly reuse changed configuration", err)
	}
	for _, value := range env {
		if strings.HasPrefix(value, "HOME=") || strings.HasPrefix(value, "DOCKER_HOST=") || strings.Contains(value, "/root/.docker") {
			t.Fatal("personal credentials or remote context adopted")
		}
	}
}

func TestComposeCLIPrivateConfigRefusesExistingUnsafeOrForeignStateWithoutRepair(t *testing.T) {
	for _, name := range []string{"empty-partial", "directory-symlink", "public-directory", "public-file", "hardlink", "file-symlink", "credentials", "remote-context", "extra-plugin", "truncated", "mode-zero"} {
		t.Run(name, func(t *testing.T) {
			s := composeCLIModelFixture(t)
			base := filepath.Join(s.state, "docker-jobs", "cli-config")
			if name == "empty-partial" || name == "directory-symlink" {
				if name == "empty-partial" {
					if os.Mkdir(base, 0700) != nil {
						t.Fatal("fixture")
					}
				} else {
					target := filepath.Join(s.state, "foreign")
					os.Mkdir(target, 0700)
					if os.Symlink(target, base) != nil {
						t.Fatal("fixture")
					}
				}
			} else {
				if _, err := composeCLIEnvironmentAt(s.state); err != nil {
					t.Fatal(err)
				}
				file := filepath.Join(base, "config.json")
				switch name {
				case "public-directory":
					os.Chmod(base, 0755)
				case "public-file":
					os.Chmod(file, 0644)
				case "mode-zero":
					os.Chmod(file, 0)
				case "hardlink":
					if os.Link(file, filepath.Join(s.state, "linked-config")) != nil {
						t.Fatal("fixture")
					}
				case "file-symlink":
					os.Rename(file, filepath.Join(s.state, "original-config"))
					os.Symlink(filepath.Join(s.state, "original-config"), file)
				case "credentials":
					os.WriteFile(file, []byte(`{"auths":{"registry.example":{"auth":"must-not-use"}}}`), 0600)
				case "remote-context":
					os.WriteFile(file, []byte(`{"currentContext":"remote"}`), 0600)
				case "extra-plugin":
					os.WriteFile(filepath.Join(base, "plugin-config"), []byte("foreign"), 0600)
				case "truncated":
					os.WriteFile(file, []byte("{"), 0600)
				}
			}
			before, _ := os.Lstat(base)
			fileBefore, fileErr := os.Lstat(filepath.Join(base, "config.json"))
			if env, err := composeCLIEnvironmentAt(s.state); err == nil || env != nil {
				t.Fatal("unsafe client configuration adopted", name)
			}
			after, _ := os.Lstat(base)
			fileAfter, afterErr := os.Lstat(filepath.Join(base, "config.json"))
			if !geoStoreStableInfo(before, after) || (fileErr == nil) != (afterErr == nil) || (fileErr == nil && !geoStoreStableInfo(fileBefore, fileAfter)) {
				t.Fatal("pre-existing configuration was repaired or replaced")
			}
		})
	}
}
