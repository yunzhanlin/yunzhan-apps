//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func memcachedPlanFileFixture(t *testing.T) (string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("actual trusted-root filesystem fixture requires Linux Root")
	}
	if err := threatIDSTrustedParents("/var/lib/panel-executor", true); err != nil {
		t.Fatal(err)
	}
	parent, err := os.MkdirTemp("/var/lib/panel-executor", "memcached-plan-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if filepath.Dir(parent) != "/var/lib/panel-executor" || !strings.HasPrefix(filepath.Base(parent), "memcached-plan-fixture-") {
			t.Error("refuse broad fixture cleanup")
			return
		}
		if err := os.RemoveAll(parent); err != nil {
			t.Error(err)
		}
	})
	base := filepath.Join(parent, "compose")
	id := strings.Repeat("a", 32)
	if os.Mkdir(base, 0700) != nil || os.Mkdir(filepath.Join(base, id), 0700) != nil {
		t.Fatal("private fixture directories")
	}
	for name, body := range map[string]string{"metadata.json": "{\"fixture\":true}", "compose.yaml": "source fixture\n"} {
		if err := os.WriteFile(filepath.Join(base, id, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return base, id
}

func TestMemcachedUpdateTrustedFilesRejectUnsafePathsWithoutRepair(t *testing.T) {
	for _, scenario := range []string{"normal", "public-project", "public-file", "foreign-owner", "file-symlink", "directory-symlink", "hardlink", "fifo", "detached-parent", "replaced-file", "missing-file"} {
		t.Run(scenario, func(t *testing.T) {
			base, id := memcachedPlanFileFixture(t)
			project := filepath.Join(base, id)
			file := filepath.Join(project, "compose.yaml")
			switch scenario {
			case "public-project":
				if err := os.Chmod(project, 0755); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.Chmod(file, 0644); err != nil {
					t.Fatal(err)
				}
			case "foreign-owner":
				if err := os.Chown(file, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "file-symlink":
				if err := os.Rename(file, file+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("compose.yaml.original", file); err != nil {
					t.Fatal(err)
				}
			case "directory-symlink":
				if err := os.Rename(project, project+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(id+".original", project); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(file, file+".other"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(file, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-file":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			}
			d, err := openComposeUpdateDirectory(base, id)
			if scenario == "public-project" || scenario == "directory-symlink" {
				if err == nil {
					d.Close()
					t.Fatal("unsafe directory opened")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if scenario == "detached-parent" {
				if err := os.Rename(base, base+".detached"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(base, 0700); err != nil {
					t.Fatal(err)
				}
				if d.current() {
					t.Fatal("detached named ancestry accepted")
				}
			}
			if scenario == "replaced-file" {
				_, before, err := d.read("compose.yaml", 4096)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(file, file+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte("source fixture\n"), 0600); err != nil {
					t.Fatal(err)
				}
				_, after, err := d.read("compose.yaml", 4096)
				if err != nil || sameComposeUpdateFile(before, after) {
					t.Fatal("replacement with identical bytes adopted")
				}
				return
			}
			raw, _, err := d.read("compose.yaml", 4096)
			if scenario == "normal" {
				if err != nil || string(raw) != "source fixture\n" {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe file accepted", scenario)
			}
			if scenario == "public-file" {
				info, _ := os.Lstat(file)
				if info.Mode().Perm() != 0644 {
					t.Fatal("reader repaired unsafe permissions")
				}
			}
		})
	}
}

var memcachedActualPlanProject = flag.String("memcached-plan-native-project", "", "explicit existing QA Memcached project for production read-only preview; never installs one")
var memcachedActualComposeSHA = flag.String("memcached-plan-native-compose-sha", "", "independently observed existing QA compose SHA")

func TestMemcachedAppUpdatePlanActualExistingReadOnlyQA(t *testing.T) {
	if *memcachedActualPlanProject == "" {
		t.Skip("explicit existing QA project required, no installation or guessed inventory")
	}
	if os.Geteuid() != 0 || !core.ValidID(*memcachedActualPlanProject) || len(*memcachedActualComposeSHA) != 64 {
		t.Fatal("explicit Root QA identity required")
	}
	project := *memcachedActualPlanProject
	d, err := openComposeUpdateDirectory(dockerProjects, project)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	before, bi, err := d.read("compose.yaml", 48*1024)
	if err != nil || core.Hash(string(before)) != *memcachedActualComposeSHA {
		t.Fatal("original observed configuration changed", err)
	}
	metadata, mi, err := d.read("metadata.json", 16*1024)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	calls := 0
	read := func(ctx context.Context, path string, out any) error {
		calls++
		_, err := dockerRequest(ctx, http.MethodGet, path, nil, out, 1024*1024)
		return err
	}
	plan, err := memcachedAppUpdatePlanAt(ctx, dockerProjects, project, read)
	if err != nil || calls != 4 || core.ValidateMemcachedUpdatePlan(plan, project) != nil || plan.ComposeSHA256 != *memcachedActualComposeSHA {
		t.Fatal("actual production reader did not return a bound preview", calls, err)
	}
	after, ai, err := d.read("compose.yaml", 48*1024)
	if err != nil || !bytes.Equal(before, after) || !sameComposeUpdateFile(bi, ai) {
		t.Fatal("preview changed original compose", err)
	}
	ma, mai, err := d.read("metadata.json", 16*1024)
	if err != nil || !bytes.Equal(metadata, ma) || !sameComposeUpdateFile(mi, mai) {
		t.Fatal("preview changed original metadata", err)
	}
	raw, _ := json.Marshal(plan)
	t.Logf("actual existing read-only preview: %s", raw)
}
