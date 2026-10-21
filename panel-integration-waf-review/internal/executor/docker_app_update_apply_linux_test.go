//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

func TestMemcachedComposeSealedInputAndFixedInvocationNoMutableEnvironment(t *testing.T) {
	_, seed := memcachedJournalFixture(t)
	raw, err := core.MemcachedComposeUpdateTarget(seed.Record.Plan)
	if err != nil {
		t.Fatal(err)
	}
	f, err := memcachedComposeInput(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte("bad"), 0); err == nil {
		t.Fatal("sealed input writable")
	}
	if f.Truncate(0) == nil {
		t.Fatal("sealed input truncatable")
	}
	got, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(raw, got) {
		t.Fatal("sealed descriptor content", err)
	}
	cmd, err := memcachedComposeCommand(context.Background(), seed.Record.Dispatch.ProjectID, memcachedProjectEngine(seed.Record.Dispatch.ProjectID), f)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/docker", "compose", "--env-file", "/dev/null", "--project-directory", filepath.Join(dockerProjects, seed.Record.Dispatch.ProjectID), "--project-name", memcachedProjectEngine(seed.Record.Dispatch.ProjectID), "--file", "/proc/" + strconv.Itoa(os.Getpid()) + "/fd/" + strconv.FormatUint(uint64(f.Fd()), 10), "up", "--pull", "never", "--no-build", "--no-deps", "--force-recreate", "--detach", "--wait", "--wait-timeout", "150", "memcached"}
	if !reflect.DeepEqual(cmd.Args, want) || len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != f || !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "COMPOSE_DISABLE_ENV_FILE=1"}) {
		t.Fatal("unfixed command/environment boundary")
	}
	if _, err := memcachedComposeCommand(context.Background(), seed.Record.Dispatch.ProjectID, "foreign", f); err == nil {
		t.Fatal("foreign engine accepted")
	}
	unsealed, err := os.CreateTemp(t.TempDir(), "unsealed-")
	if err != nil {
		t.Fatal(err)
	}
	defer unsealed.Close()
	if _, err := memcachedComposeCommand(context.Background(), seed.Record.Dispatch.ProjectID, memcachedProjectEngine(seed.Record.Dispatch.ProjectID), unsealed); err == nil {
		t.Fatal("mutable source accepted")
	}
}

func TestMemcachedComposeActualCLISealedConfigurationReadOnlyQA(t *testing.T) {
	if *memcachedActualPlanProject == "" {
		t.Skip("explicit existing QA project required; configuration-only command never installs or updates")
	}
	if !core.ValidID(*memcachedActualPlanProject) || os.Geteuid() != 0 {
		t.Fatal("explicit Root QA identity required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	plan, err := memcachedAppUpdatePlanAt(ctx, dockerProjects, *memcachedActualPlanProject, memcachedUpdateDockerRead)
	if err != nil || plan.ComposeSHA256 != *memcachedActualComposeSHA {
		t.Fatal("existing actual project precondition", err)
	}
	raw, err := core.MemcachedComposeUpdateTarget(plan)
	if err != nil {
		t.Fatal(err)
	}
	f, err := memcachedComposeInput(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd, err := memcachedComposeCommand(ctx, plan.ProjectID, memcachedProjectEngine(plan.ProjectID), f)
	if err != nil {
		t.Fatal(err)
	}
	// Use the production prefix/descriptor/environment with an explicitly
	// read-only CLI operation; NEVER run the constructed up command in this test.
	cmd.Args = append(cmd.Args[:10], "config", "--format", "json")
	out := &boundedBuffer{max: 128 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil || out.truncated {
		t.Fatal("actual Compose plugin could not read the sealed parent descriptor", err)
	}
	var config struct {
		Services map[string]struct {
			Image   string   `json:"image"`
			Command []string `json:"command"`
		} `json:"services"`
	}
	if json.Unmarshal(out.Bytes(), &config) != nil || len(config.Services) != 1 || config.Services["memcached"].Image != appcatalog.MemcachedDigestImage || !reflect.DeepEqual(config.Services["memcached"].Command, []string{"memcached", "-m", "128", "-I", "4m"}) {
		t.Fatal("actual Compose interpreted another image or command")
	}
	after, err := memcachedAppUpdatePlanAt(ctx, dockerProjects, plan.ProjectID, memcachedUpdateDockerRead)
	if err != nil || after != plan {
		t.Fatal("read-only CLI changed original project or service", err)
	}
}

func TestMemcachedComposeExchangePreservesOriginalInodeAndRefusesReplayedOrChangedSource(t *testing.T) {
	for _, scenario := range []string{"target", "rollback", "source-replaced", "metadata-replaced", "source-changed", "detached", "existing-stage", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			store, seed := memcachedJournalFixture(t)
			base := filepath.Join(filepath.Dir(store.base), "compose")
			id := seed.Record.Dispatch.ProjectID
			for name, raw := range map[string][]byte{"compose.yaml": seed.OriginalCompose, "metadata.json": seed.OriginalMetadata} {
				if err := os.WriteFile(filepath.Join(base, id, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			d, err := openComposeUpdateDirectory(base, id)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			_, si, err := d.read("compose.yaml", 48<<10)
			if err != nil {
				t.Fatal(err)
			}
			_, mi, err := d.read("metadata.json", 16<<10)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			project := filepath.Join(base, id)
			switch scenario {
			case "source-replaced", "metadata-replaced":
				name := "compose.yaml"
				raw := seed.OriginalCompose
				if scenario == "metadata-replaced" {
					name = "metadata.json"
					raw = seed.OriginalMetadata
				}
				if os.Rename(filepath.Join(project, name), filepath.Join(project, name+".original")) != nil || os.WriteFile(filepath.Join(project, name), raw, 0600) != nil {
					t.Fatal("replace fixture")
				}
			case "source-changed":
				if os.WriteFile(filepath.Join(project, "compose.yaml"), append(seed.OriginalCompose, ' '), 0600) != nil {
					t.Fatal("change fixture")
				}
			case "detached":
				if os.Rename(base, base+".original") != nil || os.Mkdir(base, 0700) != nil {
					t.Fatal("detach fixture")
				}
			case "existing-stage":
				if os.WriteFile(filepath.Join(project, "compose.publish-"+seed.Record.Dispatch.JobID+".yaml"), []byte("foreign"), 0600) != nil {
					t.Fatal("stage fixture")
				}
			case "canceled":
				cancel()
			}
			err = d.publishMemcachedCompose(ctx, seed.Record, scenario == "rollback", si, mi)
			accepted := scenario == "target" || scenario == "rollback"
			if accepted != (err == nil) {
				t.Fatal("wrong exchange outcome", err)
			}
			if !accepted {
				return
			}
			want, _ := core.MemcachedComposeUpdateTarget(seed.Record.Plan)
			name := "compose.publish-" + seed.Record.Dispatch.JobID + ".yaml"
			if scenario == "rollback" {
				want, _ = core.MemcachedComposeRollback(seed.Record.Plan)
				name = "compose.rollback-" + seed.Record.Dispatch.JobID + ".yaml"
			}
			actual, _, err := d.read("compose.yaml", 48<<10)
			backup, bi, be := geoStoreReadIdentity(d.root, name, 48<<10)
			if err != nil || be != nil || !bytes.Equal(actual, want) || !bytes.Equal(backup, seed.OriginalCompose) || !os.SameFile(bi, si) {
				t.Fatal("exchange lost original inode/bytes", err, be)
			}
			if d.publishMemcachedCompose(ctx, seed.Record, scenario == "rollback", si, mi) == nil {
				t.Fatal("publication replayed")
			}
			if scenario == "rollback" && (!strings.Contains(string(actual), seed.Record.Plan.RuntimeImageID) || bytes.Equal(actual, seed.OriginalCompose)) {
				t.Fatal("rollback retained a mutable source tag")
			}
		})
	}
}
