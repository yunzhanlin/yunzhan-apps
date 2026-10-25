//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
)

func dockerObservationFixture(t *testing.T) (string, core.DockerJobResult) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("actual trusted ancestry requires Linux Root")
	}
	if err := threatIDSTrustedParents("/var/lib/panel-executor", true); err != nil {
		t.Fatal(err)
	}
	state, err := os.MkdirTemp("/var/lib/panel-executor", "docker-observation-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if filepath.Dir(state) != "/var/lib/panel-executor" || !strings.HasPrefix(filepath.Base(state), "docker-observation-fixture-") {
			t.Fatal("refuse broad fixture cleanup")
		}
		if err := os.RemoveAll(state); err != nil {
			t.Error(err)
		}
	})
	if err := os.Mkdir(filepath.Join(state, "docker-jobs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "runtime-lifecycle.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	value := core.DockerJobResult{JobID: core.ID(), ProjectID: core.ID(), Kind: "compose", State: "running"}
	if err := writeJSON(filepath.Join(state, "docker-jobs", value.JobID+".result.json"), value); err != nil {
		t.Fatal(err)
	}
	return state, value
}

func TestDockerJobObservationReadsOriginalWhileWorkerHoldsMutationLease(t *testing.T) {
	state, value := dockerObservationFixture(t)
	store := dockerMutationStore{state: state, blocked: func() bool { return false }, pending: func(context.Context) error { return nil }}
	lease, err := store.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	file := filepath.Join(state, "docker-jobs", value.JobID+".result.json")
	before, _ := os.ReadFile(file)
	info, _ := os.Lstat(file)
	done := make(chan error, 1)
	go func() {
		out, err := readDockerJobObservation(state, value.JobID)
		if err == nil && out != value {
			err = errDockerObservation
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("read-only poll competed for worker mutation lease", err)
		}
	case <-time.After(time.Second):
		t.Fatal("read-only poll blocked behind worker")
	}
	after, _ := os.ReadFile(file)
	named, _ := os.Lstat(file)
	if string(before) != string(after) || !geoStoreStableInfo(info, named) {
		t.Fatal("observer changed original bytes or inode")
	}
	files, _ := os.ReadDir(filepath.Dir(file))
	if len(files) != 2 { // Original result plus the worker's existing compose.lock.
		t.Fatal("observer created an intent, repair or result", len(files))
	}
}

func TestDockerJobObservationRefusesUnsafeOriginalsWithoutRepair(t *testing.T) {
	for _, scenario := range []string{"missing", "partial", "duplicate", "foreign", "unknown-field", "writable", "linked", "hardlinked", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			state, value := dockerObservationFixture(t)
			file := filepath.Join(state, "docker-jobs", value.JobID+".result.json")
			raw, _ := json.Marshal(value)
			switch scenario {
			case "missing":
				os.Remove(file)
			case "partial":
				os.WriteFile(file, []byte("{"), 0600)
			case "duplicate":
				os.WriteFile(file, append(raw[:len(raw)-1], []byte(`,"state":"succeeded"}`)...), 0600)
			case "foreign":
				value.JobID = core.ID()
				writeJSON(file, value)
			case "unknown-field":
				os.WriteFile(file, append(raw[:len(raw)-1], []byte(`,"extra":true}`)...), 0600)
			case "writable":
				os.Chmod(file, 0644)
			case "linked":
				os.Rename(file, file+".original")
				os.Symlink(file+".original", file)
			case "hardlinked":
				os.Link(file, file+".original")
			case "oversized":
				os.WriteFile(file, []byte(strings.Repeat("x", 32769)), 0600)
			}
			before, _ := os.ReadFile(file)
			info, _ := os.Lstat(file)
			// The requested original ID is the fixed basename, even in foreign JSON.
			id := strings.TrimSuffix(filepath.Base(file), ".result.json")
			if _, err := readDockerJobObservation(state, id); err == nil {
				t.Fatal("unsafe original accepted")
			}
			after, _ := os.ReadFile(file)
			named, _ := os.Lstat(file)
			if string(before) != string(after) || (info == nil) != (named == nil) || info != nil && !os.SameFile(info, named) {
				t.Fatal("unsafe original repaired/replaced")
			}
		})
	}
}
