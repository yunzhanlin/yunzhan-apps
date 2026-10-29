//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

// Synthetic sealed metadata only, not app/data-signature or installed authority.
func countryProgramQueueFixture(t *testing.T, state string) (string, string, countryTaskRequest) {
	t.Helper()
	root := programQueueFixture(t)
	_, request, envelope := countryTaskFixture(t)
	dir := filepath.Join(root, "var/lib/panel-executor/waf-country-jobs", request.JobID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(dir), "store.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	result := countryTaskOperation(request, state, "synthetic clean pre-transfer refusal")
	if state == "succeeded" {
		in := request.Selection
		result.Error = ""
		result.Cache = &core.WAFCountryCacheEntry{Dataset: core.WAFCountryCacheDataset(in), DataManifestSHA: in.DataManifestSHA, Countries: append([]string{}, in.Countries...), Release: in.Release, Revision: in.Revision, OriginalJobID: request.JobID, PlanSHA: core.WAFCountryCachePlanSHA(request.JobID, in), PreparedAt: request.PreparedAt, Bytes: 1, Networks: 1, Published: true}
	}
	values := map[string]any{"request.json": request, "dispatch.json": countryTaskDispatch{1, request.JobID, countryTaskRequestDigest(request), countryFixtureBoot, request.PreparedAt}, "started.json": countryTaskSyntheticStarted(request), "result.json": result}
	for name, value := range values {
		raw, err := countryCacheJSON(value)
		if err != nil || os.WriteFile(filepath.Join(dir, name), raw, 0600) != nil {
			t.Fatal("synthetic metadata fixture could not be written", err)
		}
	}
	if os.WriteFile(filepath.Join(dir, "envelope.json"), envelope, 0600) != nil || os.WriteFile(filepath.Join(dir, "task.lock"), nil, 0600) != nil {
		t.Fatal("synthetic original envelope/lock fixture")
	}
	return root, dir, request
}

func assertCountryProgramQueueReadonly(t *testing.T, root string, reject bool) {
	t.Helper()
	before := programQueueTree(t, root)
	err := checkProgramUpgradeQueues(context.Background(), root)
	if (err != nil) != reject {
		t.Fatal("country upgrade admission differs", reject, err)
	}
	if !reflect.DeepEqual(before, programQueueTree(t, root)) {
		t.Fatal("country upgrade observer rewrote, repaired or removed original evidence")
	}
}

func TestProgramUpgradeCountryOnlyCompleteBoundTerminalAllowsReadonlyAdmission(t *testing.T) {
	for _, state := range []string{"succeeded", "failed"} {
		t.Run(state, func(t *testing.T) {
			root, _, _ := countryProgramQueueFixture(t, state)
			assertCountryProgramQueueReadonly(t, root, false)
		})
	}
	root := programQueueFixture(t)
	assertCountryProgramQueueReadonly(t, root, false)
}

func TestProgramUpgradeCountryEveryIncompleteUnknownOrChangedSealIsRetained(t *testing.T) {
	for _, kind := range []string{"request.json", "envelope.json", "dispatch.json", "started.json", "result.json", "task.lock", "actor", "boot", "ticks", "result-alias", "needs-attention", "payload", "envelope-hash", "unknown", "permissions", "hardlink", "unfinished-stage"} {
		t.Run(kind, func(t *testing.T) {
			root, dir, _ := countryProgramQueueFixture(t, "failed")
			mutate := func(name string, edit func(map[string]any)) {
				t.Helper()
				file := filepath.Join(dir, name)
				raw, err := os.ReadFile(file)
				var value map[string]any
				if err != nil || json.Unmarshal(raw, &value) != nil {
					t.Fatal(err)
				}
				edit(value)
				raw, err = json.Marshal(value)
				// Keep the production canonical struct encoding, so semantic
				// negatives reach the intended binding check, not whitespace.
				if err == nil && name == "request.json" {
					var typed countryTaskRequest
					err = json.Unmarshal(raw, &typed)
					if err == nil {
						raw, err = countryCacheJSON(typed)
					}
				}
				if err == nil && name == "started.json" {
					var typed countryTaskStarted
					err = json.Unmarshal(raw, &typed)
					if err == nil {
						raw, err = countryCacheJSON(typed)
					}
				}
				if err != nil || os.WriteFile(file, raw, 0600) != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "request.json", "envelope.json", "dispatch.json", "started.json", "result.json", "task.lock":
				if err := os.Remove(filepath.Join(dir, kind)); err != nil {
					t.Fatal(err)
				}
			case "actor":
				mutate("result.json", func(v map[string]any) { v["actor_id"] = core.ID() })
			case "boot":
				mutate("started.json", func(v map[string]any) { v["boot_id"] = "11234567-89ab-cdef-0123-456789abcdef" })
			case "ticks":
				mutate("started.json", func(v map[string]any) { v["start_ticks"] = "18446744073709551616" })
			case "result-alias":
				mutate("result.json", func(v map[string]any) { v["STATE"] = v["state"] })
			case "needs-attention":
				mutate("result.json", func(v map[string]any) { v["state"] = "needs_attention" })
			case "payload":
				mutate("request.json", func(v map[string]any) { v["payload_sha256"] = core.Hash("other original payload") })
			case "envelope-hash":
				if err := os.WriteFile(filepath.Join(dir, "envelope.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(filepath.Join(dir, "unexpected.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(filepath.Join(dir, "request.json"), 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(dir, "result.json"), filepath.Join(root, "linked-result")); err != nil {
					t.Fatal(err)
				}
			case "unfinished-stage":
				if err := os.Rename(dir, filepath.Join(filepath.Dir(dir), ".prepare-"+core.ID())); err != nil {
					t.Fatal(err)
				}
			}
			assertCountryProgramQueueReadonly(t, root, true)
		})
	}
}

func TestProgramUpgradeCountryRunningLockAndOriginalNativeUnitsCannotDisappear(t *testing.T) {
	root, dir, request := countryProgramQueueFixture(t, "succeeded")
	lock, err := os.OpenFile(filepath.Join(dir, "task.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	assertCountryProgramQueueReadonly(t, root, true)
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	assertCountryProgramQueueReadonly(t, root, false)
	unit := "panel-waf-country@" + request.JobID + ".service"
	if decodeProgramQueueJobs("1 "+unit+" start waiting\n") == nil || decodeProgramQueueUnits(unit+" loaded active running Original\n") == nil || decodeProgramQueueUnits(unit+" loaded failed failed Interrupted\n") == nil {
		t.Fatal("original native country work was omitted from upgrade barriers")
	}
	queried := false
	run := func(ctx context.Context, binary string, args ...string) (string, error) {
		if binary != "/usr/bin/systemctl" || len(args) == 0 || args[0] != "list-units" && args[0] != "list-jobs" {
			t.Fatal("observer issued a mutation", binary, args)
		}
		queried = queried || strings.Contains(strings.Join(args, " "), "panel-waf-country@*.service")
		return "", nil
	}
	if checkProgramUpgradeNativeUnits(context.Background(), run) != nil || !queried {
		t.Fatal("classification did not enumerate actual original country units")
	}
}

func TestProgramUpgradeCountryRealNamespaceLockIsReadonlyAndFailClosed(t *testing.T) {
	for _, kind := range []string{"complete", "service-group", "missing", "busy", "nonempty", "permissions", "directory", "symlink", "hardlink", "foreign-owner", "unknown-member"} {
		t.Run(kind, func(t *testing.T) {
			root, dir, _ := countryProgramQueueFixture(t, "succeeded")
			lockPath := filepath.Join(filepath.Dir(dir), "store.lock")
			switch kind {
			case "service-group":
				if err := os.Chown(lockPath, 0, 988); err != nil {
					t.Fatal(err)
				}
			case "missing", "directory", "symlink":
				if err := os.Remove(lockPath); err != nil {
					t.Fatal(err)
				}
				if kind == "directory" {
					if err := os.Mkdir(lockPath, 0700); err != nil {
						t.Fatal(err)
					}
				} else if kind == "symlink" {
					if err := os.Symlink(filepath.Join(dir, "task.lock"), lockPath); err != nil {
						t.Fatal(err)
					}
				}
			case "busy":
				f, err := os.OpenFile(lockPath, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "nonempty":
				if err := os.WriteFile(lockPath, []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(lockPath, 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(lockPath, filepath.Join(root, "namespace-lock-alias")); err != nil {
					t.Fatal(err)
				}
			case "foreign-owner":
				if err := os.Chown(lockPath, 988, 988); err != nil {
					t.Fatal(err)
				}
			case "unknown-member":
				if err := os.WriteFile(filepath.Join(filepath.Dir(dir), "foreign.lock"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			assertCountryProgramQueueReadonly(t, root, kind != "complete" && kind != "service-group")
		})
	}
}
