//go:build linux

package executor

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func countryFailedShowFixture() string {
	return "LoadState=loaded\nActiveState=failed\nSubState=failed\nMainPID=0\nControlPID=0\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\nJob=\nKillMode=control-group\nFragmentPath=/etc/systemd/system/panel-waf-country@.service\nDropInPaths=\nNeedDaemonReload=no\nTransient=no\n"
}

func TestCountryFailedUnitNeedsExactStoppedIdentityAndIndependentOwnProof(t *testing.T) {
	good := countryFailedShowFixture()
	if !countryFailedUnitStopped(good) {
		t.Fatal("complete exit1 fixture refused")
	}
	for _, change := range [][2]string{{"MainPID=0", "MainPID=8"}, {"ControlPID=0", "ControlPID=9"}, {"Result=exit-code", "Result=signal"}, {"Result=exit-code", "Result=oom-kill"}, {"ExecMainCode=1", "ExecMainCode=2"}, {"ExecMainStatus=1", "ExecMainStatus=15"}, {"Job=\n", "Job=43\n"}, {"KillMode=control-group", "KillMode=process"}, {"DropInPaths=\n", "DropInPaths=/tmp/override.conf\n"}, {"Transient=no", "Transient=yes"}, {"NeedDaemonReload=no", "NeedDaemonReload=yes"}, {"SubState=failed", "SubState=start"}} {
		if countryFailedUnitStopped(strings.Replace(good, change[0], change[1], 1)) {
			t.Fatal("partial or active unit accepted", change)
		}
	}
	id := core.ID()
	name := "panel-waf-country@" + id + ".service"
	line := name + " loaded failed failed original worker\n"
	calls := 0
	if decodeProgramQueueUnitsWithRuntimeProof(line, nil, func(string) bool { return true }, func(string) bool { return true }) == nil {
		t.Fatal("another worker's proof admitted country failure")
	}
	if err := decodeProgramQueueUnitsWithCountryProof(line, nil, nil, nil, func(n string) bool { calls++; return n == name }); err != nil || calls != 1 {
		t.Fatal("independent original proof not used", err, calls)
	}
	for _, foreign := range []string{"panel-waf-country-account@" + id + ".service", "panel-waf-country@bad.service", "panel-statistics-geodata@" + id + ".service"} {
		if _, ok := countryFailedUnitID(foreign); ok {
			t.Fatal("foreign unit ID adopted")
		}
	}
}

func TestCountryFailedUpgradeProofChecksOriginalFilesSharedLocksAndBothSides(t *testing.T) {
	for _, kind := range []string{"complete", "original-worker-locked", "missing-result", "needs-attention", "foreign-request", "unsigned-original", "Core-refused", "late-root-change", "late-lock-replacement"} {
		t.Run(kind, func(t *testing.T) {
			root, dir, request := countryProgramQueueFixture(t, "failed")
			// The generic queue reader's temporary root is not valid geography
			// storage. Copy only this throwaway fixture into a trusted private
			// /var parent; keep the production parent checks unchanged.
			fixture := newCountryCacheFixture(t)
			jobs := filepath.Join(filepath.Dir(fixture.store.base), "failed-jobs")
			if err := os.Mkdir(jobs, 0700); err != nil {
				t.Fatal(err)
			}
			global, err := os.ReadFile(filepath.Join(root, "var/lib/panel-executor/waf-country-jobs/store.lock"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(jobs, "store.lock"), global, 0600); err != nil {
				t.Fatal(err)
			}
			private := filepath.Join(jobs, request.JobID)
			if err := os.Mkdir(private, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"request.json", "envelope.json", "dispatch.json", "started.json", "result.json", "task.lock"} {
				raw, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(private, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			dir = private
			calls := 0
			p := countryFailedUpgradeProof{jobs: countryTaskStore{base: jobs, now: time.Now}, verify: func(r countryTaskRequest, raw []byte) error {
				// Metadata-only synthetic fixture, never production signature trust.
				if kind == "unsigned-original" {
					return verifyCountryFailedEnvelope(r, raw)
				}
				if !countryTaskSameBinding(r, request) {
					return errors.New("foreign synthetic envelope")
				}
				return nil
			}, validate: func(_ context.Context, result core.WAFCountryDataOperation) error {
				calls++
				if result.JobID != request.JobID || result.State != "failed" || kind == "Core-refused" {
					return errors.New("original Core result differs")
				}
				if calls == 1 && kind == "late-root-change" {
					return os.WriteFile(filepath.Join(dir, "result.json"), []byte("changed"), 0600)
				}
				if calls == 1 && kind == "late-lock-replacement" {
					path := filepath.Join(filepath.Dir(dir), "store.lock")
					if err := os.Rename(path, path+".retained"); err != nil {
						return err
					}
					return os.WriteFile(path, nil, 0600)
				}
				return nil
			}}
			switch kind {
			case "original-worker-locked":
				f, err := os.OpenFile(filepath.Join(dir, "task.lock"), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "missing-result":
				if err := os.Rename(filepath.Join(dir, "result.json"), filepath.Join(dir, "result.retained")); err != nil {
					t.Fatal(err)
				}
			case "needs-attention":
				out := countryTaskOperation(request, "needs_attention", "original outcome unknown")
				raw, _ := countryCacheJSON(out)
				if err := os.WriteFile(filepath.Join(dir, "result.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-request":
				request.ActorID = core.ID()
			}
			err = p.check(context.Background(), request.JobID)
			if (err == nil) != (kind == "complete") {
				t.Fatal("original failed proof qualification mismatch", kind, err)
			}
			if kind == "complete" && calls != 2 {
				t.Fatal("both original Core snapshots not checked", calls)
			}
		})
	}
}

var countryFailedNativeReadonly = flag.Bool("waf-country-failed-native-readonly", false, "read-only original fixed production country failure admission; never install, signal or recover")

func TestCountryFailedOriginalNativeReadOnlyAdmission(t *testing.T) {
	if !*countryFailedNativeReadonly {
		t.Skip("requires explicitly selected owned native QA with a retained complete original failure")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires Root readonly observer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store := productionCountryTaskStore()
	base, err := store.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	d, err := base.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := d.ReadDir(countryTasksMax + 2)
	d.Close()
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, entry := range entries {
		if !core.ValidID(entry.Name()) {
			continue
		}
		request, _, dir, err := store.read(base, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := geoStoreRead(dir.Root, "result.json", 32<<10)
		dir.Close()
		if err != nil {
			t.Fatal(err)
		}
		result, err := core.DecodeWAFCountryDataOperation(raw, request.JobID, request.ActorID, request.Selection)
		if err != nil {
			t.Fatal(err)
		}
		if result.State == "failed" {
			failed++
			if !closedCountryFailedTask(ctx, "panel-waf-country@"+request.JobID+".service", programQueueCommand) {
				t.Fatal("complete original production failure not independently qualified", request.JobID)
			}
		}
	}
	if failed != 1 {
		t.Fatal("expected exactly one retained original failure", failed)
	}
	if err := CheckProgramUpgradeQueues(); err != nil {
		t.Fatal("complete original native guard refused", err)
	}
	t.Log("fixed original failed country task, signed envelope, both Core witnesses and complete native guard accepted read-only; failed systemd unit and original results remain unchanged")
}
