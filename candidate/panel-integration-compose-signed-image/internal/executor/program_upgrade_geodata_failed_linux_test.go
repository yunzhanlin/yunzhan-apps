//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func TestProgramUpgradeFailedGeoUnitHasExactNarrowStoppedBoundary(t *testing.T) {
	id := core.ID()
	unit := "panel-statistics-geodata@" + id + ".service"
	if got, ok := statisticsGeoFailedUnitID(unit); !ok || got != id {
		t.Fatal(got, ok)
	}
	for _, name := range []string{"panel-statistics-geodata@bad.service", "panel-statistics-geodata@" + id + ".scope", "panel-statistics-geodata@../" + id + ".service", "panel-install@" + id + ".service", unit + ".service"} {
		if _, ok := statisticsGeoFailedUnitID(name); ok {
			t.Fatal("foreign unit", name)
		}
	}
	const show = "MainPID=0\nControlPID=0\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\nKillMode=control-group\nLoadState=loaded\nActiveState=failed\nSubState=failed\nJob=\n"
	if !statisticsGeoFailedUnitStopped(show) {
		t.Fatal("exact stopped failure rejected")
	}
	for _, raw := range []string{show + "MainPID=0\n", strings.Replace(show, "MainPID=0", "MainPID=42", 1), strings.Replace(show, "ControlPID=0", "ControlPID=12", 1), strings.Replace(show, "Result=exit-code", "Result=timeout", 1), strings.Replace(show, "ExecMainStatus=1", "ExecMainStatus=0", 1), strings.Replace(show, "ExecMainCode=1", "ExecMainCode=2", 1), strings.Replace(show, "KillMode=control-group", "KillMode=process", 1), strings.Replace(show, "Job=", "Job=1", 1), strings.Replace(show, "LoadState=loaded\n", "", 1), show + "Unknown=\n", show + "\x00", strings.Replace(show, "ActiveState=failed", "ActiveState=active", 1)} {
		if statisticsGeoFailedUnitStopped(raw) {
			t.Fatal("ambiguous/active/unsupported failure accepted", raw)
		}
	}
	failed := unit + " loaded failed failed Original failure\n"
	if decodeProgramQueueUnits(failed) == nil || decodeProgramQueueUnitsWithTerminalProof(failed, nil, func(name string) bool { return name != unit }) == nil {
		t.Fatal("missing exact proof accepted")
	}
	if err := decodeProgramQueueUnitsWithTerminalProof(failed, nil, func(name string) bool { return name == unit }); err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{unit + " loaded active running Worker\n", unit + " loaded failed dead Unknown\n", "panel-install@" + id + ".service loaded failed failed Other\n", "panel-disk-host-" + id + ".scope loaded failed failed Disk\n"} {
		calls := 0
		if decodeProgramQueueUnitsWithTerminalProof(row, nil, func(string) bool { calls++; return true }) == nil || calls != 0 {
			t.Fatal("geo proof widened another unit/state", row, calls)
		}
	}
}

func geoUpgradeFailureFixture(t *testing.T) (statisticsGeoFailedUpgradeProof, string, string, core.StatisticsGeoOperation) {
	t.Helper()
	f := geoStoreRootFixture(t)
	jobs := statisticsGeoJobArchiveStore{active: filepath.Join(f.store.base, "jobs"), archive: filepath.Join(f.store.base, "archive")}
	id := core.ID()
	dir := filepath.Join(jobs.active, id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	in := f.envelope(t, "2026-10")
	a, err := f.store.trust.VerifyGeoDataEnvelope(in, "2.6.0", f.sha, f.store.now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := json.Marshal(in)
	selection := core.StatisticsGeoSelection{Action: "install", AppVersion: "2.6.0", AppManifestSHA: f.sha, InstallationID: core.ID(), Release: "2026-10", DataManifestSHA: a.Data().SHA256()}
	request, _ := json.Marshal(statisticsGeoRequest{1, id, selection, core.Hash(string(envelope))})
	result := core.StatisticsGeoOperation{JobID: id, Selection: selection, State: "failed", Error: "synthetic original incomplete download", Steps: []core.Step{}}
	raw, _ := json.Marshal(result)
	for name, data := range map[string][]byte{"request.json": request, "envelope.json": envelope, "started.json": request, "result.json": raw, "install.lock": {}} {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	proof := statisticsGeoFailedUpgradeProof{jobs: jobs, trust: f.store.trust, now: func() time.Time { return f.store.now() }, validate: func(ctx context.Context, out core.StatisticsGeoOperation) error {
		if !reflect.DeepEqual(out, result) {
			return errors.New("changed synthetic Core binding")
		}
		return ctx.Err()
	}}
	return proof, id, dir, result
}

// Private Root/synthetic-signature fixtures plus an explicit Core boundary
// fixture, not a claim of original-key/native installed-panel acceptance.
func TestProgramUpgradeGeoFailedOriginalProofNeverRepairsOrAcceptsUnboundEvidence(t *testing.T) {
	for _, mutation := range []string{"original", "archived", "pending", "success", "changed-error", "started", "missing-lock", "locked", "hardlink", "foreign", "mode", "unknown", "bad-signature", "wrong-data-sha", "missing-core", "cancelled", "duplicate", "mid-replace", "mid-move", "mid-core"} {
		t.Run(mutation, func(t *testing.T) {
			p, id, dir, result := geoUpgradeFailureFixture(t)
			write := func(name string, data []byte) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(name string) {
				t.Helper()
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mutation {
			case "archived", "duplicate", "mid-move":
				if err := os.Mkdir(p.jobs.archive, 0700); err != nil {
					t.Fatal(err)
				}
				if mutation == "archived" {
					if err := os.Rename(dir, filepath.Join(p.jobs.archive, id)); err != nil {
						t.Fatal(err)
					}
				}
				if mutation == "duplicate" {
					if err := os.Mkdir(filepath.Join(p.jobs.archive, id), 0700); err != nil {
						t.Fatal(err)
					}
				}
				if mutation == "mid-move" {
					p.jobs.fault = func(string) error { return os.Rename(dir, filepath.Join(p.jobs.archive, id)) }
				}
			case "pending":
				remove("result.json")
			case "success":
				result.State = "succeeded"
				result.Error = ""
				raw, _ := json.Marshal(result)
				write("result.json", raw)
			case "changed-error":
				result.Error = "different"
				raw, _ := json.Marshal(result)
				write("result.json", raw)
			case "started":
				write("started.json", []byte("{}"))
			case "missing-lock":
				remove("install.lock")
			case "locked":
				f, err := os.OpenFile(filepath.Join(dir, "install.lock"), os.O_RDONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(dir, "result.json"), filepath.Join(filepath.Dir(dir), "hardlink")); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				if err := os.Chown(filepath.Join(dir, "result.json"), 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(filepath.Join(dir, "result.json"), 0644); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				write("extra.json", []byte("{}"))
			case "bad-signature", "wrong-data-sha":
				raw, err := os.ReadFile(filepath.Join(dir, "request.json"))
				if err != nil {
					t.Fatal(err)
				}
				var r statisticsGeoRequest
				if json.Unmarshal(raw, &r) != nil {
					t.Fatal("fixture")
				}
				if mutation == "bad-signature" {
					write("envelope.json", []byte("{}"))
					r.EnvelopeSHA = core.Hash("{}")
				} else {
					r.Selection.DataManifestSHA = strings.Repeat("f", 64)
					result.Selection = r.Selection
					raw, _ = json.Marshal(result)
					write("result.json", raw)
				}
				raw, _ = json.Marshal(r)
				write("request.json", raw)
				write("started.json", raw)
			case "missing-core":
				p.validate = func(context.Context, core.StatisticsGeoOperation) error { return errors.New("original Core absent") }
			case "cancelled":
				cancel()
			case "mid-replace":
				p.jobs.fault = func(string) error {
					path := filepath.Join(dir, "result.json")
					// Keep the unlinked original inode alive until AFTER the new
					// file is allocated. Immediate unlink/recreate may otherwise
					// legitimately reuse the same inode and clock tick on ext4,
					// failing to construct the claimed replacement fixture.
					held, err := os.Open(path)
					if err != nil {
						return err
					}
					defer held.Close()
					original, err := held.Stat()
					if err != nil {
						return err
					}
					raw, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					if err = os.Remove(path); err != nil {
						return err
					}
					if err = os.WriteFile(path, raw, 0600); err != nil {
						return err
					}
					replaced, err := os.Lstat(path)
					if err != nil || os.SameFile(original, replaced) {
						return errors.New("replacement fixture did not allocate a distinct inode")
					}
					return nil
				}
			case "mid-core":
				calls := 0
				p.validate = func(context.Context, core.StatisticsGeoOperation) error {
					calls++
					if calls > 1 {
						return errors.New("Core changed")
					}
					return nil
				}
			}
			before := programQueueTree(t, filepath.Dir(p.jobs.active))
			err := p.check(ctx, id)
			want := mutation == "original" || mutation == "archived"
			if (err == nil) != want {
				t.Fatal("original proof boundary", mutation, err)
			}
			if !strings.HasPrefix(mutation, "mid-") && !reflect.DeepEqual(before, programQueueTree(t, filepath.Dir(p.jobs.active))) {
				t.Fatal("readonly proof repaired/changed files")
			}
		})
	}
}

// Opt-in readonly acceptance against the user's ORIGINAL failed QA operation.
// It neither changes the failed unit nor fabricates Core/Root closure metadata.
// Ordinary tests must not touch an installed instance or require this evidence.
func TestProgramUpgradeGeoFailedInstalledOriginalReadonly(t *testing.T) {
	const id = "d8fb0c4542aa28ab6b52379278675267"
	if os.Getenv("PANEL_GEODATA_FAILED_ORIGINAL_QA") != id {
		t.Skip("explicit original ARM QA evidence required; no fixture substitution")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" || os.Geteuid() != 0 {
		t.Fatal("original owned ARM QA host required", err)
	}
	dir := filepath.Join(statisticsGeoJobsRoot, id)
	before := programQueueTree(t, dir)
	for leaf, want := range map[string]string{"request.json": "3b5795168ddbab97a18370026072edf67f706dd7014dccab538657e072b677db", "started.json": "3b5795168ddbab97a18370026072edf67f706dd7014dccab538657e072b677db", "envelope.json": "120c6524eefe42f72537585419cc8c4efaf9d2cc063fa7dbf4f14aacc54feee3", "result.json": "e1137cbf7a2b09ef9ebca19d392ea2c6790049cef20c0f92a7ea0a318ab95812"} {
		raw, e := os.ReadFile(filepath.Join(dir, leaf))
		if e != nil || core.Hash(string(raw)) != want {
			t.Fatal("original failed artifact changed", leaf, e)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if !closedStatisticsGeoFailedInstall(ctx, "panel-statistics-geodata@"+id+".service", programQueueCommand) {
		t.Fatal("original two-sided closed failure still blocks readonly native drain")
	}
	if err = CheckProgramUpgradeQueues(); err != nil {
		t.Fatal("new complete readonly preflight", err)
	}
	if !reflect.DeepEqual(before, programQueueTree(t, dir)) {
		t.Fatal("original failed evidence changed")
	}
	raw, err := programQueueCommand(ctx, "/usr/bin/systemctl", "show", "panel-statistics-geodata@"+id+".service", "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Result,ExecMainCode,ExecMainStatus,Job,KillMode", "--no-pager")
	if err != nil || !statisticsGeoFailedUnitStopped(raw) {
		t.Fatal("original failed native status was hidden or changed", err)
	}
}
