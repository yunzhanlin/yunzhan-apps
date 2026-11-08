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

const runtimeStoppedFixture = "Type=oneshot\nMainPID=0\nControlPID=0\nResult=exit-code\nExecMainStartTimestampMonotonic=100\nExecMainExitTimestampMonotonic=200\nExecMainPID=1234\nExecMainCode=1\nExecMainStatus=1\nControlGroup=\nDelegate=no\nKillMode=control-group\nLoadState=loaded\nActiveState=failed\nSubState=failed\nJob=\n"

func TestRuntimeFailedUpgradeUnitAuthorityAndGenerationAreClosed(t *testing.T) {
	id := core.ID()
	unit := "panel-install@" + id + ".service"
	if got, ok := runtimeFailedUnitID(unit); !ok || got != id {
		t.Fatal(got, ok)
	}
	for _, name := range []string{"panel-install@short.service", "panel-install@" + strings.Repeat("A", 32) + ".service", "panel-docker-install@" + id + ".service", "panel-install@../" + id + ".service", unit + ".service", "panel-pm2@" + id + ".service"} {
		if _, ok := runtimeFailedUnitID(name); ok {
			t.Fatal("foreign unit accepted", name)
		}
	}
	first, ok := runtimeFailedUnitStopped(runtimeStoppedFixture)
	if !ok || len(first) != 64 {
		t.Fatal(first, ok)
	}
	for _, raw := range []string{strings.TrimSuffix(runtimeStoppedFixture, "\n"), runtimeStoppedFixture + "MainPID=0\n", runtimeStoppedFixture + "Unknown=\n", runtimeStoppedFixture + "\x00", strings.Replace(runtimeStoppedFixture, "MainPID=0", "MainPID=123", 1), strings.Replace(runtimeStoppedFixture, "ControlPID=0", "ControlPID=22", 1), strings.Replace(runtimeStoppedFixture, "Result=exit-code", "Result=timeout", 1), strings.Replace(runtimeStoppedFixture, "ExecMainStatus=1", "ExecMainStatus=0", 1), strings.Replace(runtimeStoppedFixture, "ExecMainCode=1", "ExecMainCode=2", 1), strings.Replace(runtimeStoppedFixture, "ControlGroup=", "ControlGroup=/system.slice/foreign.service", 1), strings.Replace(runtimeStoppedFixture, "Delegate=no", "Delegate=yes", 1), strings.Replace(runtimeStoppedFixture, "KillMode=control-group", "KillMode=process", 1), strings.Replace(runtimeStoppedFixture, "Job=", "Job=42", 1), strings.Replace(runtimeStoppedFixture, "Type=oneshot", "Type=simple", 1), strings.Replace(runtimeStoppedFixture, "ExecMainPID=1234", "ExecMainPID=0", 1), strings.Replace(runtimeStoppedFixture, "ExecMainPID=1234", "ExecMainPID=01234", 1), strings.Replace(runtimeStoppedFixture, "ExecMainStartTimestampMonotonic=100", "ExecMainStartTimestampMonotonic=0", 1), strings.Replace(runtimeStoppedFixture, "ExecMainExitTimestampMonotonic=200", "ExecMainExitTimestampMonotonic=99", 1), strings.Replace(runtimeStoppedFixture, "LoadState=loaded\n", "", 1)} {
		if _, ok := runtimeFailedUnitStopped(raw); ok {
			t.Fatal("ambiguous or live generation accepted", raw)
		}
	}
	changed, ok := runtimeFailedUnitStopped(strings.Replace(runtimeStoppedFixture, "ExecMainPID=1234", "ExecMainPID=1235", 1))
	if !ok || changed == first {
		t.Fatal("unit generation not bound")
	}
	row := unit + " loaded failed failed Original retained failure\n"
	if decodeProgramQueueUnits(row) == nil || decodeProgramQueueUnitsWithTerminalProof(row, nil, func(string) bool { return true }) == nil {
		t.Fatal("historical decoder or foreign proof was widened")
	}
	if err := decodeProgramQueueUnitsWithRuntimeProof(row, nil, nil, func(name string) bool { return name == unit }); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{unit + " loaded active running Busy\n", unit + " loaded failed dead Unknown\n", "panel-docker-install@" + id + ".service loaded failed failed Docker\n", "panel-statistics-geodata@" + id + ".service loaded failed failed Geo\n"} {
		calls := 0
		if decodeProgramQueueUnitsWithRuntimeProof(raw, nil, nil, func(string) bool { calls++; return true }) == nil || calls != 0 {
			t.Fatal("native runtime callback aliases another authority", raw, calls)
		}
	}
}

func TestRuntimeFailedUpgradePrivateRootProofNeverWritesOrTrustsAmbiguity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Root-private filesystem models required")
	}
	for _, mutation := range []string{"original", "php-extension", "missing-lock", "lock-link", "lock-hardlink", "lock-mode", "busy", "record-link", "record-hardlink", "record-mode", "record-owner", "root-mode", "root-owner", "record-running", "record-success", "record-empty-error", "record-empty-steps", "record-wrong-final-step", "record-extension", "record-id", "record-release", "duplicate-json", "unknown-json", "whitespace-json", "missing-core", "different-core", "mid-core", "mid-unit", "mid-file-identical", "mid-file-changed", "mid-lock", "mid-move", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "private")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			id := core.ID()
			status := InstallStatus{JobID: id, ReleaseID: "nginx-1.30.6", State: "failed", Error: "synthetic original failure", Steps: []core.Step{{Time: core.Now(), Message: "synthetic original failure"}}}
			if mutation == "php-extension" {
				status.ReleaseID, status.ExtensionID = "php-8.5.12", "redis-6.3.0"
			}
			raw, _ := json.Marshal(status)
			file := filepath.Join(dir, id+".json")
			lockPath := filepath.Join(dir, ".native-start.lock")
			write := func(path string, data []byte) {
				t.Helper()
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(file, raw)
			write(lockPath, nil)
			calls := 0
			showCalls := 0
			p := runtimeFailedUpgradeProof{open: func() (*os.Root, error) { return os.OpenRoot(dir) }, current: func(root *os.Root) bool {
				a, err := os.Lstat(dir)
				b, be := root.Stat(".")
				return err == nil && be == nil && runtimeInstallPrivateDirectory(a) && runtimeInstallPrivateDirectory(b) && os.SameFile(a, b)
			}, stopped: func() (string, error) {
				showCalls++
				if mutation == "mid-unit" && showCalls == 2 {
					return strings.Replace(runtimeStoppedFixture, "ExecMainPID=1234", "ExecMainPID=1235", 1), nil
				}
				return runtimeStoppedFixture, nil
			}, validate: func(_ context.Context, in InstallStatus) (string, error) {
				calls++
				if !reflect.DeepEqual(in, status) || mutation == "missing-core" || mutation == "different-core" {
					return "", errors.New("synthetic unmatched Core")
				}
				if mutation == "mid-core" && calls == 2 {
					return core.Hash("different synthetic Core row"), nil
				}
				return core.Hash("original synthetic Core row"), nil
			}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mutation {
			case "missing-lock":
				if err := os.Remove(lockPath); err != nil {
					t.Fatal(err)
				}
			case "lock-link", "record-link":
				target := file
				if mutation == "lock-link" {
					target = lockPath
				}
				copy := target + ".retained"
				if err := os.Rename(target, copy); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(copy, target); err != nil {
					t.Fatal(err)
				}
			case "lock-hardlink", "record-hardlink":
				target := file
				if mutation == "lock-hardlink" {
					target = lockPath
				}
				if err := os.Link(target, target+".retained"); err != nil {
					t.Fatal(err)
				}
			case "lock-mode":
				if err := os.Chmod(lockPath, 0644); err != nil {
					t.Fatal(err)
				}
			case "record-mode":
				if err := os.Chmod(file, 0644); err != nil {
					t.Fatal(err)
				}
			case "record-owner":
				if err := os.Chown(file, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "root-mode":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "root-owner":
				if err := os.Chown(dir, 65534, 65534); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Chown(dir, 0, 0); err != nil {
						t.Error(err)
					}
				}()
			case "busy":
				held, err := os.OpenFile(lockPath, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer held.Close()
				if err := unix.Flock(int(held.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "record-running", "record-success", "record-empty-error", "record-empty-steps", "record-wrong-final-step", "record-extension", "record-id", "record-release":
				copy := status
				copy.Steps = append([]core.Step(nil), status.Steps...)
				switch mutation {
				case "record-running":
					copy.State = "running"
				case "record-success":
					copy.State = "succeeded"
				case "record-empty-error":
					copy.Error = ""
				case "record-empty-steps":
					copy.Steps = []core.Step{}
				case "record-wrong-final-step":
					copy.Steps[0].Message = "other"
				case "record-extension":
					copy.ExtensionID = "redis"
				case "record-id":
					copy.JobID = core.ID()
				case "record-release":
					copy.ReleaseID = "nginx-latest"
				}
				encoded, _ := json.Marshal(copy)
				write(file, encoded)
			case "duplicate-json":
				write(file, []byte(strings.Replace(string(raw), `"state":"failed"`, `"state":"failed","state":"failed"`, 1)))
			case "unknown-json":
				write(file, []byte(strings.TrimSuffix(string(raw), "}")+`,"invented":"allow"}`))
			case "whitespace-json":
				write(file, append(raw, '\n'))
			case "mid-file-identical", "mid-file-changed", "mid-lock", "mid-move", "cancelled":
				p.checkpoint = func() error {
					switch mutation {
					case "mid-file-identical", "mid-file-changed":
						replacement := file + ".replacement"
						value := raw
						if mutation == "mid-file-changed" {
							value = append(raw, '\n')
						}
						write(replacement, value)
						return os.Rename(replacement, file)
					case "mid-lock":
						replacement := lockPath + ".replacement"
						write(replacement, nil)
						return os.Rename(replacement, lockPath)
					case "mid-move":
						if err := os.Rename(dir, dir+".moved"); err != nil {
							return err
						}
						return os.Mkdir(dir, 0700)
					case "cancelled":
						cancel()
					}
					return nil
				}
			}
			before, readErr := os.ReadFile(file)
			if mutation == "mid-move" {
				before = nil
			}
			err := p.check(ctx, id)
			if mutation == "original" || mutation == "php-extension" {
				if err != nil || calls != 2 || showCalls != 2 {
					t.Fatal(err, calls, showCalls)
				}
			} else if err == nil {
				t.Fatal("unbound failure or changed identity accepted", mutation, calls, showCalls)
			}
			if !strings.HasPrefix(mutation, "mid-") && mutation != "cancelled" {
				after, afterErr := os.ReadFile(file)
				if !reflect.DeepEqual(before, after) || (readErr == nil) != (afterErr == nil) {
					t.Fatal("observer altered retained bytes", readErr, afterErr)
				}
			}
		})
	}
}

// Explicit genuine read-only acceptance of one retained failed request. No
// production-root replacement, synthetic command broker, dispatch or retry.
func TestRuntimeFailedUpgradeActualOriginalStoppedRequestReadOnly(t *testing.T) {
	id := os.Getenv("PANEL_QA_RUNTIME_FAILED_JOB")
	if id == "" {
		t.Skip("explicit actual retained native request required")
	}
	if !core.ValidID(id) || os.Geteuid() != 0 {
		t.Fatal("invalid actual native scope")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	root, err := runtimeInstallRecordRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, err := root.Lstat(id + ".json")
	if err != nil {
		t.Fatal(err)
	}
	before, err := readRuntimeInstallRecordBytes(id)
	if err != nil {
		t.Fatal(err)
	}
	var status InstallStatus
	if json.Unmarshal(before, &status) != nil || status.State != "failed" {
		t.Fatal("original failure missing")
	}
	for range 2 {
		if !closedRuntimeFailedInstall(ctx, "panel-install@"+id+".service", RunCommand) {
			t.Fatal("original real Core/Root/unit stopped failure could not be authenticated")
		}
	}
	after, err := readRuntimeInstallRecordBytes(id)
	final, fe := root.Lstat(id + ".json")
	if err != nil || fe != nil || string(before) != string(after) || !runtimeInstallSamePrivateFile(info, final) {
		t.Fatal("readonly validation rewrote original failure", err, fe)
	}
	t.Logf("RUNTIME_FAILED_UPGRADE_NATIVE original_job=%s original_sha256=%s retained_state=failed actual_Core_Root_unit_closed=true no_dispatch_retry_reset_or_receipt_write=true", id, core.Hash(string(before)))
}
