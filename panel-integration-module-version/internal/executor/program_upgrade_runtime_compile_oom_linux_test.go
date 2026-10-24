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

const runtimeOOMStoppedFixture = "Type=oneshot\nMainPID=0\nControlPID=0\nResult=oom-kill\nExecMainStartTimestampMonotonic=100\nExecMainExitTimestampMonotonic=200\nExecMainPID=1234\nExecMainCode=2\nExecMainStatus=15\nControlGroup=\nDelegate=no\nKillMode=control-group\nLoadState=loaded\nActiveState=failed\nSubState=failed\nJob=\n"

func runtimeOOMStatusFixture(id string) InstallStatus {
	var steps []core.Step
	for _, message := range []string{
		"核对固定版本目录，等待源码构建锁",
		"本次安装总时限 240 分钟；超时即失败，不发布未校验程序",
		"已从官方站点下载源码，并通过目录中固定的 SHA-256 校验",
		"以独立构建用户配置精确版本及固定模块",
		"开始源码编译（1 个并行任务）；完整构建日志保存在专用缓存目录",
	} {
		steps = append(steps, core.Step{Time: core.Now(), Message: message})
	}
	return InstallStatus{JobID: id, ReleaseID: "php-8.2.35", State: "running", Steps: steps}
}

func TestRuntimeCompileOOMUnitIsSeparateFromOrdinaryFailure(t *testing.T) {
	first, ok := runtimeCompileOOMUnitStopped(runtimeOOMStoppedFixture)
	if !ok || len(first) != 64 {
		t.Fatal(first, ok)
	}
	if _, ok := runtimeFailedUnitStopped(runtimeOOMStoppedFixture); ok {
		t.Fatal("ordinary failed-exit authority was widened to OOM")
	}
	if _, ok := runtimeCompileOOMUnitStopped(runtimeStoppedFixture); ok {
		t.Fatal("OOM proof borrowed an ordinary failed-exit authority")
	}
	bad := []string{"", strings.TrimSuffix(runtimeOOMStoppedFixture, "\n"), runtimeOOMStoppedFixture + "MainPID=0\n", runtimeOOMStoppedFixture + "Unknown=\n", runtimeOOMStoppedFixture + "\x00", strings.ReplaceAll(runtimeOOMStoppedFixture, "\n", "\r\n")}
	for key, values := range map[string][]string{
		"LoadState=loaded":   {"LoadState=not-found", "LoadState=masked", "LoadState=error"},
		"ActiveState=failed": {"ActiveState=active", "ActiveState=activating", "ActiveState=inactive"},
		"SubState=failed":    {"SubState=running", "SubState=dead"},
		"MainPID=0":          {"MainPID=123", "MainPID=00"}, "ControlPID=0": {"ControlPID=22"},
		"Result=oom-kill": {"Result=success", "Result=signal", "Result=timeout", "Result=exit-code", "Result=unknown"},
		"ExecMainCode=2":  {"ExecMainCode=1", "ExecMainCode=3"}, "ExecMainStatus=15": {"ExecMainStatus=0", "ExecMainStatus=9", "ExecMainStatus=015"},
		"ControlGroup=": {"ControlGroup=/system.slice/foreign.service"}, "Delegate=no": {"Delegate=yes"},
		"KillMode=control-group": {"KillMode=process", "KillMode=mixed"}, "Job=": {"Job=42", "Job=0"},
		"Type=oneshot": {"Type=simple", "Type=notify"}, "ExecMainPID=1234": {"ExecMainPID=0", "ExecMainPID=01234", "ExecMainPID=2147483648"},
		"ExecMainStartTimestampMonotonic=100": {"ExecMainStartTimestampMonotonic=0", "ExecMainStartTimestampMonotonic=0100"},
		"ExecMainExitTimestampMonotonic=200":  {"ExecMainExitTimestampMonotonic=0", "ExecMainExitTimestampMonotonic=99"},
	} {
		bad = append(bad, strings.Replace(runtimeOOMStoppedFixture, key+"\n", "", 1))
		for _, value := range values {
			bad = append(bad, strings.Replace(runtimeOOMStoppedFixture, key+"\n", value+"\n", 1))
		}
	}
	for _, raw := range bad {
		if _, ok := runtimeCompileOOMUnitStopped(raw); ok {
			t.Fatal("ambiguous/active/foreign OOM generation admitted", raw)
		}
	}
	for _, key := range []string{"ExecMainPID=1234", "ExecMainStartTimestampMonotonic=100", "ExecMainExitTimestampMonotonic=200"} {
		changed, ok := runtimeCompileOOMUnitStopped(strings.Replace(runtimeOOMStoppedFixture, key, key+"0", 1))
		if key == "ExecMainStartTimestampMonotonic=100" { // A start after exit must refuse.
			if ok {
				t.Fatal("reversed OOM lifetime admitted")
			}
		} else if !ok || changed == first {
			t.Fatal("OOM generation not bound", key)
		}
	}
}

func TestRuntimeCompileOOMPrivateProofNeverRepairsOrAcceptsUncertainty(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Root-private filesystem/lock models required")
	}
	for _, mutation := range []string{"original", "missing-lock", "lock-link", "lock-hardlink", "lock-mode", "lock-nonempty", "busy-start", "busy-build", "build-missing", "build-link", "build-hardlink", "build-mode", "build-owner", "build-nonempty", "record-link", "record-hardlink", "record-mode", "record-owner", "record-directory", "root-mode", "root-owner", "record-failed", "record-success", "record-queued", "record-error", "record-id", "record-release", "record-extension", "phase-install", "duplicate-json", "unknown-json", "whitespace-json", "missing-core", "bad-core-hash", "published", "bad-publication-hash", "missing-unit", "active-unit", "mid-core", "mid-publication", "mid-unit", "mid-file-identical", "mid-file-changed", "mid-lock", "mid-build", "mid-root", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			base := t.TempDir()
			dir, build := filepath.Join(base, "private"), filepath.Join(base, "builder")
			for _, path := range []string{dir, build} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			id := core.ID()
			status := runtimeOOMStatusFixture(id)
			raw, _ := json.Marshal(status)
			file, startLock, buildLock := filepath.Join(dir, id+".json"), filepath.Join(dir, ".native-start.lock"), filepath.Join(build, "build.lock")
			write := func(path string, data []byte) {
				t.Helper()
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(file, raw)
			write(startLock, nil)
			write(buildLock, nil)
			calls, shows, publications := 0, 0, 0
			p := runtimeCompileOOMUpgradeProof{
				open: func() (*os.Root, error) { return os.OpenRoot(dir) },
				current: func(root *os.Root) bool {
					a, err := os.Lstat(dir)
					b, be := root.Stat(".")
					return err == nil && be == nil && runtimeInstallPrivateDirectory(a) && runtimeInstallPrivateDirectory(b) && os.SameFile(a, b)
				},
				fence: func() (func() bool, func(), error) {
					r, err := os.OpenRoot(build)
					if err != nil {
						return nil, nil, err
					}
					f, info, err := runtimeCompileOOMReadLease(r, "build.lock")
					if err != nil {
						r.Close()
						return nil, nil, err
					}
					return func() bool { return runtimeCompileOOMLeaseCurrent(r, "build.lock", f, info) }, func() { f.Close(); r.Close() }, nil
				},
				stopped: func() (string, error) {
					shows++
					if mutation == "missing-unit" {
						return "", errors.New("synthetic missing unit")
					}
					if mutation == "active-unit" {
						return strings.Replace(runtimeOOMStoppedFixture, "MainPID=0", "MainPID=42", 1), nil
					}
					if mutation == "mid-unit" && shows == 2 {
						return strings.Replace(runtimeOOMStoppedFixture, "ExecMainPID=1234", "ExecMainPID=1235", 1), nil
					}
					return runtimeOOMStoppedFixture, nil
				},
				validate: func(_ context.Context, in InstallStatus) (string, error) {
					calls++
					if !reflect.DeepEqual(in, status) || mutation == "missing-core" {
						return "", errors.New("synthetic unmatched original Core OOM failure")
					}
					if mutation == "bad-core-hash" {
						return "unbound", nil
					}
					if mutation == "mid-core" && calls == 2 {
						return core.Hash("changed Core"), nil
					}
					return core.Hash("original Core failed OOM / native still-running ledger"), nil
				},
				unpublished: func(context.Context, InstallStatus) (string, error) {
					publications++
					if mutation == "published" {
						return "", errors.New("synthetic pending/final runtime exists")
					}
					if mutation == "bad-publication-hash" {
						return "unbound", nil
					}
					if mutation == "mid-publication" && publications == 2 {
						return core.Hash("changed publication ancestors"), nil
					}
					return core.Hash("all trusted parents stable; no pending or final runtime"), nil
				},
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			target := file
			if strings.HasPrefix(mutation, "build-") || mutation == "busy-build" {
				target = buildLock
			} else if strings.HasPrefix(mutation, "lock-") || mutation == "missing-lock" || mutation == "busy-start" {
				target = startLock
			}
			switch mutation {
			case "missing-lock", "build-missing":
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			case "lock-link", "build-link", "record-link":
				if err := os.Rename(target, target+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target+".original", target); err != nil {
					t.Fatal(err)
				}
			case "lock-hardlink", "build-hardlink", "record-hardlink":
				if err := os.Link(target, target+".alias"); err != nil {
					t.Fatal(err)
				}
			case "lock-mode", "build-mode", "record-mode":
				if err := os.Chmod(target, 0644); err != nil {
					t.Fatal(err)
				}
			case "lock-nonempty", "build-nonempty":
				write(target, []byte("retained original lock content"))
			case "record-owner", "build-owner":
				if err := os.Chown(target, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "record-directory":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(file, 0700); err != nil {
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
				defer os.Chown(dir, 0, 0)
			case "busy-start", "busy-build":
				f, err := os.OpenFile(target, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "record-failed", "record-success", "record-queued", "record-error", "record-id", "record-release", "record-extension", "phase-install":
				copy := status
				copy.Steps = append([]core.Step(nil), status.Steps...)
				switch mutation {
				case "record-failed":
					copy.State, copy.Error = "failed", core.RuntimeCompileOOMError
				case "record-success":
					copy.State = "succeeded"
				case "record-queued":
					copy.State = "queued"
				case "record-error":
					copy.Error = core.RuntimeCompileOOMError
				case "record-id":
					copy.JobID = core.ID()
				case "record-release":
					copy.ReleaseID = "php-8.2.33"
				case "record-extension":
					copy.ExtensionID = "redis"
				case "phase-install":
					copy.Steps[4].Message = "编译完成，安装到暂存目录"
				}
				encoded, _ := json.Marshal(copy)
				write(file, encoded)
			case "duplicate-json":
				write(file, []byte(strings.Replace(string(raw), `"state":"running"`, `"state":"running","state":"running"`, 1)))
			case "unknown-json":
				write(file, []byte(strings.TrimSuffix(string(raw), "}")+`,"allow":true}`))
			case "whitespace-json":
				write(file, append(raw, '\n'))
			case "mid-file-identical", "mid-file-changed", "mid-lock", "mid-build", "mid-root", "cancelled":
				p.checkpoint = func() error {
					switch mutation {
					case "mid-file-identical", "mid-file-changed", "mid-lock", "mid-build":
						path, value := file, raw
						if mutation == "mid-file-changed" {
							value = append(raw, '\n')
						} else if mutation == "mid-lock" {
							path, value = startLock, nil
						} else if mutation == "mid-build" {
							path, value = buildLock, nil
						}
						write(path+".replacement", value)
						return os.Rename(path+".replacement", path)
					case "mid-root":
						if err := os.Rename(dir, dir+".original"); err != nil {
							return err
						}
						return os.Mkdir(dir, 0700)
					case "cancelled":
						cancel()
					}
					return nil
				}
			}
			before, beforeErr := os.ReadFile(file)
			err := p.check(ctx, id)
			if mutation == "original" {
				if err != nil || calls != 2 || shows != 2 || publications != 2 {
					t.Fatal(err, calls, shows, publications)
				}
			} else if err == nil {
				t.Fatal("uncertain/active/changed OOM proof admitted", mutation)
			}
			if !strings.HasPrefix(mutation, "mid-") {
				after, afterErr := os.ReadFile(file)
				if !reflect.DeepEqual(before, after) || (beforeErr == nil) != (afterErr == nil) {
					t.Fatal("observer rewrote original native evidence")
				}
			}
		})
	}
}

func TestRuntimeCompileOOMActualOriginalStoppedRequestReadOnly(t *testing.T) {
	id := os.Getenv("PANEL_QA_RUNTIME_COMPILE_OOM_JOB")
	if id == "" {
		t.Skip("explicit genuine retained compile-OOM native request required")
	}
	if !core.ValidID(id) || os.Geteuid() != 0 {
		t.Fatal("invalid genuine OOM proof scope")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	root, err := runtimeInstallRecordRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before, err := readRuntimeInstallPrivateFile(root, id+".json")
	info, ie := root.Lstat(id + ".json")
	if err != nil || ie != nil {
		t.Fatal(err, ie)
	}
	var original InstallStatus
	if json.Unmarshal(before, &original) != nil || original.State != "running" || original.Error != "" || !core.RuntimeCompileOOMSteps(original.ReleaseID, original.Steps) {
		t.Fatal("original ledger does not retain the exact pre-publication compile phase")
	}
	unit := "panel-install@" + id + ".service"
	if closedRuntimeFailedInstall(ctx, unit, RunCommand) {
		t.Fatal("ordinary original failed-exit protocol was broadened to OOM")
	}
	if !closedRuntimeCompileOOMInstall(ctx, unit, RunCommand) {
		t.Fatal("genuine complete stopped OOM proof refused; no recovery/retry permitted")
	}
	after, err := readRuntimeInstallPrivateFile(root, id+".json")
	current, ce := root.Lstat(id + ".json")
	if err != nil || ce != nil || !reflect.DeepEqual(before, after) || !runtimeInstallSamePrivateFile(info, current) || ctx.Err() != nil {
		t.Fatal("read-only OOM proof changed or failed to bind original native evidence", err, ce)
	}
}

func TestRuntimeCompileOOMPublicationRejectsEveryExistingOrUnsafePath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Linux Root trusted-ancestry filesystem models required")
	}
	const base = "/var/lib/panel-executor"
	if err := threatIDSTrustedParents(base, true); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"original", "final", "pending", "final-link", "pending-link", "fifo", "parent-link", "parent-owner", "parent-mode", "invalid-id", "invalid-version", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			fixture, err := os.MkdirTemp(base, "compile-oom-publication-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if filepath.Dir(fixture) != base || !strings.HasPrefix(filepath.Base(fixture), "compile-oom-publication-") {
					t.Fatal("refuse broad fixture cleanup")
				}
				if err := os.RemoveAll(fixture); err != nil {
					t.Error(err)
				}
			})
			parent := filepath.Join(fixture, "php")
			if err := os.Mkdir(parent, 0755); err != nil {
				t.Fatal(err)
			}
			id, version := core.ID(), "8.2.35"
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mutation {
			case "final", "pending":
				name := version
				if mutation == "pending" {
					name += ".pending-" + id
				}
				if err := os.Mkdir(filepath.Join(parent, name), 0755); err != nil {
					t.Fatal(err)
				}
			case "final-link", "pending-link":
				name := version
				if mutation == "pending-link" {
					name += ".pending-" + id
				}
				if err := os.Symlink("/missing-original-runtime", filepath.Join(parent, name)); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(filepath.Join(parent, version), 0600); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				if err := os.Rename(parent, parent+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+".original", parent); err != nil {
					t.Fatal(err)
				}
			case "parent-owner":
				if err := os.Chown(parent, 65534, 65534); err != nil {
					t.Fatal(err)
				}
				defer os.Chown(parent, 0, 0)
			case "parent-mode":
				if err := os.Chmod(parent, 0775); err != nil {
					t.Fatal(err)
				}
			case "invalid-id":
				id = "../" + id
			case "invalid-version":
				version = "../8.2.35"
			case "cancelled":
				cancel()
			}
			before, err := os.Lstat(parent)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := runtimeCompileOOMPublication(ctx, parent, version, id)
			if mutation == "original" {
				second, se := runtimeCompileOOMPublication(ctx, parent, version, id)
				if err != nil || se != nil || len(bound) != 64 || bound != second {
					t.Fatal(bound, second, err, se)
				}
			} else if err == nil || bound != "" {
				t.Fatal("existing/unsafe publication path admitted", mutation, bound, err)
			}
			after, err := os.Lstat(parent)
			if err != nil || !programQueueSame(before, after) {
				t.Fatal("publication proof repaired/changed original path", mutation, err)
			}
		})
	}
}
