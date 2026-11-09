//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRemoteUnpublishedOfflineAtomicReceiptPreserves200AndOriginalFragments(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Linux Root anonymous-link capability is qualified in the separate zero-skip native Root gate")
	}
	s, _, _, base, c := offlineConditionFixture(t)
	entries, _ := os.ReadDir(base)
	part := filepath.Join(base, entries[0].Name())
	originalInfo, _ := os.Lstat(part)
	original, _ := os.ReadFile(part)
	installed := filepath.Join(s.moduleDir("files-sync"), "installed.json")
	installedInfo, _ := os.Lstat(installed)
	installedRaw, _ := os.ReadFile(installed)
	calls := 0
	view, written, err := s.retainUnpublishedOfflineCondition(c, func() error {
		calls++
		now, err := os.ReadDir(base)
		if err != nil || len(now) != 1 || now[0].Name() != entries[0].Name() {
			t.Fatal("anonymous fsynced receipt exposed a named partial file before final authorization", err)
		}
		return nil
	})
	if err != nil || !written || calls != 2 || view.State != "observed-original-retained-receipt" || view.Review.InstalledVersion != "2.0.0" || view.Review.BackupComplete || view.Review.SourceAuthority || view.Review.Downloadable {
		t.Fatal("offline receipt was not a distinct non-backup retention of the old installation", view, written, calls, err)
	}
	nowInfo, _ := os.Lstat(part)
	now, _ := os.ReadFile(part)
	installedAfter, _ := os.Lstat(installed)
	installedActual, _ := os.ReadFile(installed)
	if !programQueueSame(originalInfo, nowInfo) || !bytes.Equal(original, now) || !programQueueSame(installedInfo, installedAfter) || !bytes.Equal(installedRaw, installedActual) {
		t.Fatal("original fragment or original 2.0.0 installed record changed")
	}
	receipt := filepath.Join(base, remoteUnpublishedReceipt)
	receiptInfo, _ := os.Lstat(receipt)
	receiptRaw, _ := os.ReadFile(receipt)
	if !moduleRecordInfo(receiptInfo, false, false) {
		t.Fatal("anonymous published receipt lacks independent Root0600/nlink1 ownership")
	}
	_, replayWrite, err := s.retainUnpublishedOfflineCondition(c, func() error { return nil })
	receiptAfter, _ := os.Lstat(receipt)
	receiptActual, _ := os.ReadFile(receipt)
	if err != nil || replayWrite || !programQueueSame(receiptInfo, receiptAfter) || !bytes.Equal(receiptRaw, receiptActual) {
		t.Fatal("lost-reply recognition rewrote or republished the original receipt", err)
	}
}

func TestRemoteUnpublishedOfflineAtomicFinalRefusalLeavesNoNewPart(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Linux Root anonymous-link capability is qualified in the separate zero-skip native Root gate")
	}
	for _, kind := range []string{"missing-authority", "revoked-after-fsync", "old-fragment-writer", "foreign-receipt", "changed-config"} {
		t.Run(kind, func(t *testing.T) {
			s, cfg, _, base, c := offlineConditionFixture(t)
			entries, _ := os.ReadDir(base)
			part := filepath.Join(base, entries[0].Name())
			oldFD, err := os.OpenFile(part, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer oldFD.Close()
			calls := 0
			var authorize func() error
			if kind != "missing-authority" {
				authorize = func() error {
					calls++
					if calls != 2 {
						return nil
					}
					switch kind {
					case "revoked-after-fsync":
						return errors.New("original fixture authority revoked")
					case "old-fragment-writer":
						if _, err := oldFD.WriteAt([]byte("changed through pre-existing descriptor"), 0); err != nil {
							t.Fatal(err)
						}
					case "foreign-receipt":
						if err := os.Symlink(part, filepath.Join(base, remoteUnpublishedReceipt)); err != nil {
							t.Fatal(err)
						}
					case "changed-config":
						cfg.Revision++
						if err := moduleWrite(s.remoteConfigPath(cfg.ID), cfg); err != nil {
							t.Fatal(err)
						}
					}
					return nil
				}
			}
			if _, written, err := s.retainUnpublishedOfflineCondition(c, authorize); err == nil || written {
				t.Fatal("final stale/foreign/revoked authority published a receipt", err)
			}
			now, err := os.ReadDir(base)
			expected := 1
			if kind == "foreign-receipt" {
				expected = 2
				info, _ := os.Lstat(filepath.Join(base, remoteUnpublishedReceipt))
				if info.Mode()&os.ModeSymlink == 0 {
					t.Fatal("foreign symbolic link was overwritten")
				}
			}
			if err != nil || len(now) != expected {
				t.Fatal("refused anonymous staging left another named part", err, len(now))
			}
		})
	}
}

// The child exits only after the anonymous inode is fsynced, in the last
// authorization callback before linkat. Killing this owned process is a real
// process-loss test, distinct from the later full native power-cut acceptance.
func TestRemoteUnpublishedOfflineAnonymousProcessLoss(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Linux Root anonymous-link capability is qualified in the separate zero-skip native Root gate")
	}
	if base := os.Getenv("PANEL_TEST_OFFLINE_ANONYMOUS_BASE"); base != "" {
		raw, err := os.ReadFile(filepath.Join(base, "request.json"))
		if err != nil {
			t.Fatal(err)
		}
		var request struct {
			SecurityDir string                            `json:"security_dir"`
			Condition   remoteUnpublishedOfflineCondition `json:"condition"`
		}
		if json.Unmarshal(raw, &request) != nil {
			t.Fatal("invalid private owned fixture request")
		}
		s := &Service{Config: Config{SecurityDir: request.SecurityDir}}
		calls := 0
		_, _, err = s.retainUnpublishedOfflineCondition(request.Condition, func() error {
			calls++
			if calls == 2 {
				if err := os.WriteFile(filepath.Join(base, "anonymous-fsynced"), []byte("ready\n"), 0600); err != nil {
					return err
				}
				if err := syscall.Kill(os.Getpid(), syscall.SIGSTOP); err != nil {
					return err
				}
				return errors.New("owned process-loss fixture resumed unexpectedly")
			}
			return nil
		})
		t.Fatal("owned process-loss child was not killed at the final barrier", err)
	}
	s, _, _, base, c := offlineConditionFixture(t)
	control := t.TempDir()
	raw, _ := json.Marshal(map[string]any{"security_dir": s.Config.SecurityDir, "condition": c})
	if err := os.WriteFile(filepath.Join(control, "request.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRemoteUnpublishedOfflineAnonymousProcessLoss$")
	cmd.Env = append(os.Environ(), "PANEL_TEST_OFFLINE_ANONYMOUS_BASE="+control)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	ready := filepath.Join(control, "anonymous-fsynced")
	for {
		if _, err := os.Lstat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned process did not reach actual fsynced anonymous publication boundary", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	waited = true
	if exit, ok := err.(*exec.ExitError); !ok || !exit.ProcessState.Sys().(syscall.WaitStatus).Signaled() || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatal("original child outcome was not an owned actual SIGKILL", err)
	}
	entries, err := os.ReadDir(base)
	view, observeErr := s.matchUnpublishedOfflineCondition(c)
	if err != nil || len(entries) != 1 || observeErr != nil || view.State != "original-unpublished" || view.ObservedCensus != c.CensusSHA {
		t.Fatal("killed anonymous writer changed original inventory or left a named partial receipt", entries, err, observeErr)
	}
	if _, err := s.remoteCopyPending("", ""); err == nil {
		t.Fatal("process loss weakened ordinary original unknown-outcome guard")
	}
}

func TestRemoteUnpublishedOfflineWriterRequestIsClosed(t *testing.T) {
	request := offlineUpgradeWriterRequest{1, "0.1.0-candidate65", core.Hash("original plan"), [2]int{7, 8}}
	raw, _ := json.Marshal(request)
	if got, err := decodeOfflineWriterRequest(raw); err != nil || got != request {
		t.Fatal(got, err)
	}
	for name, input := range map[string][]byte{
		"duplicate":       bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1),
		"case-alias":      bytes.Replace(raw, []byte(`"version"`), []byte(`"Version"`), 1),
		"extra-root":      bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"root":"/tmp"`), 1),
		"extra-condition": bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"condition":{}`), 1),
		"null":            bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":null`), 1),
		"boolean":         bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":true`), 1),
		"fraction":        bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1.0`), 1),
		"path":            bytes.Replace(raw, []byte(`0.1.0-candidate65`), []byte(`../../tmp`), 1),
		"long-version":    bytes.Replace(raw, []byte(`0.1.0-candidate65`), []byte("0.1.0-"+strings.Repeat("a", 161)), 1),
		"bad-digest":      bytes.Replace(raw, []byte(request.PlanSHA), []byte(strings.Repeat("A", 64)), 1),
		"trailing":        append(append([]byte(nil), raw...), []byte(`{}`)...),
		"array":           []byte(`[]`),
		"oversize":        bytes.Repeat([]byte(" "), 513),
		"standard-fd":     bytes.Replace(raw, []byte(`[7,8]`), []byte(`[0,8]`), 1),
		"duplicate-fd":    bytes.Replace(raw, []byte(`[7,8]`), []byte(`[7,7]`), 1),
		"truncated-fds":   bytes.Replace(raw, []byte(`[7,8]`), []byte(`[7]`), 1),
		"extra-fd":        bytes.Replace(raw, []byte(`[7,8]`), []byte(`[7,8,9]`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeOfflineWriterRequest(input); err == nil {
				t.Fatal("noncanonical or caller-directed writer request accepted")
			}
		})
	}
}

func TestRemoteUnpublishedOfflineRequiresEveryFixedWriterStopped(t *testing.T) {
	for _, kind := range []string{"positive", "active-core", "remaining-pid", "remaining-cgroup", "masked", "timer-active", "recovery-active", "queued-job", "unknown-job", "duplicate-empty-field", "missing-empty-field", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			run := func(_ context.Context, program string, args ...string) (string, error) {
				if program != "/usr/bin/systemctl" {
					t.Fatal("writer stop proof used an unexpected program", program)
				}
				if args[0] == "list-jobs" {
					if kind == "queued-job" {
						return "123 panel.service start waiting\n", nil
					}
					if kind == "unknown-job" {
						return "123 unknown\n", nil
					}
					return "", nil
				}
				unit := args[1]
				raw := "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
				if !strings.HasSuffix(unit, ".timer") {
					raw += "MainPID=0\nControlPID=0\nControlGroup=\n"
				}
				if unit == "panel.service" {
					switch kind {
					case "active-core":
						raw = strings.Replace(raw, "ActiveState=inactive", "ActiveState=active", 1)
					case "remaining-pid":
						raw = strings.Replace(raw, "MainPID=0", "MainPID=99", 1)
					case "remaining-cgroup":
						raw = strings.Replace(raw, "ControlGroup=\n", "ControlGroup=/system.slice/panel.service\n", 1)
					case "masked":
						raw = strings.Replace(raw, "LoadState=loaded", "LoadState=masked", 1)
					case "duplicate-empty-field":
						raw += "ControlGroup=\n"
					case "missing-empty-field":
						raw = strings.Replace(raw, "ControlGroup=\n", "", 1)
					case "unknown-field":
						raw = strings.Replace(raw, "ControlGroup=\n", "Unknown=\n", 1)
					}
				}
				if kind == "timer-active" && strings.HasSuffix(unit, ".timer") || kind == "recovery-active" && unit == "panel-mysql-overwrite-recovery.service" {
					raw = strings.Replace(raw, "ActiveState=inactive", "ActiveState=active", 1)
				}
				return raw, nil
			}
			if err := checkOfflineUpgradeStopped(context.Background(), run); (err == nil) != (kind == "positive") {
				t.Fatal("fixed-writer proof did not preserve exact stop boundaries", err)
			}
		})
	}
}

func TestRemoteUnpublishedOfflineExclusiveLeaseRejectsAmbiguity(t *testing.T) {
	device := unix.Mkdev(8, 1)
	valid := "1: FLOCK ADVISORY WRITE 123 08:01:456 0 EOF\n"
	if !offlineParentExclusiveLease([]byte(valid), 123, device, 456) {
		t.Fatal("exact exclusive kernel lease refused")
	}
	for _, raw := range []string{"", valid + valid, strings.Replace(valid, "WRITE", "READ", 1), strings.Replace(valid, "123", "124", 1), strings.Replace(valid, "456", "457", 1), strings.Replace(valid, "FLOCK", "OFDLCK", 1), strings.Replace(valid, "0 EOF", "0 99", 1)} {
		if offlineParentExclusiveLease([]byte(raw), 123, device, 456) {
			t.Fatal("missing, shared, duplicate, foreign or partial kernel lease admitted")
		}
	}
}

func TestRemoteUnpublishedOfflineRootTreeRejectsLinksAndDetachedParents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Root-owned nofollow tree is qualified by the separate zero-skip native Root gate")
	}
	for _, kind := range []string{"safe", "symlink-file", "hardlink-file", "unsafe-file-mode", "symlink-parent", "detached-parent", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			base, err := os.MkdirTemp("/root", "panel-owned-offline-tree-test-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(base) })
			dir := filepath.Join(base, "child")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "original.json")
			original := []byte("original independent Root data\n")
			if err := os.WriteFile(file, original, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink-parent" {
				path := filepath.Join(base, "alias")
				if err := os.Symlink(dir, path); err != nil {
					t.Fatal(err)
				}
				if tree, err := openOfflineRootTree(path); err == nil {
					tree.Close()
					t.Fatal("linked parent accepted")
				}
				return
			}
			tree, err := openOfflineRootTree(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer tree.Close()
			name := "original.json"
			switch kind {
			case "symlink-file":
				name = "linked.json"
				err = os.Symlink(file, filepath.Join(dir, name))
			case "hardlink-file":
				name = "linked.json"
				err = os.Link(file, filepath.Join(dir, name))
			case "unsafe-file-mode":
				err = os.Chmod(file, 0660)
			case "detached-parent":
				err = os.Rename(dir, filepath.Join(base, "original-child"))
				if err == nil {
					err = os.Mkdir(dir, 0700)
				}
			case "fifo":
				name = "record.fifo"
				err = unix.Mkfifo(filepath.Join(dir, name), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, _, err := tree.read(name, 0600, 4096)
			if kind == "safe" {
				if err != nil || !bytes.Equal(raw, original) {
					t.Fatal("safe Root-held file refused", err)
				}
			} else if err == nil {
				t.Fatal("unsafe link, mode, type or detached parent was read")
			}
			if kind == "detached-parent" {
				file = filepath.Join(base, "original-child", "original.json")
			}
			actual, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(actual, original) {
				t.Fatal("read-only refusal changed original data", err)
			}
		})
	}
}
