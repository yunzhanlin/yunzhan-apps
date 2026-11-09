//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Test-only persistent kernel model: subprocess SIGKILL must not erase state.
// No helper invokes a real sysctl, shell, service command or production root.
func hardeningProcessService(t *testing.T, root, cut string) *Service {
	t.Helper()
	info, err := os.Lstat(root)
	if err != nil || root == "/" || !filepath.IsAbs(root) || filepath.Clean(root) != root || !hardeningJournalDirectoryInfo(info) {
		t.Fatal("invalid private process fixture root", err)
	}
	c := Config{SystemRoot: root, SecurityDir: filepath.Join(root, "security"), SitesDir: filepath.Join(root, "sites"), ConfDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), ApacheSiteConfig: filepath.Join(root, "apache.conf"), NginxConf: filepath.Join(root, "nginx.conf"), NginxBin: "/usr/sbin/nginx"}
	for _, path := range []string{c.SecurityDir, c.SitesDir, c.ConfDir, c.StateDir} {
		st, err := os.Lstat(path)
		if err != nil || !hardeningJournalDirectoryInfo(st) {
			t.Fatal("private fixture directory invalid", err)
		}
	}
	model := filepath.Join(root, "kernel-values.json")
	read := func() (map[string]string, error) {
		st, err := os.Lstat(model)
		if err != nil || !softwareManifestRecordInfo(st) || st.Mode().Perm() != 0600 || st.Size() < 1 || st.Size() > 8192 {
			return nil, errors.New("private persistent kernel model invalid")
		}
		raw, err := os.ReadFile(model)
		if err != nil {
			return nil, err
		}
		var values map[string]string
		if json.Unmarshal(raw, &values) != nil || len(values) != len(hardeningValues("strict")) {
			return nil, errors.New("private kernel model schema invalid")
		}
		for key := range hardeningValues("strict") {
			if !hardeningValueValid(key, values[key]) {
				return nil, errors.New("private kernel model key invalid")
			}
		}
		return values, nil
	}
	stop := func(phase string) { fmt.Fprintln(os.Stdout, "hardening-cut "+phase); select {} }
	var svc *Service
	c.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if name != "/usr/sbin/sysctl" || len(args) != 2 {
			return "", errors.New("test adapter refused external command")
		}
		values, err := read()
		if err != nil {
			return "", err
		}
		switch args[0] {
		case "-n":
			if cut == "manifest" {
				m, err := svc.readSoftwareManifest("system-hardening")
				if err == nil && m.Settings["profile"] == "strict" {
					stop(cut)
				}
			}
			value, ok := values[args[1]]
			if !ok {
				return "", errors.New("foreign model read")
			}
			return value + "\n", nil
		case "-p":
			if args[1] != svc.systemPath("/etc/sysctl.d/99-zz-panel-hardening.conf") {
				return "", errors.New("foreign model profile path")
			}
			if cut == "config" {
				stop(cut)
			}
			raw, err := os.ReadFile(args[1])
			if err != nil {
				return "", err
			}
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(line, "#") || line == "" {
					continue
				}
				key, value, ok := strings.Cut(line, "=")
				key = strings.TrimSpace(key)
				value = strings.TrimSpace(value)
				if !ok || !hardeningValueValid(key, value) {
					return "", errors.New("foreign model assignment")
				}
				values[key] = value
			}
		case "-w":
			key, value, ok := strings.Cut(args[1], "=")
			if !ok || !hardeningValueValid(key, value) {
				return "", errors.New("foreign model assignment")
			}
			values[key] = value
		default:
			return "", errors.New("unsupported model operation")
		}
		raw, err := json.Marshal(values)
		if err != nil {
			return "", err
		}
		if err = atomicWrite(model, append(raw, '\n'), 0600); err != nil {
			return "", err
		}
		if cut == "kernel" {
			stop(cut)
		}
		return "", nil
	}
	svc = New(c)
	return svc
}

func TestHardeningJournalKilledProcessHelper(t *testing.T) {
	root := os.Getenv("PANEL_TEST_HARDENING_ROOT")
	if root == "" {
		return
	}
	cut := os.Getenv("PANEL_TEST_HARDENING_CUT")
	job := os.Getenv("PANEL_TEST_HARDENING_JOB")
	if !core.ValidID(job) {
		t.Fatal("invalid test job")
	}
	svc := hardeningProcessService(t, root, cut)
	ctx := context.WithValue(context.Background(), hardeningJobContextKey{}, job)
	if cut == "prepared" || cut == "terminal" {
		lock, err := svc.hardeningMutationLock()
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		config, err := svc.hardeningConfigBackups()
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := svc.hardeningManifestBackup()
		if err != nil {
			t.Fatal(err)
		}
		before, err := svc.hardeningReadValues(ctx, hardeningValues("strict"))
		if err != nil {
			t.Fatal(err)
		}
		plan, raw, err := svc.hardeningPrepareOperation(ctx, job, "configure", "strict", before, config, manifest)
		if err != nil {
			t.Fatal(err)
		}
		if cut == "terminal" {
			paths := svc.hardeningJournalPaths()
			for _, i := range []int{0, 2} {
				file := plan.Files[i].After
				if err = atomicWriteWithOwner(paths[i], file.Data, os.FileMode(file.Mode), file.Owner); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = svc.Config.Run(ctx, "/usr/sbin/sysctl", "-p", paths[0]); err != nil {
				t.Fatal(err)
			}
			if err = svc.hardeningJournalWriteTerminal(plan, raw, "committed", ""); err != nil {
				t.Fatal(err)
			}
		}
		fmt.Fprintln(os.Stdout, "hardening-cut "+cut)
		select {}
	}
	if cut != "config" && cut != "kernel" && cut != "manifest" {
		t.Fatal("unknown declared cut")
	}
	if err := svc.applyHardening(ctx, map[string]any{"profile": "strict"}, false, func(string) {}); err != nil {
		t.Fatal(err)
	}
	t.Fatal("declared cut did not suspend child")
}

func TestHardeningJournalActualSIGKILLPreservesOriginalPlanAndRequiresExplicitRecovery(t *testing.T) {
	for _, cut := range []string{"prepared", "config", "kernel", "manifest", "terminal"} {
		t.Run(cut, func(t *testing.T) {
			f := newHardeningFixture(t)
			if err := f.apply("baseline", true); err != nil {
				t.Fatal(err)
			}
			root := f.s.Config.SystemRoot
			model := filepath.Join(root, "kernel-values.json")
			raw, err := json.Marshal(f.values)
			if err != nil {
				t.Fatal(err)
			}
			if err = atomicWrite(model, append(raw, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			job := core.ID()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHardeningJournalKilledProcessHelper$", "-test.v", "-test.timeout=20s")
			cmd.Env = append(os.Environ(), "PANEL_TEST_HARDENING_ROOT="+root, "PANEL_TEST_HARDENING_CUT="+cut, "PANEL_TEST_HARDENING_JOB="+job)
			pipe, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			type readiness struct {
				ok       bool
				observed string
			}
			ready := make(chan readiness, 1)
			go func() {
				scanner := bufio.NewScanner(pipe)
				var observed strings.Builder
				for scanner.Scan() {
					if observed.Len() > 32768 {
						ready <- readiness{false, "child output exceeded private fixture budget"}
						return
					}
					observed.WriteString(scanner.Text() + "\n")
					if scanner.Text() == "hardening-cut "+cut {
						ready <- readiness{true, observed.String()}
						return
					}
				}
				ready <- readiness{false, observed.String()}
			}()
			select {
			case result := <-ready:
				if !result.ok {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
					t.Fatal("child did not reach original cut", result.observed, stderr.String())
				}
			case <-ctx.Done():
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal("child cut timed out")
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("child was not actually killed", err)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("not actual SIGKILL", err)
			}
			reopened := hardeningProcessService(t, root, "")
			plan, pending, err := reopened.hardeningJournalPending()
			if err != nil || plan.ID != job {
				t.Fatal("actual exit lost original pending identity", err)
			}
			originalDigest := hardeningJournalDigest(pending)
			beforeModel, _ := os.ReadFile(model)
			beforeInfo, _ := os.Lstat(model)
			recoverCtx := context.WithValue(context.Background(), hardeningJobContextKey{}, core.ID())
			if err = reopened.recoverHardeningOperation(recoverCtx, hardeningRecoverySettings(plan, pending), func(string) {}); err != nil {
				t.Fatal(err)
			}
			state := "rolled_back"
			if cut == "terminal" {
				state = "committed"
				afterModel, _ := os.ReadFile(model)
				afterInfo, _ := os.Lstat(model)
				if !bytes.Equal(beforeModel, afterModel) || !os.SameFile(beforeInfo, afterInfo) {
					t.Fatal("committed source was replayed/compensated")
				}
			}
			if err = reopened.hardeningJournalVerifyState(recoverCtx, plan, state); err != nil {
				t.Fatal(err)
			}
			inventory, err := reopened.hardeningJournalInventoryRead()
			if err != nil {
				t.Fatal(err)
			}
			terminal := inventory.Records[job]
			if terminal.State != state || terminal.PlanSHA256 != originalDigest || terminal.Plan.ID != job {
				t.Fatal("original exit identity lost")
			}
			if cut != "terminal" {
				now := map[string]string{}
				b, _ := os.ReadFile(model)
				if json.Unmarshal(b, &now) != nil || !maps.Equal(now, f.values) {
					t.Fatal("persistent fake kernel did not restore exact pre-operation values")
				}
			}
		})
	}
}
