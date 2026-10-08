//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func requireApacheRecoveryRuntime(t *testing.T) {
	t.Helper()
	if os.Getenv("PANEL_QA_APACHE_NATIVE") != "1" {
		t.Skip("explicit isolated pinned Apache runtime required")
	}
	if _, err := apacheRelease(); err != nil {
		t.Fatal("requested pinned runtime absent", err)
	}
}

// These tests invoke a command double, not an actual system service. The real
// Apache request/ABI tests and later signed service acceptance are separate.
func TestApacheWAFRecoveryKeepsPendingUntilNativeValidation(t *testing.T) {
	requireApacheRecoveryRuntime(t)
	for _, failure := range []string{"syntax", "reload", "unknown-service"} {
		t.Run(failure, func(t *testing.T) {
			s, plan := apacheTransactionFixture(t, false, false)
			if _, err := s.startWAFTransaction(plan); err != nil {
				t.Fatal(err)
			}
			if err := wafApplyChange(plan[0], true); err != nil {
				t.Fatal(err)
			}
			reloads := 0
			s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
				call := strings.Join(args, " ")
				if name == "/usr/bin/systemctl" {
					if call == "is-active panel-apache" {
						if failure == "unknown-service" {
							return "unknown\n", errors.New("unknown unit")
						}
						return "active\n", nil
					}
					if call == "reload panel-apache" {
						reloads++
						return "", errors.New("injected reload failure")
					}
					t.Fatal("unexpected system command", name, args)
				}
				if failure == "syntax" {
					return "", errors.New("injected syntax failure")
				}
				return "Syntax OK", nil
			}
			if err := s.recoverApacheWAFBeforeMutation(context.Background()); err == nil {
				t.Fatal("failed native validation acknowledged recovery")
			}
			pending, err := s.readWAFTransaction()
			if err != nil || pending.State != "recovered" {
				t.Fatal("lost retryable recovery evidence", err)
			}
			for _, c := range plan {
				match, err := s.wafCurrentMatches(c, false)
				if err != nil || !match {
					t.Fatal("original files not restored", c.Path, err)
				}
			}
			s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
				if name == "/usr/bin/systemctl" && strings.Join(args, " ") == "is-active panel-apache" {
					return "inactive\n", errors.New("exit 3")
				}
				if name == "/usr/bin/systemctl" {
					t.Fatal("cold recovery mutated service unexpectedly", args)
				}
				return "Syntax OK", nil
			}
			if err := s.recoverApacheWAFBeforeMutation(context.Background()); err != nil {
				t.Fatal("retry on native validated cold original failed", err)
			}
			if _, err = os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("verified recovery not acknowledged", err)
			}
			if failure == "reload" && reloads != 1 {
				t.Fatal("reload boundary not tested")
			}
		})
	}
}

func TestApacheWAFTransactionPipelineProbeFailureRollsBackManifestAndFiles(t *testing.T) {
	requireApacheRecoveryRuntime(t)
	s, plan := apacheTransactionFixture(t, false, false)
	s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "/usr/bin/systemctl" && strings.Join(args, " ") == "is-active panel-apache" {
			return "inactive\n", errors.New("exit 3")
		}
		return "Syntax OK", nil
	}
	called := false
	err := s.applyApacheWAFPlanned(context.Background(), plan, func(context.Context) error {
		called = true
		if match, e := s.wafCurrentMatches(plan[2], false); e != nil || !match {
			t.Fatal("manifest committed before loaded probe", e)
		}
		return errors.New("injected actual load verification failure")
	}, func(string) {})
	if err == nil || !called {
		t.Fatal("missing load verification boundary", err)
	}
	for _, c := range plan {
		match, e := s.wafCurrentMatches(c, false)
		if e != nil || !match {
			t.Fatal("failure did not restore original triplet", c.Path, e)
		}
	}
	if _, err = os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful rollback remains unacknowledged", err)
	}
}

func TestApacheWAFTransactionPipelineSuccessfulRemovalPreservesSourceAndEvidence(t *testing.T) {
	requireApacheRecoveryRuntime(t)
	s, plan := apacheTransactionFixture(t, true, true)
	s.Config.Run = func(context.Context, string, ...string) (string, error) { return "Syntax OK", nil }
	if err := s.applyApacheWAFPlanned(context.Background(), plan, func(context.Context) error { return nil }, func(string) {}); err != nil {
		t.Fatal(err)
	}
	for _, c := range plan {
		match, e := s.wafCurrentMatches(c, true)
		if e != nil || !match {
			t.Fatal("planned final bytes/mode/existence mismatch", c.Path, e)
		}
	}
	if _, err := os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful removal left pending", err)
	}
	rows, err := os.ReadDir(filepath.Dir(s.wafPendingPath()))
	if err != nil || len(rows) != 1 {
		t.Fatal("committed recovery evidence missing", err)
	}
}

func TestApacheWAFKnown21PolicyOnlyMigratesUnderSignedUpgrade(t *testing.T) {
	s := wafPolicyFixture(t)
	cfg := core.DefaultApacheWAFConfig()
	cfg.Policy.Revision = 9
	cfg.TrustedProxy = apacheTrustedProxyFixture()
	if err := moduleWrite(filepath.Join(s.moduleDir("apache-waf"), "installed.json"), map[string]any{"id": "apache-waf", "version": "2.1.0", "settings": core.WAFSettings(cfg)}); err != nil {
		t.Fatal(err)
	}
	raw := core.WAFSettings(cfg)
	if _, err := s.apacheWAFSettingsForApply(raw, false, false); err == nil {
		t.Fatal("ordinary configure enabled a legacy application's trust")
	}
	next, err := s.apacheWAFSettingsForApply(raw, false, true)
	if err != nil || next.Policy.Revision != 9 || next.TrustedProxy == nil || !next.TrustedProxy.Enabled {
		t.Fatal("known signed legacy policy not preserved", err)
	}
}

func TestApacheWAFKnown21ReadOnlyViewPreservesPolicyWithoutWriteAuthority(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("trust-enabled-%v", enabled), func(t *testing.T) {
			s := wafPolicyFixture(t)
			cfg := core.DefaultApacheWAFConfig()
			cfg.Policy.Revision = 9
			cfg.TrustedProxy = apacheTrustedProxyFixture()
			cfg.TrustedProxy.Enabled = enabled
			path := filepath.Join(s.moduleDir("apache-waf"), "installed.json")
			if err := moduleWrite(path, map[string]any{"id": "apache-waf", "version": "2.1.0", "settings": core.WAFSettings(cfg)}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			s.Config.Run = func(context.Context, string, ...string) (string, error) {
				t.Fatal("read-only legacy view attempted a native command")
				return "", nil
			}
			view, err := s.apacheWAFReadSettings()
			got, _ := json.Marshal(view)
			want, _ := json.Marshal(cfg)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("old policy cannot be viewed exactly", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("read-only view changed the installation", err)
			}
			if _, err := s.apacheWAFSettingsForApply(core.WAFSettings(view), false, false); err == nil {
				t.Fatal("read-only view gave ordinary configure signed-upgrade authority")
			}
			if err := moduleWrite(path, map[string]any{"id": "apache-waf", "version": "9.0.0", "settings": core.WAFSettings(cfg)}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.apacheWAFReadSettings(); err == nil {
				t.Fatal("unknown legacy identity semantics guessed")
			}
		})
	}
}

func TestApacheWAFOwnExecStartPreOnlyAcknowledgesVerifiedZeroMainPID(t *testing.T) {
	requireApacheRecoveryRuntime(t)
	for _, pid := range []string{"0", "42", "unknown"} {
		t.Run(pid, func(t *testing.T) {
			s, plan := apacheTransactionFixture(t, false, false)
			if _, err := s.startWAFTransaction(plan); err != nil {
				t.Fatal(err)
			}
			s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
				if name != "/usr/bin/systemctl" {
					return "Syntax OK", nil
				}
				if strings.Join(args, " ") == "is-active panel-apache" {
					return "activating\n", errors.New("exit 3")
				}
				if strings.Join(args, " ") == "show panel-apache --property=MainPID --value" {
					return pid + "\n", nil
				}
				t.Fatal("unexpected native command", name, args)
				return "", nil
			}
			err := s.recoverApacheWAFBeforeMutation(context.Background())
			if (err == nil) != (pid == "0") {
				t.Fatal("activation process identity incorrectly acknowledged", pid, err)
			}
			_, pendingErr := os.Lstat(s.wafPendingPath())
			if pid == "0" && !errors.Is(pendingErr, os.ErrNotExist) || pid != "0" && pendingErr != nil {
				t.Fatal("wrong pending evidence state", pendingErr)
			}
		})
	}
}
