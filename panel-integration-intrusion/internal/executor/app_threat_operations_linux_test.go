//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func threatIDSOperationsFixture(t *testing.T) *Service {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	s := New(Config{StateDir: state, SystemRoot: root, SecurityDir: filepath.Join(root, "security")})
	if err := moduleWrite(filepath.Join(s.moduleDir("network-threat-detection"), "installed.json"), map[string]any{"id": "network-threat-detection"}); err != nil {
		t.Fatal(err)
	}
	s.idsOperationStarted = true
	s.idsOperationWake = make(chan struct{}, 1)
	return s
}

func TestThreatIDSOperationsStableReplayImmutableTerminalAndOnePending(t *testing.T) {
	s := threatIDSOperationsFixture(t)
	id := core.ID()
	input := core.NetworkIDSOperationRequest{Action: "ids-start", Input: core.NetworkIDSOperationInput{ExpectedRevision: 3}}
	queued, err := s.enqueueThreatIDSOperation(id, input)
	if err != nil || queued.State != "queued" {
		t.Fatal(err, queued)
	}
	path := filepath.Join(s.threatIDSOperationsDir(), id+".json")
	before, _ := os.ReadFile(path)
	if replay, err := s.enqueueThreatIDSOperation(id, input); err != nil || replay.ID != id {
		t.Fatal("stable retry", err)
	}
	if _, err := s.enqueueThreatIDSOperation(core.ID(), input); err == nil {
		t.Fatal("second pending operation accepted")
	}
	changed := input
	changed.Input.ExpectedRevision++
	if _, err := s.enqueueThreatIDSOperation(id, changed); err == nil {
		t.Fatal("changed input overwrote original")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("queued retry rewrote bytes")
	}
	calls := 0
	s.drainThreatIDSOperations(func(ctx context.Context, action string, in core.AppModuleInput) (any, error) {
		calls++
		if action != "ids-start" || in.ExpectedRevision != 3 {
			t.Fatal("wrong immutable input")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > threatIDSOperationBudget {
			t.Fatal("unbounded background lifetime")
		}
		if !s.mu.TryLock() {
			t.Fatal("IDS blocked global website lock")
		}
		s.mu.Unlock()
		return nil, nil
	})
	out, err := s.threatIDSOperation(id)
	if err != nil || out.State != "succeeded" || calls != 1 {
		t.Fatal(out, err, calls)
	}
	before, _ = os.ReadFile(path)
	if out, err := s.enqueueThreatIDSOperation(id, input); err != nil || out.State != "succeeded" {
		t.Fatal("terminal replay", err)
	}
	s.drainThreatIDSOperations(func(context.Context, string, core.AppModuleInput) (any, error) { calls++; return nil, nil })
	after, _ = os.ReadFile(path)
	if calls != 1 || string(before) != string(after) {
		t.Fatal("terminal operation replayed or overwritten")
	}
	var v threatIDSOperationRecord
	json.Unmarshal(before, &v)
	v.Operation.State = "running"
	if s.saveThreatIDSOperation(v) == nil {
		t.Fatal("terminal receipt reused as running")
	}
}

func TestThreatIDSOperationsInterruptedExecutionAndDispatchedRecoveryAreNotSuccess(t *testing.T) {
	for _, scenario := range []string{"restart", "control-error", "dispatched-recovery"} {
		t.Run(scenario, func(t *testing.T) {
			s := threatIDSOperationsFixture(t)
			input := core.NetworkIDSOperationRequest{Action: "ids-recover", Input: core.NetworkIDSOperationInput{ExpectedRevision: 2}}
			id := core.ID()
			if _, err := s.enqueueThreatIDSOperation(id, input); err != nil {
				t.Fatal(err)
			}
			if scenario == "restart" {
				items, _ := s.readThreatIDSOperations()
				item := items[0]
				item.Operation.State = "running"
				item.Operation.UpdatedAt = core.Now()
				if err := s.saveThreatIDSOperation(item); err != nil {
					t.Fatal(err)
				}
				fresh := New(s.Config)
				if err := fresh.StartNetworkIDSOperations(); err != nil {
					t.Fatal(err)
				}
				s = fresh
			} else {
				s.drainThreatIDSOperations(func(context.Context, string, core.AppModuleInput) (any, error) {
					if scenario == "control-error" {
						return nil, errors.New("own injected unknown native outcome")
					}
					return map[string]any{"state": "recovering-runtime", "recovered": false}, nil
				})
			}
			out, err := s.threatIDSOperation(id)
			if err != nil || out.State != "needs-attention" || out.Error == "" {
				t.Fatal("interruption or merely dispatched recovery declared success", out, err)
			}
			path := filepath.Join(s.threatIDSOperationsDir(), id+".json")
			before, _ := os.ReadFile(path)
			if _, err := s.enqueueThreatIDSOperation(id, input); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("interrupted receipt overwritten")
			}
		})
	}
}

func TestThreatIDSOperationsMalformedRecordsFreezeWithoutTouchingOtherModules(t *testing.T) {
	for _, scenario := range []string{"edited", "mode", "symlink", "unknown-file", "missing-installed"} {
		t.Run(scenario, func(t *testing.T) {
			s := threatIDSOperationsFixture(t)
			id := core.ID()
			input := core.NetworkIDSOperationRequest{Action: "ids-stop", Input: core.NetworkIDSOperationInput{ExpectedRevision: 1}}
			if scenario == "missing-installed" {
				if err := os.Remove(filepath.Join(s.moduleDir("network-threat-detection"), "installed.json")); err != nil {
					t.Fatal(err)
				}
				if _, err := s.enqueueThreatIDSOperation(id, input); err == nil {
					t.Fatal("uninstalled app queued")
				}
				return
			}
			if _, err := s.enqueueThreatIDSOperation(id, input); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.threatIDSOperationsDir(), id+".json")
			if scenario == "mode" {
				os.Chmod(path, 0644)
			} else if scenario == "unknown-file" {
				os.WriteFile(filepath.Join(s.threatIDSOperationsDir(), "unknown.json"), []byte("retained"), 0600)
			} else if scenario == "symlink" {
				target := filepath.Join(s.Config.StateDir, "own-link-target")
				os.Rename(path, target)
				os.Symlink(target, path)
			} else {
				raw, _ := os.ReadFile(path)
				os.WriteFile(path, []byte(strings.Replace(string(raw), `"format":1`, `"format":99`, 1)), 0600)
			}
			if _, err := s.threatIDSOperation(id); err == nil {
				t.Fatal("malformed private receipt accepted")
			}
			calls := 0
			s.drainThreatIDSOperations(func(context.Context, string, core.AppModuleInput) (any, error) { calls++; return nil, nil })
			if calls != 0 || s.idsOperationError == nil {
				t.Fatal("damaged queue executed")
			}
			if s.mu.TryLock() {
				s.mu.Unlock()
			} else {
				t.Fatal("damaged IDS queue disabled other modules")
			}
		})
	}
}
