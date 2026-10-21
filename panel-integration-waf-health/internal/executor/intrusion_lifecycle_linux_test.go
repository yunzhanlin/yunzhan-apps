//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestIntrusionLifecycleOriginalReceiptNeverReplaysOrStealsPending(t *testing.T) {
	for _, kind := range []string{"committed", "committed-pending", "different-request", "rolled-back", "unknown-pending", "other-pending"} {
		t.Run(kind, func(t *testing.T) {
			s, lock, p, raw, d, _ := intrusionAdvanceFixture(t)
			ctx := context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID)
			if kind == "committed-pending" {
				if err := s.intrusionJournalWriteFile(ctx, lock, p, raw, 0, "committed"); err != nil {
					t.Fatal(err)
				}
				if err := s.intrusionJournalWriteScalars(ctx, lock, p, raw, "committed"); err != nil {
					t.Fatal(err)
				}
				if err := s.intrusionJournalWriteKernel(ctx, lock, p, raw, "committed"); err != nil {
					t.Fatal(err)
				}
				for _, slot := range []int{2, 1} {
					if err := s.intrusionJournalWriteFile(ctx, lock, p, raw, slot, "committed"); err != nil {
						t.Fatal(err)
					}
				}
				if err := s.intrusionJournalWriteTerminal(ctx, lock, p, raw, "committed", ""); err != nil {
					t.Fatal(err)
				}
			} else if kind == "rolled-back" {
				recovery := core.ID()
				if err := s.intrusionJournalAdvance(context.WithValue(ctx, intrusionJobContextKey{}, recovery), lock, p, raw, "rolled_back", recovery); err != nil {
					t.Fatal(err)
				}
			} else if kind != "unknown-pending" {
				if err := s.intrusionJournalAdvance(ctx, lock, p, raw, "committed", ""); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "other-pending" {
				settings := map[string]any{"max_retry": 5, "find_time_minutes": 10, "ban_time_minutes": 60}
				if _, _, err := s.intrusionPrepareOperation(context.WithValue(ctx, intrusionJobContextKey{}, core.ID()), lock, "configure", settings); err != nil {
					t.Fatal(err)
				}
			}
			_, pendingBefore, pendingErr := s.intrusionJournalPending()
			writes := []int{len(d.Scalars), len(d.Templates), d.Checks, d.Applies}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			action := "update"
			if kind == "different-request" {
				action = "uninstall"
			}
			var steps []string
			err := s.applyIntrusionOperation(ctx, nil, action, func(v string) { steps = append(steps, v) })
			wantSuccess := kind == "committed" || kind == "committed-pending"
			if (err == nil) != wantSuccess {
				t.Fatal("wrong original-receipt result", err)
			}
			if !slices.Equal(writes, []int{len(d.Scalars), len(d.Templates), d.Checks, d.Applies}) {
				t.Fatal("original receipt replayed system writes")
			}
			_, pendingAfter, afterErr := s.intrusionJournalPending()
			if wantSuccess {
				if !errors.Is(afterErr, os.ErrNotExist) || len(steps) != 1 {
					t.Fatal("original close not verified", afterErr)
				}
			} else if pendingErr == nil {
				if afterErr != nil || !bytes.Equal(pendingBefore, pendingAfter) {
					t.Fatal("refused request stole or replaced pending", afterErr)
				}
			}
		})
	}
}

func TestIntrusionLifecycleFreshOriginalCommitsOnceAndWarnsOnDurationRestoration(t *testing.T) {
	s, lock, p, _, d, _ := intrusionAdvanceFixtureWithSetup(t, func(_ *Service, p *intrusionJournalPlan) { intrusionRemovalPlanSetup(t, p, []int{22}) })
	if err := os.Remove(filepath.Join(s.Config.SecurityDir, intrusionPendingName)); err != nil {
		t.Fatal(err)
	} // ONLY the fake fixture's initial latch.
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	run := s.Config.Run
	s.Config.Run = func(ctx context.Context, program string, args ...string) (string, error) {
		if program == "/usr/bin/python3" && len(args) == 6 && slices.Equal(args[:5], []string{"-I", "-B", "-c", intrusionConfigurationDumpScript, "--owned-removal-candidate"}) {
			return string(p.Removal.Dump), nil
		}
		return run(ctx, program, args...)
	}
	id := core.ID()
	ctx := context.WithValue(context.Background(), intrusionJobContextKey{}, id)
	var steps []string
	add := func(v string) { steps = append(steps, v) }
	if err := s.applyIntrusionOperation(ctx, nil, "uninstall", add); err != nil {
		t.Fatal(err)
	}
	if len(d.Scalars) != 3 || len(d.Templates) != 0 || d.Checks != 0 || d.Applies != 0 || len(steps) != 3 || !strings.Contains(steps[0], "到期时间会随新策略改变") {
		t.Fatal("missing explicit duration semantics or unexpected operations", d, steps)
	}
	for _, name := range s.intrusionJournalPaths() {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned file remains", err)
		}
	}
	if err := s.applyIntrusionOperation(ctx, nil, "uninstall", add); err != nil {
		t.Fatal("idempotent original rejected", err)
	}
	if len(d.Scalars) != 3 || len(steps) != 4 {
		t.Fatal("original request replayed uninstall")
	}
}

func TestIntrusionLifecycleRejectsUnqualifiedEntryBeforeAnyRuntimeCommand(t *testing.T) {
	for _, kind := range []string{"missing-job", "cancelled", "unknown-action", "update-settings", "uninstall-settings"} {
		t.Run(kind, func(t *testing.T) {
			s, lock, p, raw, d, _ := intrusionAdvanceFixture(t)
			lock.Close()
			ctx := context.WithValue(context.Background(), intrusionJobContextKey{}, p.ID)
			action := "update"
			var settings map[string]any
			switch kind {
			case "missing-job":
				ctx = context.Background()
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "unknown-action":
				action = "restart"
			case "update-settings":
				settings = map[string]any{"max_retry": 7}
			case "uninstall-settings":
				action = "uninstall"
				settings = map[string]any{"force": true}
			}
			calls := 0
			s.Config.Run = func(context.Context, string, ...string) (string, error) { calls++; return "", errors.New("unexpected") }
			if err := s.applyIntrusionOperation(ctx, settings, action, func(string) { t.Fatal("refused request logged success") }); err == nil {
				t.Fatal("unqualified controller entry accepted")
			}
			_, pending, err := s.intrusionJournalPending()
			if err != nil || !bytes.Equal(raw, pending) || calls != 0 || len(d.Scalars) != 0 || len(d.Templates) != 0 || d.Checks != 0 || d.Applies != 0 {
				t.Fatal("refused entry changed original authority", err)
			}
		})
	}
}
