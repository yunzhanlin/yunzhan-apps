package executor

import (
	"context"
	"errors"
	"local/panel/internal/runtimecatalog"
	"testing"
	"time"
)

func TestApacheRuntimeObservationWaitsForLauncherExecWithoutRepeatingServiceOperation(t *testing.T) {
	// Reproduce the real native failure: systemd already says active, while
	// /proc/MainPID/exe still belongs to the normal integrity-checking launcher.
	calls := 0
	state, actual, err := waitApacheRuntimeExecutable(context.Background(), runtimecatalog.ApacheCurrentID, func(context.Context) (string, string, error) {
		calls++
		if calls == 1 {
			return "", "", errors.New("Apache 主进程未使用受管审核程序")
		}
		if calls == 2 {
			return "active", runtimecatalog.ApacheLegacyID, nil
		}
		return "active", runtimecatalog.ApacheCurrentID, nil
	})
	if err != nil || state != "active" || actual != runtimecatalog.ApacheCurrentID || calls != 3 {
		t.Fatalf("launcher was mistaken for httpd or actual exec was missed: %q %q %v calls=%d", state, actual, err, calls)
	}
}

func TestApacheRuntimeObservationCannotAcceptWrongOrInactiveExecutable(t *testing.T) {
	for name, value := range map[string][2]string{
		"old-executable": {"active", runtimecatalog.ApacheLegacyID},
		"no-pid":         {"inactive", ""},
		"failed":         {"failed", runtimecatalog.ApacheCurrentID},
		"transitional":   {"activating", runtimecatalog.ApacheCurrentID},
		"unknown":        {"active", "apache-2.4.70"},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			state, actual, err := waitApacheRuntimeExecutable(ctx, runtimecatalog.ApacheCurrentID, func(context.Context) (string, string, error) { return value[0], value[1], nil })
			if err == nil || !errors.Is(err, context.DeadlineExceeded) || state != "" || actual != "" {
				t.Fatal("unverified executable escaped the original deadline", state, actual, err)
			}
		})
	}
}

func TestApacheRuntimeObservationCancelledCallerNeverStartsObservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	_, _, err := waitApacheRuntimeExecutable(ctx, runtimecatalog.ApacheCurrentID, func(context.Context) (string, string, error) {
		calls++
		return "active", runtimecatalog.ApacheCurrentID, nil
	})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("cancelled original task acquired a fresh observation", err, calls)
	}
	_, _, err = waitApacheRuntimeExecutable(context.Background(), "apache-2.4.70", func(context.Context) (string, string, error) { calls++; return "active", "apache-2.4.70", nil })
	if err == nil || calls != 0 {
		t.Fatal("unreviewed target acquired runtime authority", err, calls)
	}
}

func TestApacheRuntimeObservationRejectsLateIdentityAfterOriginalDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	state, actual, err := waitApacheRuntimeExecutable(ctx, runtimecatalog.ApacheCurrentID, func(observation context.Context) (string, string, error) {
		<-observation.Done()
		return "active", runtimecatalog.ApacheCurrentID, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || state != "" || actual != "" {
		t.Fatal("late identity became a completed activation", state, actual, err)
	}
}
