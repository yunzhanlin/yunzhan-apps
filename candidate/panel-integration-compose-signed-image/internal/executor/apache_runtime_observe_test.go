package executor

import (
	"context"
	"errors"
	"io"
	"local/panel/internal/runtimecatalog"
	"maps"
	"net"
	"net/http"
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

func TestApacheRuntimeReadinessSurvivesActualListenerNotYetBound(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	if err = reserved.Close(); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	defer server.Close()
	calls := 0
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	expected := map[string]int{"qa.example.test": http.StatusNoContent}
	result, err := waitApacheRuntimeResponses(context.Background(), expected, func(ctx context.Context) (map[string]int, error) {
		calls++
		request, e := http.NewRequestWithContext(ctx, "GET", "http://"+address+"/", nil)
		if e != nil {
			return nil, e
		}
		request.Host = "qa.example.test"
		response, e := client.Do(request)
		if calls == 1 {
			if e == nil {
				response.Body.Close()
				t.Fatal("the owned listener was unexpectedly already serving")
			}
			listener, startErr := net.Listen("tcp", address)
			if startErr != nil {
				t.Fatal(startErr)
			}
			go server.Serve(listener)
		}
		if e != nil {
			return nil, e
		}
		defer response.Body.Close()
		_, e = io.Copy(io.Discard, response.Body)
		return map[string]int{"qa.example.test": response.StatusCode}, e
	})
	if err != nil || !maps.Equal(result, expected) || calls != 2 {
		t.Fatal("committed before the real listener was ready or missed readiness", result, err, calls)
	}
}

func TestApacheRuntimeReadinessRejectsPartialForeignOrChangedWebsiteResults(t *testing.T) {
	expected := map[string]int{"one.example.test": 200, "two.example.test": 403}
	for name, actual := range map[string]map[string]int{
		"partial":        {"one.example.test": 200},
		"changed-status": {"one.example.test": 200, "two.example.test": 200},
		"foreign-domain": {"one.example.test": 200, "three.example.test": 403},
		"extra-domain":   {"one.example.test": 200, "two.example.test": 403, "extra.example.test": 200},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			result, err := waitApacheRuntimeResponses(ctx, expected, func(context.Context) (map[string]int, error) { return actual, nil })
			if result != nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("incomplete original website set became committed readiness", result, err)
			}
		})
	}
}

func TestApacheRuntimeReadinessRejectsLateResultsAndCancelledOrUnknownOriginals(t *testing.T) {
	expected := map[string]int{"qa.example.test": 200}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	actual, err := waitApacheRuntimeResponses(ctx, expected, func(ctx context.Context) (map[string]int, error) { <-ctx.Done(); return expected, nil })
	if actual != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("late response escaped original task deadline", actual, err)
	}
	calls := 0
	for _, invalid := range []map[string]int{nil, {"qa.example.test": 500}, {"untrusted.invalid/path": 200}} {
		_, err := waitApacheRuntimeResponses(context.Background(), invalid, func(context.Context) (map[string]int, error) { calls++; return invalid, nil })
		if err == nil || calls != 0 {
			t.Fatal("unknown original website result acquired readiness authority", err, calls)
		}
	}
}
