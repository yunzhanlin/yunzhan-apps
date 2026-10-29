package executor

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestCountryDownloadCancellationObserverRequiresCompleteTimelyOriginalProof(t *testing.T) {
	for _, mode := range []string{"valid", "absent", "malformed", "late-positive"} {
		t.Run(mode, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), 650*time.Millisecond)
			defer cancel()
			var calls atomic.Int32
			download, stop := watchCountryDownloadCancellation(parent, func(ctx context.Context) (bool, error) {
				calls.Add(1)
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > countryDownloadCancelReadTimeout {
					t.Error("observer read was not bounded independently")
				}
				switch mode {
				case "valid":
					return true, nil
				case "malformed":
					return true, errors.New("incomplete original binding")
				case "late-positive":
					<-ctx.Done()
					return true, nil // A late callback cannot turn a timed-out read into proof.
				default:
					return false, nil
				}
			})
			defer stop()
			<-download.Done()
			if mode == "valid" {
				if !errors.Is(context.Cause(download), errCountryOriginalDownloadCancelled) || calls.Load() != 1 {
					t.Fatal("complete stop proof did not stop exactly its original observer", context.Cause(download), calls.Load())
				}
			} else if !errors.Is(context.Cause(download), context.DeadlineExceeded) {
				t.Fatal("unknown, malformed or late proof was labelled user cancellation", context.Cause(download))
			}
		})
	}
}

func TestCountryDownloadCancellationObserverPreservesFirstParentCause(t *testing.T) {
	parent, cancel := context.WithCancelCause(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	download, stop := watchCountryDownloadCancellation(parent, func(context.Context) (bool, error) {
		close(entered)
		<-release
		return true, nil
	})
	<-entered
	original := errors.New("original service shutdown")
	cancel(original)
	close(release)
	stop()
	if !errors.Is(context.Cause(download), original) {
		t.Fatal("late user request relabelled the original parent interruption", context.Cause(download))
	}
}

func TestCountryDownloadCancellationObserverStopIgnoresLateCallback(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	download, stop := watchCountryDownloadCancellation(parent, func(ctx context.Context) (bool, error) {
		close(entered)
		<-ctx.Done()
		close(release)
		return true, nil
	})
	<-entered
	go func() { stop(); close(returned) }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("stopping the read-only observer blocked original settlement")
	}
	<-release
	stop() // Cleanup may be called twice; neither call authorizes cancellation.
	if download.Err() != nil || context.Cause(download) != nil {
		t.Fatal("stopped observer adopted a late callback as proof")
	}
}
