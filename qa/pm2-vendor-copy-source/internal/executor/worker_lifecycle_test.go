package executor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerLifecycleCancelJoinsCleanupAndNeverRestarts(t *testing.T) {
	var g workerLifecycle
	entered, cleaning, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var starts atomic.Int32
	run := func(ctx context.Context) {
		starts.Add(1)
		close(entered)
		<-ctx.Done()
		close(cleaning)
		<-release
	}
	if !g.start(context.Background(), nil, run) || g.start(context.Background(), nil, run) {
		t.Fatal("not a single lifetime")
	}
	<-entered
	stopped := make(chan error, 1)
	go func() { stopped <- g.stop(context.Background()) }()
	<-cleaning
	select {
	case err := <-stopped:
		t.Fatal("reported drained before cleanup", err)
	default:
	}
	close(release)
	if err := <-stopped; err != nil || starts.Load() != 1 {
		t.Fatal(starts.Load(), err)
	}
	if g.start(context.Background(), nil, run) || g.stop(context.Background()) != nil {
		t.Fatal("stopped lifetime restarted or stop was not idempotent")
	}
}

func TestWorkerLifecycleStopBeforeDelayedStartAndCanceledParent(t *testing.T) {
	var g workerLifecycle
	if g.stop(context.Background()) != nil || g.start(context.Background(), func() { t.Fatal("late prepare") }) {
		t.Fatal("delayed startup escaped shutdown")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var other workerLifecycle
	if other.start(ctx, func() { t.Fatal("canceled prepare") }) || other.start(nil, nil) || other.stop(nil) == nil {
		t.Fatal("invalid lifecycle accepted")
	}
}

func TestWorkerLifecycleDeadlineReportsIncompleteThenWaitsWithoutReplay(t *testing.T) {
	var g workerLifecycle
	release, canceled := make(chan struct{}), make(chan struct{})
	g.start(context.Background(), nil, func(ctx context.Context) { <-ctx.Done(); close(canceled); <-release })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("incomplete cleanup hidden", err)
	}
	<-canceled
	if g.start(context.Background(), nil) {
		t.Fatal("timeout allowed a second worker")
	}
	close(release)
	if err := g.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerLifecycleConcurrentStartStopHasNoLateAdmission(t *testing.T) {
	for i := 0; i < 100; i++ {
		var g workerLifecycle
		var runs atomic.Int32
		var wg sync.WaitGroup
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				g.start(context.Background(), nil, func(ctx context.Context) { runs.Add(1); <-ctx.Done() })
			}()
		}
		if err := g.stop(context.Background()); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		if g.start(context.Background(), nil) || runs.Load() > 1 {
			t.Fatal("late/duplicate start", runs.Load())
		}
	}
}

func TestWorkerLifecycleServiceStopDoesNotHoldModuleMutex(t *testing.T) {
	s := &Service{}
	ready := make(chan struct{})
	s.moduleWorkers.start(context.Background(), nil, func(ctx context.Context) {
		close(ready)
		<-ctx.Done()
		s.mu.Lock()
		defer s.mu.Unlock()
	})
	<-ready
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.StopAppModuleWorker(ctx); err != nil {
		t.Fatal("cleanup deadlocked on service mutex", err)
	}
}
