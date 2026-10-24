package executor

import (
	"context"
	"errors"
	"sync"
)

// A service owns each group for its entire lifetime. Cancellation is not a
// retry/recovery authority: stopped groups never start again, even if startup
// was still waiting for the program-upgrade guard when shutdown began.
type workerLifecycle struct {
	mu      sync.Mutex
	started bool
	stopped bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func (g *workerLifecycle) start(parent context.Context, prepare func(), workers ...func(context.Context)) bool {
	if parent == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.started || g.stopped || parent.Err() != nil {
		return false
	}
	ctx, cancel := context.WithCancel(parent)
	g.started, g.cancel, g.done = true, cancel, make(chan struct{})
	if prepare != nil {
		prepare()
	}
	var wg sync.WaitGroup
	wg.Add(len(workers))
	for _, run := range workers {
		go func() {
			defer wg.Done()
			run(ctx)
		}()
	}
	go func() {
		wg.Wait()
		close(g.done)
	}()
	return true
}

func (g *workerLifecycle) stop(ctx context.Context) error {
	if ctx == nil {
		return errors.New("worker shutdown requires a context")
	}
	g.mu.Lock()
	g.stopped = true
	if g.cancel != nil {
		g.cancel()
	}
	done := g.done
	g.mu.Unlock()
	if done == nil {
		return nil
	}
	// A completed drain wins even when the caller's deadline has just elapsed.
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// No service mutex is held while waiting: workers must be able to finish their
// current transaction, close SQLite and release cross-process locks.
func (s *Service) StopAppModuleWorker(ctx context.Context) error {
	return s.moduleWorkers.stop(ctx)
}
