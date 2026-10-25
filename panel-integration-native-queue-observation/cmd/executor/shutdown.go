//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// Stay below the original systemd stop limit. Do not extend any application
// read/commit budgets. Serve returning ErrServerClosed is NOT proof that active
// handlers or module SQLite transactions have finished.
const executorDrainTimeout = 30 * time.Second

func serveUntilStopped(ctx context.Context, cancelStartup context.CancelFunc, server *http.Server, listener net.Listener, startupDone <-chan struct{}, stopWorkers func(context.Context) error) error {
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	var serveErr error
	serveFinished := false
	select {
	case <-ctx.Done():
	case serveErr = <-served:
		serveFinished = true
	}
	cancelStartup()
	drain, cancel := context.WithTimeout(context.Background(), executorDrainTimeout)
	defer cancel()
	// Cancel the worker group even on an unexpected listener failure. Its own
	// cancellation is independent of the HTTP handler's request lifetime.
	workers := make(chan error, 1)
	go func() { workers <- stopWorkers(drain) }()
	httpErr := server.Shutdown(drain)
	if httpErr != nil {
		_ = server.Close()
	}
	var startupErr error
	select {
	case <-startupDone:
	case <-drain.Done():
		startupErr = drain.Err()
	}
	workerErr := <-workers
	if !serveFinished {
		serveErr = <-served
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	return errors.Join(serveErr, httpErr, startupErr, workerErr)
}
