//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestExecutorShutdownWaitsForHTTPAndWorkerCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entered, cleaned, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server := &http.Server{BaseContext: func(net.Listener) context.Context { return ctx }, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		<-release
		close(cleaned)
	})}
	startup := make(chan struct{})
	close(startup)
	workerCanceled, workerRelease := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveUntilStopped(ctx, cancel, server, listener, startup, func(ctx context.Context) error { close(workerCanceled); <-workerRelease; return nil })
	}()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		client := &http.Client{Timeout: 5 * time.Second}
		response, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not enter")
	}
	cancel()
	<-workerCanceled
	select {
	case err := <-done:
		t.Fatal("Serve exit incorrectly counted as drain", err)
	default:
	}
	close(release)
	<-cleaned
	select {
	case err := <-done:
		t.Fatal("HTTP exit incorrectly counted as worker drain", err)
	default:
	}
	close(workerRelease)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-requestDone
}

func TestExecutorUnexpectedListenerFailureCancelsDelayedStartupAndPreservesFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	startup := make(chan struct{})
	go func() { <-ctx.Done(); close(startup) }()
	called := false
	err = serveUntilStopped(ctx, cancel, &http.Server{}, listener, startup, func(context.Context) error { called = true; return errors.New("worker drain refused") })
	if err == nil || !called || ctx.Err() == nil {
		t.Fatal("unexpected server/worker failure hidden or startup left alive", called, err)
	}
}
