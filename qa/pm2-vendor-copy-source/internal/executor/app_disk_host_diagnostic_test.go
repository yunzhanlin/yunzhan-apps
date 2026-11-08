package executor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDiskHostDiagnosticMasksUntrustedCauseAndPreservesIdentity(t *testing.T) {
	private := errors.New("private account=example path=/root/private token=must-not-appear")
	for _, phase := range []diskHostPhase{diskHostAuthorityContext, diskHostAuthorityIdentity, diskHostAuthorityCore, diskHostAuthorityReceipt, diskHostAuthorityInstallation, diskHostProgressEncode, diskHostProgressValidate, diskHostProgressPublish} {
		got := diskHostFailure(phase, context.Background(), private)
		if !errors.Is(got, private) || strings.Contains(got.Error(), "private") || strings.Contains(got.Error(), "/") || strings.Contains(got.Error(), "account") || strings.Contains(got.Error(), "token") {
			t.Fatal("diagnostic exposed original cause or changed its identity")
		}
		if got.Error() != "disk_host_worker_failure phase="+phase.name()+" reason=unverified" {
			t.Fatal("non-enumerated diagnostic")
		}
		if diskHostFailure(phase, context.Background(), nil) != nil {
			t.Fatal("successful guard became a diagnostic failure")
		}
	}
	bad := diskHostFailure(diskHostPhase(255), context.Background(), private)
	if bad.Error() != "disk_host_worker_failure phase=internal reason=unverified" || !errors.Is(bad, private) {
		t.Fatal("invalid phase became caller-controlled text")
	}
}

func TestDiskHostDiagnosticCapturesContextWithoutForgingCause(t *testing.T) {
	private := errors.New("original collapsed authority error")
	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	got := diskHostFailure(diskHostAuthorityCore, deadline, private)
	if got.Error() != "disk_host_worker_failure phase=authority_core reason=deadline" || !errors.Is(got, private) || errors.Is(got, context.DeadlineExceeded) {
		t.Fatal("diagnostic lost timeout or changed existing public error classification")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if got := diskHostFailure(diskHostProgressPublish, canceled, private); got.Error() != "disk_host_worker_failure phase=progress_publish reason=canceled" || !errors.Is(got, private) {
		t.Fatal("canceled context was misreported or bypassed")
	}
	for _, native := range []error{context.Canceled, context.DeadlineExceeded} {
		got := diskHostFailure(diskHostAuthorityContext, context.Background(), native)
		if !errors.Is(got, native) {
			t.Fatal("original cancel/deadline sentinel lost")
		}
	}
}

func TestDiskHostDiagnosticSurvivesOpaqueObserverWithoutLeakingWrappers(t *testing.T) {
	private := errors.New("private inner cause")
	marked := diskHostFailure(diskHostProgressValidate, context.Background(), private)
	wrapped := fmt.Errorf("private outer wrapper: %w", marked)
	root := diskHostRootDiagnostic(wrapped)
	if root.Error() != "disk_host_worker_failure phase=progress_validate reason=unverified" || !errors.Is(root, private) || !errors.Is(root, wrapped) {
		t.Fatal("Root log lost fixed original phase or original error chain")
	}
	// An outer annotation must never erase the first, precise failure phase.
	if got := diskHostFailure(diskHostAuthorityCore, context.Background(), wrapped); got != wrapped {
		t.Fatal("first precise phase was overwritten")
	}
	if diskHostRootDiagnostic(nil) != nil || diskHostRootDiagnostic(private) != private {
		t.Fatal("unrelated error semantics changed")
	}
}

func TestDiskHostDiagnosticStreamOnlyEmitsOneEnumeratedBoundedLine(t *testing.T) {
	var calls [][2]string
	w := newDiskHostDiagnosticWriter(func(phase, reason string) { calls = append(calls, [2]string{phase, reason}) })
	chunks := []string{
		"private token=never-log path=/root/private\n",
		strings.Repeat("private-oversized", 8192) + "\n",
		"disk_host_worker_failure phase=unknown reason=deadline\n",
		"disk_host_worker_failure phase=authority_core reason=private\n",
		"2026/10/15 14:00:00 disk_host_worker_fail",
		"ure phase=authority_core reason=deadline\n",
		"disk_host_worker_failure phase=progress_validate reason=unverified\n",
	}
	for _, chunk := range chunks {
		n, err := w.Write([]byte(chunk))
		if err != nil || n != len(chunk) {
			t.Fatal("diagnostic drain interrupted the original native process")
		}
	}
	if len(calls) != 1 || calls[0] != [2]string{"authority_core", "deadline"} || w.used > len(w.line) {
		t.Fatal("raw text, repeated diagnostics or an unbounded line escaped")
	}
}

func TestDiskHostDiagnosticStreamIsConcurrentAndNeverChangesCommandErrors(t *testing.T) {
	var wg sync.WaitGroup
	calls := 0
	w := newDiskHostDiagnosticWriter(func(phase, reason string) {
		calls++
		if phase != "progress_publish" || reason != "unverified" {
			t.Error("non-enumerated native diagnostic")
		}
	})
	for range 16 {
		wg.Go(func() {
			line := []byte("disk_host_worker_failure phase=progress_publish reason=unverified\n")
			if n, err := w.Write(line); n != len(line) || err != nil {
				t.Error("diagnostic writer changed command semantics")
			}
		})
	}
	wg.Wait()
	if calls != 1 {
		t.Fatal("more than one Root log line emitted")
	}
	if n, err := newDiskHostDiagnosticWriter(nil).Write([]byte("discard\n")); n != 8 || err != nil {
		t.Fatal("nil optional sink blocked original process")
	}
}

func TestDiskHostDiagnosticCommandChild(t *testing.T) {
	if os.Getenv("PANEL_HOST_DIAGNOSTIC_CHILD24BFQM") != "1" {
		return
	}
	fmt.Fprintln(os.Stderr, "private token=must-not-escape path=/root/private")
	ctx, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	cause := errors.New("private collapsed SQL error")
	err := diskHostFailure(diskHostAuthorityCore, ctx, cause)
	log.Print(diskHostRootDiagnostic(fmt.Errorf("private wrapper: %w", err)))
	os.Exit(19)
}

func TestDiskHostDiagnosticActualChildStderrKeepsNativeExitAndNoRawText(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestDiskHostDiagnosticCommandChild$")
	cmd.Env = append(os.Environ(), "PANEL_HOST_DIAGNOSTIC_CHILD24BFQM=1")
	var seen [][2]string
	cmd.Stderr = newDiskHostDiagnosticWriter(func(phase, reason string) { seen = append(seen, [2]string{phase, reason}) })
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 19 || len(seen) != 1 || seen[0] != [2]string{"authority_core", "deadline"} {
		t.Fatal("real child stderr capture changed original exit or lost fixed diagnostic")
	}
}

func TestDiskHostDiagnosticBlockedLoggerCannotHoldOriginalChildExit(t *testing.T) {
	entered, blocked := make(chan struct{}), make(chan struct{})
	var first sync.Once
	box := newDiskHostDiagnosticMailbox(func(diskHostDiagnosticEvent) { first.Do(func() { close(entered); <-blocked }) })
	defer func() { close(blocked); close(box.queue) }()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDiskHostDiagnosticCommandChild$")
	cmd.Env = append(os.Environ(), "PANEL_HOST_DIAGNOSTIC_CHILD24BFQM=1")
	cmd.Stderr = newDiskHostCommandDiagnosticWriter(strings.Repeat("5", 32), strings.Repeat("7", 64), box)
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("original child diagnostic never reached blocked sink")
	}
	select {
	case err := <-done:
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 19 {
			t.Fatal("original child native exit changed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Root logging held original command Wait/launch lease")
	}
	// The first sink is deliberately still blocked; diagnostic pressure must
	// never allocate a goroutine per job, grow the queue or block producers.
	filled := make(chan struct{})
	go func() {
		for range 10000 {
			box.offer(diskHostDiagnosticEvent{jobID: strings.Repeat("5", 32), requestSHA: strings.Repeat("7", 64), phase: "authority_core", reason: "deadline"})
		}
		close(filled)
	}()
	select {
	case <-filled:
		if len(box.queue) != 128 || cap(box.queue) != 128 {
			t.Fatal("diagnostic queue is not fixed at128")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("full diagnostic queue blocked original producer")
	}
}

func TestDiskHostDiagnosticMailboxRejectsUnboundOrPrivateLogFields(t *testing.T) {
	seen := make(chan diskHostDiagnosticEvent, 16)
	box := newDiskHostDiagnosticMailbox(func(e diskHostDiagnosticEvent) { seen <- e })
	defer close(box.queue)
	for _, e := range []diskHostDiagnosticEvent{
		{jobID: "/private", requestSHA: strings.Repeat("7", 64), phase: "authority_core", reason: "deadline"},
		{jobID: strings.Repeat("5", 32), requestSHA: "private token", phase: "authority_core", reason: "deadline"},
		{jobID: strings.Repeat("5", 32), requestSHA: strings.Repeat("7", 64), phase: "/private", reason: "deadline"},
		{jobID: strings.Repeat("5", 32), requestSHA: strings.Repeat("7", 64), phase: "authority_core", reason: "private"},
	} {
		box.offer(e)
	}
	valid := diskHostDiagnosticEvent{jobID: strings.Repeat("5", 32), requestSHA: strings.Repeat("7", 64), phase: "authority_core", reason: "deadline"}
	box.offer(valid)
	select {
	case e := <-seen:
		if e != valid || len(seen) != 0 {
			t.Fatal("noncanonical identity or raw private text reached diagnostic sink")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("valid bound diagnostic was unavailable")
	}
	if newDiskHostDiagnosticMailbox(nil).offer(valid) {
		t.Fatal("disabled optional logger accepted an event")
	}
}
