package executor

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"local/panel/internal/diskjob"
)

// Only fixed enums can reach the Root-only worker log. Never log the wrapped
// error text: SQL/OS errors may contain private paths or account information.
// The original error chain is retained unchanged for cancellation, public
// result classification and fail-closed authority decisions.
type diskHostPhase uint8

const (
	diskHostAuthorityContext diskHostPhase = iota + 1
	diskHostAuthorityIdentity
	diskHostAuthorityCore
	diskHostAuthorityReceipt
	diskHostAuthorityInstallation
	diskHostProgressEncode
	diskHostProgressValidate
	diskHostProgressPublish
)

func (p diskHostPhase) name() string {
	switch p {
	case diskHostAuthorityContext:
		return "authority_context"
	case diskHostAuthorityIdentity:
		return "authority_identity"
	case diskHostAuthorityCore:
		return "authority_core"
	case diskHostAuthorityReceipt:
		return "authority_receipt"
	case diskHostAuthorityInstallation:
		return "authority_installation"
	case diskHostProgressEncode:
		return "progress_encode"
	case diskHostProgressValidate:
		return "progress_validate"
	case diskHostProgressPublish:
		return "progress_publish"
	default:
		return "internal"
	}
}

type diskHostReason uint8

func (r diskHostReason) name() string {
	switch r {
	case 1:
		return "deadline"
	case 2:
		return "canceled"
	default:
		return "unverified"
	}
}

type diskHostPhaseError struct {
	phase  diskHostPhase
	reason diskHostReason
	cause  error
}

func (e *diskHostPhaseError) Error() string {
	return "disk_host_worker_failure phase=" + e.phase.name() + " reason=" + e.reason.name()
}
func (e *diskHostPhaseError) Unwrap() error { return e.cause }

func diskHostFailure(phase diskHostPhase, ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var first *diskHostPhaseError
	if errors.As(err, &first) {
		return err
	}
	var contextErr error
	if ctx != nil {
		contextErr = ctx.Err()
	}
	reason := diskHostReason(0)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(contextErr, context.DeadlineExceeded) {
		reason = 1
	} else if errors.Is(err, context.Canceled) || errors.Is(contextErr, context.Canceled) {
		reason = 2
	}
	return &diskHostPhaseError{phase: phase, reason: reason, cause: err}
}

// scanner's opaque observer error intentionally hides its cause. Expose only
// the first fixed phase at the Root entry point, not arbitrary wrapper text.
func diskHostRootDiagnostic(err error) error {
	var first *diskHostPhaseError
	if err != nil && errors.As(err, &first) {
		return &diskHostPhaseError{phase: first.phase, reason: first.reason, cause: err}
	}
	return err
}

// exec.Cmd otherwise discards a scope child's stderr. Drain it without storing
// arbitrary text or allowing diagnostics to interrupt the original command.
// Only one fixed enum pair, with a 2KiB line bound, can reach the Root logger.
type diskHostDiagnosticWriter struct {
	mu       sync.Mutex
	line     [2048]byte
	used     int
	discard  bool
	reported bool
	emit     func(string, string)
}

func newDiskHostDiagnosticWriter(emit func(string, string)) *diskHostDiagnosticWriter {
	return &diskHostDiagnosticWriter{emit: emit}
}

func diskHostDiagnosticLine(line []byte) (diskHostPhase, diskHostReason, bool) {
	marker := []byte("disk_host_worker_failure phase=")
	start := bytes.Index(line, marker)
	if start < 0 {
		return 0, 0, false
	}
	for phase := diskHostAuthorityContext; phase <= diskHostProgressPublish; phase++ {
		for reason := diskHostReason(0); reason <= 2; reason++ {
			fixed := (&diskHostPhaseError{phase: phase, reason: reason}).Error()
			if bytes.Equal(line[start:], []byte(fixed)) {
				return phase, reason, true
			}
		}
	}
	return 0, 0, false
}

func (w *diskHostDiagnosticWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	if w.reported || w.emit == nil {
		w.mu.Unlock()
		return len(p), nil
	}
	var phaseName, reasonName string
	for _, c := range p {
		if c == '\n' {
			if !w.discard {
				if phase, reason, ok := diskHostDiagnosticLine(w.line[:w.used]); ok {
					phaseName, reasonName = phase.name(), reason.name()
					w.reported = true
					clear(w.line[:])
					w.used = 0
					break
				}
			}
			w.used, w.discard = 0, false
		} else if !w.discard {
			if w.used == len(w.line) {
				w.used, w.discard = 0, true
			} else {
				w.line[w.used] = c
				w.used++
			}
		}
	}
	w.mu.Unlock()
	if phaseName != "" {
		w.emit(phaseName, reasonName)
	}
	return len(p), nil
}

type diskHostDiagnosticEvent struct {
	jobID, requestSHA, phase, reason string
}

// One process-wide bounded mailbox, not a goroutine per job. A slow/full
// management log must never hold cmd.Wait, the launch lease or new admission.
// Dropped diagnostics remain unavailable; they never prove a job outcome.
type diskHostDiagnosticMailbox struct {
	queue chan diskHostDiagnosticEvent
	once  sync.Once
	emit  func(diskHostDiagnosticEvent)
}

func newDiskHostDiagnosticMailbox(emit func(diskHostDiagnosticEvent)) *diskHostDiagnosticMailbox {
	return &diskHostDiagnosticMailbox{queue: make(chan diskHostDiagnosticEvent, 128), emit: emit}
}

func (m *diskHostDiagnosticMailbox) offer(e diskHostDiagnosticEvent) bool {
	if m == nil || m.emit == nil || !diskjob.ValidID(e.jobID) || !diskjob.ValidSHA(e.requestSHA) {
		return false
	}
	knownPhase, knownReason := false, false
	for phase := diskHostAuthorityContext; phase <= diskHostProgressPublish; phase++ {
		knownPhase = knownPhase || e.phase == phase.name()
	}
	for reason := diskHostReason(0); reason <= 2; reason++ {
		knownReason = knownReason || e.reason == reason.name()
	}
	if !knownPhase || !knownReason {
		return false
	}
	m.once.Do(func() {
		go func() {
			for event := range m.queue {
				m.emit(event)
			}
		}()
	})
	select {
	case m.queue <- e:
		return true
	default:
		return false
	}
}

func newDiskHostCommandDiagnosticWriter(jobID, requestSHA string, mailbox *diskHostDiagnosticMailbox) *diskHostDiagnosticWriter {
	return newDiskHostDiagnosticWriter(func(phase, reason string) {
		mailbox.offer(diskHostDiagnosticEvent{jobID: jobID, requestSHA: requestSHA, phase: phase, reason: reason})
	})
}
