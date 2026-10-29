package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"time"
)

var errCountryOriginalDownloadCancelled = errors.New(core.WAFCountryDownloadCancelledMessage)

const countryDownloadCancelInterval = 250 * time.Millisecond
const countryDownloadCancelReadTimeout = 200 * time.Millisecond

// Internal callback seam only. One fixed original worker reads a bounded Core
// stop proof; no PID, signal, command, file, source or verification flag can be
// supplied over HTTP. Malformed/unknown proof never cancels another task.
func watchCountryDownloadCancellation(parent context.Context, check func(context.Context) (bool, error)) (context.Context, func()) {
	download, cancel := context.WithCancelCause(parent)
	poll, stop := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-poll.Done():
				return
			case <-timer.C:
			}
			if poll.Err() != nil || download.Err() != nil {
				return
			}
			ctx, finish := context.WithTimeout(poll, countryDownloadCancelReadTimeout)
			requested, err := check(ctx)
			timely := ctx.Err() == nil
			finish()
			if err == nil && requested && timely && poll.Err() == nil && download.Err() == nil {
				cancel(errCountryOriginalDownloadCancelled)
				return
			}
			timer.Reset(countryDownloadCancelInterval)
		}
	}()
	return download, func() {
		stop()
		select {
		case <-done:
		case <-time.After(countryDownloadCancelReadTimeout + 50*time.Millisecond):
			// The timed-out operation is read-only and its context is cancelled.
			// Never block original filesystem settlement on a stuck observer.
		}
	}
}
