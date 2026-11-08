//go:build linux

package diskjob

import (
	"context"
	"errors"
	"os"
	"time"
)

// WaitForAdmissionIdle only observes the original launch/run leases. It never
// creates locks, signals a process, seals admission or retries an uncertain
// write. The caller still has to perform the existing closure checks once.
func (j *Journal) WaitForAdmissionIdle(ctx context.Context, stillCurrent func() bool) error {
	if ctx == nil || stillCurrent == nil {
		return ErrJournal
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !j.current() || !stillCurrent() {
			return ErrJournal
		}
		free := true
		for _, name := range []string{"launch.lock", "run.lock"} {
			available, err := j.leaseFree(name)
			if errors.Is(err, os.ErrNotExist) {
				// Preserve the existing not-yet-launched recovery path. Only
				// SealClosure may create its original admission locks.
				continue
			}
			if err != nil {
				return err
			}
			free = free && available
		}
		if free {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !j.current() || !stillCurrent() {
				return ErrJournal
			}
			return nil
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
