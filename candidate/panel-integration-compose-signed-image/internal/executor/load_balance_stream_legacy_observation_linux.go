//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"time"
)

// Only classify the ORIGINAL complete read's closed, typed observation. This
// grants no exemption: the same full guard must subsequently return nil. Keep
// this eligibility identical to the normal installer's bounded periodic MySQL
// recovery observation; failed, unknown, unrelated and legacy text refuse.
func loadBalanceStreamPeriodicNativeRead(err error) bool {
	var original *programQueueNativeRefusal
	if err == nil || !errors.As(err, &original) || original == nil || ProgramUpgradeQueueFailureText(err) == err.Error() {
		return false
	}
	o := original.observation
	if o.Unit != "panel-mysql-overwrite-recovery.service" {
		return false
	}
	if o.Kind == "native-program-job-refusal-v1" {
		return o.JobType == "start" && (o.JobState == "waiting" || o.JobState == "running")
	}
	if o.Kind != "native-program-unit-refusal-v1" || o.LoadState != "loaded" {
		return false
	}
	switch o.ActiveState + "/" + o.SubState {
	case "activating/condition", "activating/start-pre", "activating/start", "activating/start-post", "active/running", "deactivating/stop-post":
		return true
	}
	return false
}

// The cache worker keeps the shared instance lease for its entire verification.
// Wait before taking runtime or mutation leases. Once acquired, the same inode
// excludes another cache verification across parent and account-child checks.
func holdLoadBalanceStreamGeodataFence(ctx context.Context, current func(context.Context) error) (*os.File, error) {
	bounded, cancel := context.WithTimeout(ctx, 310*time.Second)
	defer cancel()
	return waitLoadBalanceStreamGeodataFence(bounded, current, func() (*os.File, error) {
		return statisticsGeoInstanceLease(true)
	}, func(ctx context.Context) error { return pauseLoadBalanceStreamQueue(ctx, time.Second) })
}

func waitLoadBalanceStreamGeodataFence(ctx context.Context, current func(context.Context) error, acquire func() (*os.File, error), pause func(context.Context) error) (*os.File, error) {
	for {
		if ctx.Err() != nil || current(ctx) != nil {
			return nil, errLoadBalanceStreamInstallationGate
		}
		lease, err := acquire()
		if err == nil {
			if ctx.Err() != nil || current(ctx) != nil {
				lease.Close()
				return nil, errLoadBalanceStreamInstallationGate
			}
			return lease, nil
		}
		if !errors.Is(err, errStatisticsGeoInstanceBusy) {
			return nil, err
		}
		if pause(ctx) != nil {
			if ctx.Err() != nil {
				return nil, errStatisticsGeoInstanceBusy
			}
			return nil, errLoadBalanceStreamInstallationGate
		}
	}
}

func streamInstallGeodataFenceCurrent(lease *os.File) bool {
	if lease == nil {
		return false
	}
	opened, openErr := lease.Stat()
	named, nameErr := os.Lstat(statisticsGeoInstanceLock)
	return openErr == nil && nameErr == nil && moduleRecordInfo(opened, false, false) &&
		opened.Size() == 0 && geoStoreStableInfo(opened, named)
}

func pauseLoadBalanceStreamQueue(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func observeLoadBalanceStreamLegacyQueues(ctx context.Context, current func(context.Context) error) error {
	return loadBalanceStreamLegacyQueueObservation(ctx, current, checkLegacyProgramUpgradeQueues, func(ctx context.Context) error {
		return pauseLoadBalanceStreamQueue(ctx, 250*time.Millisecond)
	})
}

// The private callback seam tests observation and revocation only. Production
// above always executes the original full guard and fixed cancellable pause.
// No read, wait or cached error grants mutation, starts a job or repairs state.
func loadBalanceStreamLegacyQueueObservation(ctx context.Context, current func(context.Context) error, read func() error, pause func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || current == nil || read == nil || pause == nil {
		return errLoadBalanceStreamInstallationGate
	}
	for observations := 0; ; observations++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := read()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil || observations >= 2 || !loadBalanceStreamPeriodicNativeRead(err) {
			return err
		}
		// Callers already validate their original authority before the initial
		// guard and after full queue verification. A wait additionally requires
		// that exact live grant/leases/kernel state on BOTH sides of the pause.
		if current(ctx) != nil {
			return errLoadBalanceStreamInstallationGate
		}
		if err := pause(ctx); err != nil {
			return err
		}
		if ctx.Err() != nil || current(ctx) != nil {
			return errLoadBalanceStreamInstallationGate
		}
	}
}
