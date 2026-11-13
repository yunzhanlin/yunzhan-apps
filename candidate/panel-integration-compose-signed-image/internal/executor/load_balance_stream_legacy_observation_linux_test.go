//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func streamLegacyPeriodicBusy() *programQueueNativeRefusal {
	return &programQueueNativeRefusal{
		message:     "native program operation is active, failed or transitional; upgrade refused",
		observation: programQueueNativeObservation{Format: 1, Kind: "native-program-unit-refusal-v1", Unit: "panel-mysql-overwrite-recovery.service", LoadState: "loaded", ActiveState: "activating", SubState: "condition", InventorySHA: strings.Repeat("a", 64)},
	}
}

func TestLoadBalanceStreamLegacyObservationNeedsAnActualLaterFullGuardSuccess(t *testing.T) {
	checks, waits, authorizations := 0, 0, 0
	err := loadBalanceStreamLegacyQueueObservation(t.Context(), func(context.Context) error {
		authorizations++
		return nil
	}, func() error {
		checks++
		if checks == 1 {
			return streamLegacyPeriodicBusy()
		}
		return nil
	}, func(context.Context) error {
		waits++
		return nil
	})
	if err != nil || checks != 2 || waits != 1 || authorizations != 2 {
		t.Fatal("a timer observation must be followed by a complete guard success and live authorization on both sides", err, checks, waits, authorizations)
	}
	checks, waits = 0, 0
	original := streamLegacyPeriodicBusy()
	err = loadBalanceStreamLegacyQueueObservation(t.Context(), func(context.Context) error { return nil }, func() error {
		checks++
		return original
	}, func(context.Context) error { waits++; return nil })
	if err != original || checks != 3 || waits != 2 {
		t.Fatal("a still active timer must retain its original refusal after two bounded further reads", err, checks, waits)
	}
}

func TestLoadBalanceStreamLegacyObservationDoesNotReobserveOtherFailures(t *testing.T) {
	for _, fault := range []string{"foreign-unit", "failed", "unknown", "masked", "bad-digest", "bad-format", "legacy-message", "wrapped-message", "ordinary-error", "wrong-job-operation", "unknown-job-state"} {
		t.Run(fault, func(t *testing.T) {
			refusal := streamLegacyPeriodicBusy()
			var original error = refusal
			switch fault {
			case "foreign-unit":
				refusal.observation.Unit = "panel-compose-recovery.service"
			case "failed":
				refusal.observation.ActiveState, refusal.observation.SubState = "failed", "failed"
			case "unknown":
				refusal.observation.ActiveState = "unknown"
			case "masked":
				refusal.observation.LoadState = "masked"
			case "bad-digest":
				refusal.observation.InventorySHA = ""
			case "bad-format":
				refusal.observation.Format = 2
			case "legacy-message":
				refusal.message = "legacy refusal without a closed observation"
			case "wrapped-message":
				original = fmt.Errorf("other path: %w", refusal)
			case "ordinary-error":
				original = errors.New(refusal.Error())
			case "wrong-job-operation", "unknown-job-state":
				refusal.message = "native program operation is queued; upgrade refused"
				refusal.observation.Kind = "native-program-job-refusal-v1"
				refusal.observation.LoadState, refusal.observation.ActiveState, refusal.observation.SubState = "", "", ""
				refusal.observation.JobID, refusal.observation.JobType, refusal.observation.JobState = "42", "stop", "running"
				if fault == "unknown-job-state" {
					refusal.observation.JobType, refusal.observation.JobState = "start", "unknown"
				}
			}
			checks := 0
			err := loadBalanceStreamLegacyQueueObservation(t.Context(), func(context.Context) error { t.Fatal("no wait can borrow authority for this refusal"); return nil }, func() error { checks++; return original }, func(context.Context) error { t.Fatal("unrelated failure was waited away"); return nil })
			if err != original || checks != 1 {
				t.Fatal("original refusal was discarded or reobserved", err, checks)
			}
		})
	}
}

func TestLoadBalanceStreamLegacyObservationRejectsRevocationBeforeAndAfterWait(t *testing.T) {
	for _, revokeAt := range []int{1, 2} {
		t.Run(fmt.Sprint(revokeAt), func(t *testing.T) {
			checks, current, waits := 0, 0, 0
			err := loadBalanceStreamLegacyQueueObservation(t.Context(), func(context.Context) error {
				current++
				if current == revokeAt {
					return errors.New("original grant revoked")
				}
				return nil
			}, func() error { checks++; return streamLegacyPeriodicBusy() }, func(context.Context) error { waits++; return nil })
			if !errors.Is(err, errLoadBalanceStreamInstallationGate) || checks != 1 || current != revokeAt || waits != revokeAt-1 {
				t.Fatal("stale authority caused another native read", err, checks, current, waits)
			}
		})
	}
}

func TestLoadBalanceStreamLegacyObservationKeepsOriginalContextAndFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	checks := 0
	err := loadBalanceStreamLegacyQueueObservation(ctx, func(context.Context) error { return nil }, func() error { checks++; return streamLegacyPeriodicBusy() }, func(same context.Context) error {
		if same != ctx {
			t.Fatal("observation replaced or renewed original deadline")
		}
		cancel()
		return same.Err()
	})
	if !errors.Is(err, context.Canceled) || checks != 1 {
		t.Fatal("canceled observation performed another full read", err, checks)
	}
	for _, absent := range []context.Context{nil, ctx} {
		if loadBalanceStreamLegacyQueueObservation(absent, func(context.Context) error { return nil }, func() error { t.Fatal("missing/canceled context read native state"); return nil }, func(context.Context) error { t.Fatal("missing/canceled context waited"); return nil }) == nil {
			t.Fatal("missing/canceled original context accepted")
		}
	}
	refusal := streamLegacyPeriodicBusy()
	refusal.message = "native program operation is queued; upgrade refused"
	refusal.observation.Kind = "native-program-job-refusal-v1"
	refusal.observation.LoadState, refusal.observation.ActiveState, refusal.observation.SubState = "", "", ""
	refusal.observation.JobID, refusal.observation.JobType, refusal.observation.JobState = "42", "start", "waiting"
	if !loadBalanceStreamPeriodicNativeRead(refusal) {
		t.Fatal("original closed pending periodic start cannot be observed again")
	}
}

func TestLoadBalanceStreamGeodataFenceWaitsForOriginalSharedReader(t *testing.T) {
	fixture := geoStoreRootFixture(t)
	path := filepath.Join(filepath.Dir(fixture.store.base), "geodata.lock")
	shared, err := statisticsGeoInstanceLeaseAt(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	checks, pauses := 0, 0
	lease, err := waitLoadBalanceStreamGeodataFence(t.Context(), func(context.Context) error {
		checks++
		return nil
	}, func() (*os.File, error) {
		return statisticsGeoInstanceLeaseOpen(path, true, false)
	}, func(context.Context) error {
		pauses++
		return shared.Close()
	})
	if err != nil || lease == nil || checks != 3 || pauses != 1 {
		t.Fatal("exclusive acquisition did not wait for the original reader", checks, pauses, err)
	}
	defer lease.Close()
	if other, err := statisticsGeoInstanceLeaseOpen(path, false, false); !errors.Is(err, errStatisticsGeoInstanceBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("new verification entered while the installation fence was held", err)
	}
}

func TestLoadBalanceStreamGeodataFenceStopsOnRevocationOrInvalidLock(t *testing.T) {
	for _, scenario := range []string{"revoked", "invalid-lock", "deadline"} {
		t.Run(scenario, func(t *testing.T) {
			calls, pauses := 0, 0
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			lease, err := waitLoadBalanceStreamGeodataFence(ctx, func(context.Context) error {
				if scenario == "revoked" && calls > 0 {
					return errors.New("revoked")
				}
				return nil
			}, func() (*os.File, error) {
				calls++
				if scenario == "invalid-lock" {
					return nil, os.ErrPermission
				}
				return nil, errStatisticsGeoInstanceBusy
			}, func(context.Context) error {
				pauses++
				if scenario == "deadline" {
					cancel()
					return ctx.Err()
				}
				return nil
			})
			if lease != nil || err == nil || calls != 1 || scenario == "invalid-lock" && pauses != 0 ||
				scenario == "deadline" && !errors.Is(err, errStatisticsGeoInstanceBusy) {
				t.Fatal("unsafe wait or failure result", calls, pauses, err)
			}
		})
	}
}
