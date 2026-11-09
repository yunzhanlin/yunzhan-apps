package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"local/panel/internal/runtimecatalog"
)

func memoryWaitRelease(t *testing.T) runtimecatalog.Release {
	t.Helper()
	r, ok := runtimecatalog.Find("php-8.2.35")
	if !ok {
		t.Fatal("fixed official PHP release missing")
	}
	return r
}

func TestRuntimePHPCompilerMemoryWaitRecoversOnlyAfterFreshFullAdmission(t *testing.T) {
	for _, failures := range []int{0, 1, 3, 45} {
		t.Run(fmt.Sprint(failures), func(t *testing.T) {
			calls, sleeps := 0, 0
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			deadline, _ := ctx.Deadline()
			err := awaitRuntimePHPCompilerMemory(ctx, memoryWaitRelease(t), func() error {
				calls++
				available := "1572863"
				if calls > failures {
					available = "1572864"
				}
				return runtimePHPCompilerMemoryAdmission(memoryWaitRelease(t), []byte("MemTotal: 3145728 kB\nMemAvailable: "+available+" kB\n"))
			}, func(current context.Context, interval time.Duration) error {
				sleeps++
				actual, ok := current.Deadline()
				if !ok || !actual.Equal(deadline) || interval != 2*time.Second || current.Err() != nil {
					t.Fatal("original context, deadline or fixed interval changed")
				}
				return nil
			})
			if err != nil || calls != failures+1 || sleeps != failures {
				t.Fatal("admitted without a new full successful probe", err, calls, sleeps)
			}
		})
	}
}

func TestRuntimePHPCompilerMemoryWaitFiniteCapDoesNotRelaxOneByteShortage(t *testing.T) {
	calls, sleeps := 0, 0
	err := awaitRuntimePHPCompilerMemory(context.Background(), memoryWaitRelease(t), func() error {
		calls++
		// Host counters are KiB. Crediting exactly1023 independently-owned
		// anonymous bytes leaves this actual sample ONE BYTE short.
		return runtimePHPCompilerMemoryAdmissionOwned(memoryWaitRelease(t), []byte("MemTotal: 3145728 kB\nMemAvailable: 1572863 kB\n"), 1023)
	}, func(context.Context, time.Duration) error { sleeps++; return nil })
	var shortage *runtimePHPCompilerMemoryShortage
	if err == nil || !errors.As(err, &shortage) || !strings.Contains(err.Error(), "90 秒上限") || calls != 46 || sleeps != 45 {
		t.Fatal("fixed bounded wait or original1536MiB reserve changed", err, calls, sleeps)
	}
	if runtimePHPCompilerMemoryBytes != 1<<30 || runtimePHPCompilerServiceReserve != 512<<20 || runtimePHPCompilerMemoryWait != 90*time.Second || runtimePHPCompilerMemoryPoll != 2*time.Second || runtimePHPCompilerMemoryRetries != 45 {
		t.Fatal("caller-selected or lowered admission budget")
	}
}

func TestRuntimePHPCompilerMemoryWaitRejectsUnknownFailuresWithoutWaiting(t *testing.T) {
	short := &runtimePHPCompilerMemoryShortage{"actual capacity shortage"}
	var typedNil *runtimePHPCompilerMemoryShortage
	for name, refusal := range map[string]error{
		"identity":  errRuntimePHPCompilerMemoryIdentity,
		"inventory": errRuntimePHPCompilerMemoryInventory,
		"kernel":    errRuntimePHPCompilerMemoryKernel,
		"unknown":   errors.New("unrecognized failure"),
		"wrapped":   fmt.Errorf("unknown wrapper: %w", short),
		"joined":    errors.Join(short, errRuntimePHPCompilerMemoryKernel),
		"empty":     &runtimePHPCompilerMemoryShortage{},
		"typed-nil": typedNil,
	} {
		t.Run(name, func(t *testing.T) {
			calls, sleeps := 0, 0
			err := awaitRuntimePHPCompilerMemory(context.Background(), memoryWaitRelease(t), func() error { calls++; return refusal }, func(context.Context, time.Duration) error { sleeps++; return nil })
			if err == nil || calls != 1 || sleeps != 0 {
				t.Fatal("unknown failure retried or admitted", err, calls, sleeps)
			}
		})
	}
}

func TestRuntimePHPCompilerMemoryWaitCancellationCannotBecomeSuccess(t *testing.T) {
	for _, phase := range []string{"before", "probe", "wait"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "before" {
				cancel()
			}
			calls, sleeps := 0, 0
			err := awaitRuntimePHPCompilerMemory(ctx, memoryWaitRelease(t), func() error {
				calls++
				if phase == "probe" {
					cancel()
					return nil
				}
				return &runtimePHPCompilerMemoryShortage{"short"}
			}, func(context.Context, time.Duration) error { sleeps++; cancel(); return context.Canceled })
			if !errors.Is(err, context.Canceled) || phase == "before" && calls != 0 || phase != "wait" && sleeps != 0 {
				t.Fatal("cancelled context admitted command or waited", err, calls, sleeps)
			}
		})
	}
}

func TestRuntimePHPCompilerMemoryWaitContractAndUnselectedReleases(t *testing.T) {
	r := memoryWaitRelease(t)
	probe := func() error { t.Fatal("unexpected probe"); return nil }
	wait := func(context.Context, time.Duration) error { t.Fatal("unexpected wait"); return nil }
	if !errors.Is(awaitRuntimePHPCompilerMemory(nil, r, probe, wait), errRuntimePHPCompilerMemoryWaitContract) || !errors.Is(awaitRuntimePHPCompilerMemory(context.Background(), r, nil, wait), errRuntimePHPCompilerMemoryWaitContract) || !errors.Is(awaitRuntimePHPCompilerMemory(context.Background(), r, probe, nil), errRuntimePHPCompilerMemoryWaitContract) {
		t.Fatal("missing internal context or callbacks admitted")
	}
	r.SHA256 = strings.Repeat("0", 64)
	if !errors.Is(awaitRuntimePHPCompilerMemory(context.Background(), r, probe, wait), errRuntimePHPCompilerMemoryIdentity) {
		t.Fatal("foreign official source admitted")
	}
	if err := awaitRuntimePHPCompilerMemory(context.Background(), runtimecatalog.Release{ID: "unselected-runtime"}, probe, wait); err != nil {
		t.Fatal("unselected runtime behavior changed", err)
	}
}

func TestRuntimePHPCompilerMemoryWaitDeadlineAndWaitFailureRemainFatal(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	probe := func() error { t.Fatal("expired deadline probed"); return nil }
	if !errors.Is(awaitRuntimePHPCompilerMemory(ctx, memoryWaitRelease(t), probe, nil), context.DeadlineExceeded) {
		t.Fatal("expired parent deadline was extended")
	}
	stop := errors.New("timer refused")
	err := awaitRuntimePHPCompilerMemory(context.Background(), memoryWaitRelease(t), func() error { return &runtimePHPCompilerMemoryShortage{"short"} }, func(context.Context, time.Duration) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatal("wait error became readiness", err)
	}
}
