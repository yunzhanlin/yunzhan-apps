//go:build linux

package executor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWAFNativeBusyRetryOnlyBeforeMutation(t *testing.T) {
	calls := 0
	if err := wafNativeRetryLockBusy(context.Background(), func() error {
		calls++
		if calls == 1 {
			return errWAFConfigurationBusy
		}
		return nil
	}); err != nil || calls != 2 {
		t.Fatal("typed pre-mutation contention not retried", calls, err)
	}
	for _, failure := range []error{errors.New("WAF 正在变更或恢复，请稍后重试"), errors.New("reload failed after commit"), errors.New("unsafe owner or evidence")} {
		calls = 0
		if err := wafNativeRetryLockBusy(context.Background(), func() error { calls++; return failure }); err != failure || calls != 1 {
			t.Fatal("non-lock failure retried", calls, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	calls = 0
	if err := wafNativeRetryLockBusy(ctx, func() error { calls++; return errWAFConfigurationBusy }); !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatal("cancellation did not bound contention", calls, err)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := wafNativeRetryLockBusy(canceled, func() error { t.Fatal("operation called after cancellation"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
