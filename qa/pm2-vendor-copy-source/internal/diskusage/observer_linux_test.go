//go:build linux

package diskusage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostScanNativeObservedProgressFlushedCopiedAndFailureStops(t *testing.T) {
	base := nativeHostFixture(t)
	for n := range 130 {
		nativeWrite(t, filepath.Join(base, fmt.Sprintf("entry-%03d", n)), nil)
	}
	i, m, relative := nativeMountFor(t, base)
	s, err := i.OpenMount(context.Background(), m.ID, m.BindingSHA)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	index, _ := nativeLedgerAt(t, nativeHostFixture(t), 256)
	observed := 0
	r, err := ScanObserved(context.Background(), s, relative, index, DefaultScanBudget(), func(p ScanReport) error {
		observed++
		if !p.IndexFlushed || p.Complete || p.State != "running" || p.FinishedAt != "" {
			t.Fatal("unflushed/terminal progress misrepresented")
		}
		if len(p.TopFiles) > 0 {
			p.TopFiles[0].Path = "/must-not-mutate-original-report"
		}
		return nil
	})
	if err != nil || !r.Complete || !r.IndexFlushed || observed < 2 || len(r.TopFiles) != 100 || strings.Contains(fmt.Sprint(r.TopFiles), "must-not-mutate") {
		t.Fatalf("native observed scan failed/aliased: %+v %d %v", r, observed, err)
	}
	failedIndex, _ := nativeLedgerAt(t, nativeHostFixture(t), 256)
	privateFailure := errors.New("test-only-private-progress-storage-details")
	r, err = ScanObserved(context.Background(), s, relative, failedIndex, DefaultScanBudget(), func(ScanReport) error { return privateFailure })
	if !errors.Is(err, ErrObserver) || !errors.Is(err, privateFailure) || strings.Contains(err.Error(), "private-progress-storage") || r.Complete || r.State != "failed" || r.EntriesRead != 0 {
		t.Fatal("observer failure leaked, continued enumeration, or became complete", r, err)
	}
}

func TestHostScanNativeObserverCancellationDuringOriginalScan(t *testing.T) {
	base := nativeHostFixture(t)
	for n := range 8193 {
		nativeWrite(t, filepath.Join(base, fmt.Sprintf("entry-%04d", n)), nil)
	}
	i, m, relative := nativeMountFor(t, base)
	s, err := i.OpenMount(context.Background(), m.ID, m.BindingSHA)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	index, _ := nativeLedgerAt(t, nativeHostFixture(t), 512)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := false
	r, err := ScanObserved(ctx, s, relative, index, DefaultScanBudget(), func(progress ScanReport) error {
		if progress.EntriesRead > 0 {
			seen = true
			cancel()
			return context.Canceled
		}
		return nil
	})
	if !seen || !errors.Is(err, context.Canceled) || r.Complete || r.State != "canceled" || r.EntriesRead == 0 || r.EntriesRead >= 8193 {
		t.Fatal("actual original scan cancellation not observed", r, err)
	}
	// This is actual metadata/native callback cancellation, NOT a browser,
	// Core/Root job, live role revocation or cgroup SIGTERM acceptance claim.
}
