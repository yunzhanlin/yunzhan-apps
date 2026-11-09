//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

const countryFixtureBoot = "01234567-89ab-cdef-0123-456789abcdef"

func countryTaskPreparedFixture(t *testing.T) (countryTaskStore, countryTaskRequest, *statisticsGeoDirectory, *statisticsGeoDirectory) {
	t.Helper()
	s, request, raw := countryTaskFixture(t)
	if _, _, _, err := s.prepare(context.Background(), request, raw); err != nil {
		t.Fatal(err)
	}
	base, err := s.open(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })
	_, _, dir, err := s.read(base, request.JobID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	return s, request, base, dir
}
func countryTaskSyntheticStarted(request countryTaskRequest) countryTaskStarted {
	return countryTaskStarted{1, request.JobID, countryTaskRequestDigest(request), countryFixtureBoot, 123, "456", core.Hash("explicit synthetic worker identity; not installed executor")}
}

func TestCountryTaskDispatchLostAcknowledgementCannotAuthorizeAnotherStart(t *testing.T) {
	s, request, _, dir := countryTaskPreparedFixture(t)
	s.fault = func(point string) error {
		if point == "after-dispatch-write" {
			return errors.New("lost original systemd dispatch acknowledgement")
		}
		return nil
	}
	if _, fresh, err := s.markDispatch(context.Background(), request, countryFixtureBoot); err == nil || fresh {
		t.Fatal("injected unknown acknowledgement disappeared", fresh, err)
	}
	before, err := dir.Lstat("dispatch.json")
	if err != nil {
		t.Fatal(err)
	}
	s.fault = nil
	dispatch, fresh, err := s.markDispatch(context.Background(), request, countryFixtureBoot)
	if err != nil || fresh || dispatch.RequestSHA != countryTaskRequestDigest(request) {
		t.Fatal("original dispatch replayed", dispatch, fresh, err)
	}
	after, err := dir.Lstat("dispatch.json")
	if err != nil || !geoStoreStableInfo(before, after) {
		t.Fatal("observation rewrote original dispatch", err)
	}
	changed := request
	changed.ActorID = core.ID()
	if _, fresh, err := s.markDispatch(context.Background(), changed, countryFixtureBoot); err == nil || fresh {
		t.Fatal("another actor adopted original dispatch")
	}
	for _, name := range []string{"started.json", "result.json"} {
		if _, err := dir.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("dispatch metadata ran a worker", name, err)
		}
	}
}

func TestCountryTaskWorkerStartOnceBindsOriginalBootFullRequestAndNamedExclusiveLock(t *testing.T) {
	s, request, _, dir := countryTaskPreparedFixture(t)
	if _, fresh, err := s.markDispatch(context.Background(), request, countryFixtureBoot); err != nil || !fresh {
		t.Fatal(fresh, err)
	}
	lock, err := countryTaskWorkerLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	marker := countryTaskSyntheticStarted(request)
	for _, kind := range []string{"boot", "request", "ticks", "pid"} {
		bad := marker
		switch kind {
		case "boot":
			bad.BootID = "11234567-89ab-cdef-0123-456789abcdef"
		case "request":
			bad.RequestSHA = core.Hash("foreign")
		case "ticks":
			bad.StartTicks = "18446744073709551616"
		case "pid":
			bad.PID = 1
		}
		if countryTaskPublishStarted(context.Background(), dir, lock, request, bad) == nil {
			t.Fatal("invalid worker start proof accepted", kind)
		}
	}
	readonly, err := dir.OpenFile("task.lock", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer readonly.Close()
	if countryTaskPublishStarted(context.Background(), dir, readonly, request, marker) == nil {
		t.Fatal("read-only observation granted execution")
	}
	if err := countryTaskPublishStarted(context.Background(), dir, lock, request, marker); err != nil {
		t.Fatal(err)
	}
	if err := countryTaskPublishStarted(context.Background(), dir, lock, request, marker); err == nil {
		t.Fatal("original worker started twice")
	}
	got, err := countryTaskReadStarted(dir.Root, request)
	if err != nil || got != marker {
		t.Fatal(got, err)
	}
}

func TestCountryTaskTerminalKeepsOriginalFailureImmutableAndCannotInventSuccess(t *testing.T) {
	s, request, _, dir := countryTaskPreparedFixture(t)
	if _, _, err := s.markDispatch(context.Background(), request, countryFixtureBoot); err != nil {
		t.Fatal(err)
	}
	lock, err := countryTaskWorkerLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := countryTaskPublishStarted(context.Background(), dir, lock, request, countryTaskSyntheticStarted(request)); err != nil {
		t.Fatal(err)
	}
	missing := countryTaskOperation(request, "succeeded", "")
	if countryTaskPublishResult(context.Background(), dir, lock, request, missing) == nil {
		t.Fatal("missing data commit receipt invented success")
	}
	original := countryTaskOperation(request, "needs_attention", "synthetic incomplete data transfer; retain original")
	if err := countryTaskPublishResult(context.Background(), dir, lock, request, original); err != nil {
		t.Fatal(err)
	}
	before, err := dir.Lstat("result.json")
	if err != nil {
		t.Fatal(err)
	}
	changed := countryTaskOperation(request, "failed", "must not replace historical original")
	if countryTaskPublishResult(context.Background(), dir, lock, request, changed) == nil {
		t.Fatal("historical failure overwritten")
	}
	raw, err := geoStoreRead(dir.Root, "result.json", 32<<10)
	if err != nil {
		t.Fatal(err)
	}
	got, err := core.DecodeWAFCountryDataOperation(raw, request.JobID, request.ActorID, request.Selection)
	if err != nil || got.State != original.State || got.Error != original.Error {
		t.Fatal(got, err)
	}
	after, err := dir.Lstat("result.json")
	if err != nil || !geoStoreStableInfo(before, after) {
		t.Fatal("terminal identity changed", err)
	}
}

func TestCountryTaskCancelledOrUnnamedWorkerCannotPublishStartOrTerminal(t *testing.T) {
	s, request, _, dir := countryTaskPreparedFixture(t)
	if _, _, err := s.markDispatch(context.Background(), request, countryFixtureBoot); err != nil {
		t.Fatal(err)
	}
	lock, err := countryTaskWorkerLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if countryTaskPublishStarted(ctx, dir, lock, request, countryTaskSyntheticStarted(request)) == nil {
		t.Fatal("cancelled worker start published")
	}
	if err := dir.Rename("task.lock", "retained.lock"); err != nil {
		t.Fatal(err)
	}
	if countryTaskPublishStarted(context.Background(), dir, lock, request, countryTaskSyntheticStarted(request)) == nil {
		t.Fatal("unnamed old descriptor granted execution")
	}
	if countryTaskPublishResult(context.Background(), dir, lock, request, countryTaskOperation(request, "failed", "synthetic cancelled original")) == nil {
		t.Fatal("missing start/lock granted terminal")
	}
}

func TestCountryTaskUnitObservationRejectsUnknownDuplicateAndInventedRunningState(t *testing.T) {
	for _, raw := range []string{"MainPID=0\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n", "MainPID=123\nLoadState=loaded\nActiveState=activating\nSubState=start\n", "MainPID=123\nLoadState=loaded\nActiveState=active\nSubState=running\n", "MainPID=0\nLoadState=loaded\nActiveState=failed\nSubState=failed\n"} {
		if _, err := parseCountryTaskUnitObservation(raw); err != nil {
			t.Fatal(raw, err)
		}
	}
	valid := "MainPID=123\nLoadState=loaded\nActiveState=active\nSubState=running\n"
	for _, raw := range []string{valid + "MainPID=123\n", valid + "Other=0\n", strings.Replace(valid, "MainPID=123", "MainPID=0123", 1), strings.Replace(valid, "LoadState=loaded", "LoadState=error", 1), strings.Replace(valid, "ActiveState=active", "ActiveState=inactive", 1), strings.Replace(valid, "SubState=running", "SubState=unknown", 1), "", strings.Repeat(" ", 4097)} {
		if _, err := parseCountryTaskUnitObservation(raw); err == nil {
			t.Fatal("ambiguous unit state accepted", raw)
		}
	}
}

func TestCountryTaskLiveIdentityUsesActualCurrentKernelLifetimeAndExecutable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual read-only kernel identity fixture requires Linux root")
	}
	boot, err := countryTaskBootID()
	if err != nil {
		t.Fatal(err)
	}
	ticks, err := diskHostStartTicks()
	if err != nil {
		t.Fatal(err)
	}
	sha, err := diskHostExecutableSHA()
	if err != nil {
		t.Fatal(err)
	}
	marker := countryTaskStarted{Format: 1, BootID: boot, PID: os.Getpid(), StartTicks: ticks, ExecutableSHA: sha}
	if err := countryTaskLiveProcess(context.Background(), marker); err != nil {
		t.Fatal(err)
	}
	n, err := strconv.ParseUint(ticks, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	bad := marker
	bad.StartTicks = strconv.FormatUint(n+1, 10)
	if countryTaskLiveProcess(context.Background(), bad) == nil {
		t.Fatal("reused PID/lifetime accepted")
	}
	bad = marker
	bad.ExecutableSHA = core.Hash("another executable")
	if countryTaskLiveProcess(context.Background(), bad) == nil {
		t.Fatal("another executable accepted")
	}
}
