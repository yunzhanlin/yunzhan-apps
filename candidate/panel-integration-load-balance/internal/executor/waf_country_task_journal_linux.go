//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

type countryTaskDispatch struct {
	Format      int    `json:"format"`
	JobID       string `json:"job_id"`
	RequestSHA  string `json:"request_sha256"`
	BootID      string `json:"boot_id"`
	SubmittedAt string `json:"submitted_at"`
}
type countryTaskStarted struct {
	Format        int    `json:"format"`
	JobID         string `json:"job_id"`
	RequestSHA    string `json:"request_sha256"`
	BootID        string `json:"boot_id"`
	PID           int    `json:"pid"`
	StartTicks    string `json:"start_ticks"`
	ExecutableSHA string `json:"executable_sha256"`
}

var countryTaskBootPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func countryTaskStartTicksValid(value string) bool {
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == value
}

func countryTaskBootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(raw) != 37 || raw[36] != '\n' || !countryTaskBootPattern.Match(raw[:36]) {
		return "", errors.New("country task kernel boot identity unavailable")
	}
	return string(raw[:36]), nil
}
func countryTaskRequestDigest(request countryTaskRequest) string {
	if !countryTaskRequestValid(request) {
		return ""
	}
	raw, _ := countryCacheJSON(request)
	return core.Hash(string(raw))
}
func countryTaskOperation(request countryTaskRequest, state, detail string) core.WAFCountryDataOperation {
	return core.WAFCountryDataOperation{Format: 1, JobID: request.JobID, ActorID: request.ActorID, Selection: request.Selection, PayloadSHA: request.PayloadSHA, RequestSHA: countryTaskRequestDigest(request), RequestedCachePlanSHA: core.WAFCountryCachePlanSHA(request.JobID, request.Selection), State: state, Error: detail, DataOnly: true}
}

func countryTaskReadDispatch(root *os.Root, request countryTaskRequest) (countryTaskDispatch, error) {
	var out countryTaskDispatch
	if root == nil || !countryTaskRequestValid(request) {
		return out, errors.New("country task dispatch observation identity invalid")
	}
	raw, err := geoStoreRead(root, "dispatch.json", 4096)
	if err != nil {
		return out, err
	}
	if countryCacheDecode(raw, &out) != nil || out.Format != 1 || out.JobID != request.JobID || out.RequestSHA != countryTaskRequestDigest(request) || !countryTaskBootPattern.MatchString(out.BootID) || !hardeningCanonicalTime(out.SubmittedAt) {
		return countryTaskDispatch{}, errors.New("country task original dispatch proof differs")
	}
	return out, nil
}
func countryTaskReadStarted(root *os.Root, request countryTaskRequest) (countryTaskStarted, error) {
	var out countryTaskStarted
	if root == nil || !countryTaskRequestValid(request) {
		return out, errors.New("country task worker observation identity invalid")
	}
	raw, err := geoStoreRead(root, "started.json", 4096)
	if err != nil {
		return out, err
	}
	if countryCacheDecode(raw, &out) != nil || out.Format != 1 || out.JobID != request.JobID || out.RequestSHA != countryTaskRequestDigest(request) || !countryTaskBootPattern.MatchString(out.BootID) || out.PID < 2 || !countryTaskStartTicksValid(out.StartTicks) || !wafLogDigestValid(out.ExecutableSHA) {
		return countryTaskStarted{}, errors.New("country task original worker identity proof differs")
	}
	return out, nil
}

// Dispatch intent is durable BEFORE the one systemd start. Seeing any prior
// dispatch is observation only, including a lost reply or a reboot. No retry
// can turn this metadata method into another start request.
func (s countryTaskStore) markDispatch(ctx context.Context, request countryTaskRequest, boot string) (countryTaskDispatch, bool, error) {
	var empty countryTaskDispatch
	if !countryTaskRequestValid(request) || !countryTaskBootPattern.MatchString(boot) {
		return empty, false, errors.New("country task original dispatch identity invalid")
	}
	if err := s.checkpoint(ctx, "before-dispatch-open"); err != nil {
		return empty, false, err
	}
	base, err := s.open(false)
	if err != nil {
		return empty, false, err
	}
	defer base.Close()
	lock, err := geoStoreLock(base.Root)
	if err != nil {
		return empty, false, err
	}
	defer lock.Close()
	prior, _, dir, err := s.read(base, request.JobID)
	if err != nil {
		return empty, false, err
	}
	defer dir.Close()
	if !countryTaskSameBinding(prior, request) || prior.PreparedAt != request.PreparedAt {
		return empty, false, errors.New("country task original prepared seal differs")
	}
	if old, err := countryTaskReadDispatch(dir.Root, request); err == nil {
		return old, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, false, err
	}
	for _, name := range []string{"started.json", "result.json", "task.lock"} {
		if _, err := dir.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return empty, false, errors.New("country task has execution evidence without original dispatch; no start")
		}
	}
	if err := s.checkpoint(ctx, "before-dispatch-write"); err != nil {
		return empty, false, err
	}
	if err := countryCacheRequireLock(base, lock); err != nil {
		return empty, false, err
	}
	if !dir.current() {
		return empty, false, errors.New("country task original dispatch directory changed")
	}
	marker := countryTaskDispatch{1, request.JobID, countryTaskRequestDigest(request), boot, s.now().UTC().Format(time.RFC3339)}
	raw, err := countryCacheJSON(marker)
	if err != nil {
		return empty, false, err
	}
	if err := countryTaskWriteNew(dir.Root, "dispatch.json", raw); err != nil {
		return empty, false, err
	}
	if err := s.checkpoint(ctx, "after-dispatch-write"); err != nil {
		return empty, false, err
	}
	return marker, true, nil
}

func countryTaskWorkerLock(dir *statisticsGeoDirectory) (*os.File, error) {
	if dir == nil || !dir.current() {
		return nil, errors.New("country task worker directory unavailable")
	}
	f, err := dir.OpenFile("task.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if errors.Is(err, os.ErrExist) {
		f, err = dir.OpenFile("task.lock", os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, err
	}
	if err := countryTaskRequireWorkerLock(dir, f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
func countryTaskRequireWorkerLock(dir *statisticsGeoDirectory, f *os.File) error {
	if dir == nil || f == nil || !dir.current() {
		return errors.New("country task original worker lock missing")
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDWR {
		return errors.New("country task read-only observation cannot grant execution")
	}
	opened, err := f.Stat()
	named, nerr := dir.Lstat("task.lock")
	if err != nil || nerr != nil || !moduleRecordInfo(opened, false, false) || opened.Size() != 0 || !geoStoreStableInfo(opened, named) {
		return errors.New("country task original named worker lock changed")
	}
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func countryTaskPublishStarted(ctx context.Context, dir *statisticsGeoDirectory, lock *os.File, request countryTaskRequest, marker countryTaskStarted) error {
	if ctx == nil || ctx.Err() != nil || dir == nil || lock == nil || !countryTaskRequestValid(request) || marker.Format != 1 || marker.JobID != request.JobID || marker.RequestSHA != countryTaskRequestDigest(request) || !countryTaskBootPattern.MatchString(marker.BootID) || marker.PID < 2 || !countryTaskStartTicksValid(marker.StartTicks) || !wafLogDigestValid(marker.ExecutableSHA) {
		return errors.New("country task original worker start proof invalid")
	}
	dispatch, err := countryTaskReadDispatch(dir.Root, request)
	if err != nil || dispatch.BootID != marker.BootID {
		return errors.New("country task original dispatch boot differs; no replay after restart")
	}
	for _, name := range []string{"started.json", "result.json"} {
		if _, err := dir.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.New("country task already ran or completed; no worker replay")
		}
	}
	if err := countryTaskRequireWorkerLock(dir, lock); err != nil {
		return err
	}
	raw, err := countryCacheJSON(marker)
	if err != nil {
		return err
	}
	return countryTaskWriteNew(dir.Root, "started.json", raw)
}

func countryTaskPublishResult(ctx context.Context, dir *statisticsGeoDirectory, lock *os.File, request countryTaskRequest, out core.WAFCountryDataOperation) error {
	if ctx == nil || ctx.Err() != nil || dir == nil || lock == nil || !countryTaskRequestValid(request) {
		return errors.New("country task terminal publication context invalid")
	}
	raw, err := countryCacheJSON(out)
	if err != nil {
		return err
	}
	parsed, err := core.DecodeWAFCountryDataOperation(raw, request.JobID, request.ActorID, request.Selection)
	if err != nil || parsed.RequestSHA != countryTaskRequestDigest(request) || parsed.State != "succeeded" && parsed.State != "failed" && parsed.State != "needs_attention" {
		return errors.New("country task terminal original result differs")
	}
	started, err := countryTaskReadStarted(dir.Root, request)
	if err != nil {
		return err
	}
	dispatch, err := countryTaskReadDispatch(dir.Root, request)
	if err != nil || dispatch.BootID != started.BootID {
		return errors.New("country task terminal original dispatch/start chain differs")
	}
	if err := countryTaskRequireWorkerLock(dir, lock); err != nil {
		return err
	}
	return countryTaskWriteNew(dir.Root, "result.json", raw)
}
