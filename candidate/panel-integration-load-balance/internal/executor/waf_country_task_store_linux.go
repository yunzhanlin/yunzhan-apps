//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

const countryTasksRoot = "/var/lib/panel-executor/waf-country-jobs"
const countryTasksMax = 128
const countryTasksMaxBytes int64 = 512 << 20

type countryTaskRequest struct {
	Format      int                          `json:"format"`
	JobID       string                       `json:"job_id"`
	ActorID     string                       `json:"actor_id"`
	Selection   core.WAFCountryDataSelection `json:"selection"`
	PayloadSHA  string                       `json:"payload_sha256"`
	EnvelopeSHA string                       `json:"envelope_sha256"`
	PreparedAt  string                       `json:"prepared_at"`
}

// Internal filesystem primitive, NOT signature or execution authority. The
// production controller MUST call authorizeWAFCountryData before preparing
// this seal and the fixed worker must independently reauthorize the same seal.
// Tests may exercise metadata durability without claiming application trust.
type countryTaskStore struct {
	base  string
	now   func() time.Time
	guard func() error
	fault func(string) error
}

func productionCountryTaskStore() countryTaskStore {
	return countryTaskStore{base: countryTasksRoot, now: time.Now}
}
func (s countryTaskStore) open(create bool) (*statisticsGeoDirectory, error) {
	return (statisticsGeoStore{base: s.base, trust: appcatalog.Default(), now: s.now}).open(create)
}
func (s countryTaskStore) checkpoint(ctx context.Context, point string) error {
	if ctx == nil {
		return errors.New("country task context missing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.guard != nil {
		if err := s.guard(); err != nil {
			return err
		}
	}
	if s.fault != nil {
		return s.fault(point)
	}
	return nil
}
func countryTaskName(name string) bool {
	return core.ValidID(name) || strings.HasPrefix(name, ".prepare-") && core.ValidID(strings.TrimPrefix(name, ".prepare-"))
}
func countryTaskDirectory(base *statisticsGeoDirectory, name string) (*statisticsGeoDirectory, error) {
	if base == nil || !base.current() || !countryTaskName(name) {
		return nil, errors.New("country task fixed directory name invalid")
	}
	info, err := base.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !moduleRecordInfo(info, true, false) {
		return nil, errors.New("country task private directory identity invalid")
	}
	root, err := base.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	dir := &statisticsGeoDirectory{root, filepath.Join(base.path, name), info}
	if !base.current() || !dir.current() {
		root.Close()
		return nil, errors.New("country task directory changed during open")
	}
	return dir, nil
}
func countryTaskFileLimit(name string) (int64, bool) {
	switch name {
	case "request.json":
		return 4096, true
	case "envelope.json":
		return appcatalog.MaxGeoDataEnvelopeBytes, true
	case "dispatch.json", "started.json":
		return 4096, true
	case "result.json":
		return 32 << 10, true
	case "task.lock":
		return 0, true
	}
	return 0, false
}
func countryTaskRequestValid(in countryTaskRequest) bool {
	if in.Format != 1 || !core.ValidID(in.JobID) || !core.ValidID(in.ActorID) || core.ValidateWAFCountryDataSelection(in.Selection) != nil || !wafLogDigestValid(in.EnvelopeSHA) || !hardeningCanonicalTime(in.PreparedAt) {
		return false
	}
	raw, _ := json.Marshal(in.Selection)
	return in.PayloadSHA == core.Hash(string(raw))
}
func countryTaskSameBinding(a, b countryTaskRequest) bool {
	return countryTaskRequestValid(a) && countryTaskRequestValid(b) && a.JobID == b.JobID && a.ActorID == b.ActorID && a.PayloadSHA == b.PayloadSHA && a.EnvelopeSHA == b.EnvelopeSHA && core.SameWAFCountryDataSelection(a.Selection, b.Selection)
}
func countryTaskWriteNew(root *os.Root, name string, raw []byte) error {
	limit, ok := countryTaskFileLimit(name)
	if !ok || name == "task.lock" || len(raw) < 1 || int64(len(raw)) > limit {
		return errors.New("country task new metadata capacity invalid")
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	return hardeningJournalSync(root)
}
func countryTaskContents(root *os.Root, preparedOnly bool) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := f.ReadDir(7)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 6 {
		return errors.New("country task leaf membership exceeds fixed capacity")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		limit, ok := countryTaskFileLimit(entry.Name())
		info, e := root.Lstat(entry.Name())
		if !ok || e != nil || !moduleRecordInfo(info, false, false) || info.Size() > limit || entry.Name() != "task.lock" && info.Size() < 1 || preparedOnly && entry.Name() != "request.json" && entry.Name() != "envelope.json" {
			return errors.New("country task unknown, unsafe or incomplete private member")
		}
		seen[entry.Name()] = true
	}
	if !seen["request.json"] || !seen["envelope.json"] {
		return errors.New("country task original request/envelope missing")
	}
	return nil
}

func (s countryTaskStore) read(base *statisticsGeoDirectory, id string) (countryTaskRequest, []byte, *statisticsGeoDirectory, error) {
	var empty countryTaskRequest
	if !core.ValidID(id) {
		return empty, nil, nil, errors.New("country task original ID invalid")
	}
	dir, err := countryTaskDirectory(base, id)
	if err != nil {
		return empty, nil, nil, err
	}
	failed := func(err error) (countryTaskRequest, []byte, *statisticsGeoDirectory, error) {
		dir.Close()
		return empty, nil, nil, err
	}
	if err := countryTaskContents(dir.Root, false); err != nil {
		return failed(err)
	}
	raw, info, err := geoStoreReadIdentity(dir.Root, "request.json", 4096)
	if err != nil {
		return failed(err)
	}
	var request countryTaskRequest
	if countryCacheDecode(raw, &request) != nil || !countryTaskRequestValid(request) || request.JobID != id {
		return failed(errors.New("country task sealed original request invalid"))
	}
	envelope, err := geoStoreRead(dir.Root, "envelope.json", appcatalog.MaxGeoDataEnvelopeBytes)
	if err != nil {
		return failed(err)
	}
	if core.Hash(string(envelope)) != request.EnvelopeSHA {
		return failed(errors.New("country task original full envelope digest differs"))
	}
	decoded, err := appcatalog.DecodeGeoDataEnvelope(envelope)
	if err != nil {
		return failed(err)
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, envelope) {
		return failed(errors.New("country task envelope not complete canonical original bytes"))
	}
	named, err := dir.Lstat("request.json")
	if err != nil || !geoStoreStableInfo(info, named) || !dir.current() || !base.current() {
		return failed(errors.New("country task original metadata changed during read"))
	}
	return request, envelope, dir, nil
}

func (s countryTaskStore) usage(ctx context.Context, base *statisticsGeoDirectory) (int64, int, error) {
	if ctx == nil || base == nil || !base.current() {
		return 0, 0, errors.New("country task inventory context or original anchor invalid")
	}
	f, err := base.Open(".")
	if err != nil {
		return 0, 0, err
	}
	entries, err := f.ReadDir(countryTasksMax + 2)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > countryTasksMax+1 {
		return 0, 0, errors.New("country task namespace exceeds fixed capacity")
	}
	var total int64
	count := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		if entry.Name() == "store.lock" {
			info, err := base.Lstat(entry.Name())
			if err != nil || !moduleRecordInfo(info, false, false) || info.Size() != 0 {
				return 0, 0, errors.New("country task original namespace lock invalid")
			}
			continue
		}
		dir, err := countryTaskDirectory(base, entry.Name())
		if err != nil {
			return 0, 0, err
		}
		count++
		f, err := dir.Open(".")
		if err != nil {
			dir.Close()
			return 0, 0, err
		}
		files, err := f.ReadDir(7)
		f.Close()
		if err != nil && !errors.Is(err, io.EOF) || len(files) > 6 {
			dir.Close()
			return 0, 0, errors.New("country task retained member capacity exceeded")
		}
		for _, file := range files {
			limit, ok := countryTaskFileLimit(file.Name())
			info, err := dir.Lstat(file.Name())
			if !ok || err != nil || !moduleRecordInfo(info, false, false) || info.Size() < 0 || info.Size() > limit {
				dir.Close()
				return 0, 0, errors.New("country task retained original has unsafe/foreign member")
			}
			total += info.Size()
			if total > countryTasksMaxBytes {
				dir.Close()
				return 0, 0, errors.New("country task retained metadata quota exceeded")
			}
		}
		current := dir.current()
		dir.Close()
		if !current {
			return 0, 0, errors.New("country task retained directory changed")
		}
	}
	if !base.current() {
		return 0, 0, errors.New("country task namespace changed")
	}
	return total, count, nil
}

// Sealing prepares metadata ONLY. It never starts a worker or transfers data.
// Existing originals are observed, NEVER restarted; a partial original stage
// is retained and blocks replay. Complete request precedes the envelope write.
func (s countryTaskStore) prepare(ctx context.Context, request countryTaskRequest, envelope []byte) (countryTaskRequest, string, bool, error) {
	var empty countryTaskRequest
	if !countryTaskRequestValid(request) || len(envelope) < 1 || len(envelope) > appcatalog.MaxGeoDataEnvelopeBytes {
		return empty, "", false, errors.New("country task original preparation identity invalid")
	}
	request.Selection.Countries = append([]string(nil), request.Selection.Countries...)
	envelope = bytes.Clone(envelope)
	if core.Hash(string(envelope)) != request.EnvelopeSHA {
		return empty, "", false, errors.New("country task original envelope hash differs")
	}
	decoded, err := appcatalog.DecodeGeoDataEnvelope(envelope)
	if err != nil {
		return empty, "", false, err
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, envelope) {
		return empty, "", false, errors.New("country task original envelope not canonical")
	}
	if err := s.checkpoint(ctx, "before-prepare-open"); err != nil {
		return empty, "", false, err
	}
	base, err := s.open(true)
	if err != nil {
		return empty, "", false, err
	}
	defer base.Close()
	lock, err := geoStoreLock(base.Root)
	if err != nil {
		return empty, "", false, err
	}
	defer lock.Close()
	if _, err := base.Lstat(request.JobID); err == nil {
		prior, _, dir, err := s.read(base, request.JobID)
		if err != nil {
			return empty, "", false, err
		}
		defer dir.Close()
		if !countryTaskSameBinding(prior, request) {
			return empty, "", false, errors.New("country task original ID already binds another complete request")
		}
		raw, _ := countryCacheJSON(prior)
		return prior, core.Hash(string(raw)), false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, "", false, err
	}
	stage := ".prepare-" + request.JobID
	if _, err := base.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		return empty, "", false, errors.New("country task original incomplete stage retained; no prepare/dispatch replay")
	}
	raw, err := countryCacheJSON(request)
	if err != nil || len(raw) > 4096 {
		return empty, "", false, errors.New("country task original request exceeds capacity")
	}
	used, count, err := s.usage(ctx, base)
	if err != nil {
		return empty, "", false, err
	}
	if count >= countryTasksMax || int64(len(raw)+len(envelope)+(40<<10)) > countryTasksMaxBytes-used {
		return empty, "", false, errors.New("country task metadata quota unavailable; originals not pruned")
	}
	if err := countryCacheRequireLock(base, lock); err != nil {
		return empty, "", false, err
	}
	if err := s.checkpoint(ctx, "before-prepare-stage"); err != nil {
		return empty, "", false, err
	}
	if err := base.Mkdir(stage, 0700); err != nil {
		return empty, "", false, err
	}
	if err := hardeningJournalSync(base.Root); err != nil {
		return empty, "", false, err
	}
	dir, err := countryTaskDirectory(base, stage)
	if err != nil {
		return empty, "", false, err
	}
	defer dir.Close()
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"request.json", raw}, {"envelope.json", envelope}} {
		if err := s.checkpoint(ctx, "before-prepare-"+file.name); err != nil {
			return empty, "", false, err
		}
		if !dir.current() {
			return empty, "", false, errors.New("country task original stage changed")
		}
		if err := countryTaskWriteNew(dir.Root, file.name, file.raw); err != nil {
			return empty, "", false, err
		}
		if err := s.checkpoint(ctx, "after-prepare-"+file.name); err != nil {
			return empty, "", false, err
		}
	}
	if err := countryTaskContents(dir.Root, true); err != nil {
		return empty, "", false, err
	}
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"request.json", raw}, {"envelope.json", envelope}} {
		read, err := geoStoreRead(dir.Root, file.name, int64(len(file.raw)))
		if err != nil || !bytes.Equal(read, file.raw) {
			return empty, "", false, errors.New("country task original staged bytes differ")
		}
	}
	if err := s.checkpoint(ctx, "before-prepare-publish"); err != nil {
		return empty, "", false, err
	}
	if err := countryCacheRequireLock(base, lock); err != nil {
		return empty, "", false, err
	}
	if !dir.current() {
		return empty, "", false, errors.New("country task original staged directory changed")
	}
	f, err := base.Open(".")
	if err != nil {
		return empty, "", false, err
	}
	info, err := f.Stat()
	if err != nil || !os.SameFile(info, base.identity) {
		f.Close()
		return empty, "", false, errors.New("country task publication anchor changed")
	}
	err = unix.Renameat2(int(f.Fd()), stage, int(f.Fd()), request.JobID, unix.RENAME_NOREPLACE)
	f.Close()
	if err != nil {
		return empty, "", false, err
	}
	if err := hardeningJournalSync(base.Root); err != nil {
		return empty, "", false, err
	}
	if err := s.checkpoint(ctx, "after-prepare-publish"); err != nil {
		return empty, "", false, err
	}
	return request, core.Hash(string(raw)), true, nil
}
