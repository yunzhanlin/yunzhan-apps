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
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

const memcachedUnixControlsRoot = "/var/lib/panel-executor/memcached-unix-controls"
const memcachedUnixControlRootLimit = 4096
const memcachedUnixControlSeedLimit = 4096

func memcachedUnixControlInstalledSHA(record core.MemcachedUnixInstallRecord) string {
	raw, err := coreEncodeMemcachedUnixInstallRecord(record)
	if err != nil {
		return ""
	}
	return core.Hash(string(raw))
}

// Separate evidence, never install events or the legacy TCP update journal.
// The operation cannot choose a native account, image, container or command.
type memcachedUnixControlSeed struct {
	Format                int                                `json:"format"`
	Operation             core.MemcachedUnixControlOperation `json:"operation"`
	InstalledRecordSHA256 string                             `json:"installed_record_sha256"`
}
type memcachedUnixControlIssued struct {
	Format           int    `json:"format"`
	SeedSHA256       string `json:"seed_sha256"`
	ContainerID      string `json:"container_id"`
	InitialPID       int    `json:"initial_pid"`
	InitialStartedAt string `json:"initial_started_at"`
}
type memcachedUnixControlJournalStore struct{ base string }
type memcachedUnixControlJournal struct {
	d  *composeUpdateDirectory
	id string
}
type memcachedUnixControlLease struct {
	j    *memcachedUnixControlJournal
	file *os.File
	info os.FileInfo
}
type memcachedUnixControlSnapshot struct {
	Seed        memcachedUnixControlSeed
	Issued      *memcachedUnixControlIssued
	Result      *core.MemcachedUnixControlResult
	Observation *memcachedUnixControlObservation
}

func (j *memcachedUnixControlJournal) Close() {
	if j != nil && j.d != nil {
		j.d.Close()
	}
}
func (l *memcachedUnixControlLease) Close() {
	if l != nil && l.file != nil {
		l.file.Close()
		l.file = nil
	}
}
func memcachedUnixControlLeafLimit(name string) (int64, bool) {
	switch name {
	case "operation.json", "issued.json", "result.json", "observation.json":
		return memcachedUnixControlSeedLimit, true
	case "run.lock", "store.lock":
		return 0, true
	}
	return 0, false
}
func memcachedUnixControlWrite(root *os.Root, name string, raw []byte) error {
	limit, known := memcachedUnixControlLeafLimit(name)
	if !known || int64(len(raw)) > limit || (len(raw) == 0) != (limit == 0) {
		return core.ErrMemcachedUnixControl
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if file.Chown(0, 0) != nil || file.Chmod(0600) != nil {
		return core.ErrMemcachedUnixControl
	}
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		return core.ErrMemcachedUnixControl
	}
	if file.Sync() != nil || ruleFeedStoreSync(root) != nil {
		return core.ErrMemcachedUnixControl
	}
	info, e1 := file.Stat()
	named, e2 := root.Lstat(name)
	if e1 != nil || e2 != nil || !memcachedUnixJournalFileInfo(info, limit, len(raw) == 0) || !geoStoreStableInfo(info, named) {
		return core.ErrMemcachedUnixControl
	}
	return nil
}
func memcachedUnixControlDecodeSeed(raw []byte) (memcachedUnixControlSeed, error) {
	var seed memcachedUnixControlSeed
	if len(raw) == 0 || len(raw) > memcachedUnixControlSeedLimit || json.Unmarshal(raw, &seed) != nil {
		return seed, core.ErrMemcachedUnixControl
	}
	canonical, _ := json.Marshal(seed)
	if !bytes.Equal(raw, canonical) || seed.Format != 1 || core.ValidateMemcachedUnixControlOperation(seed.Operation) != nil || len(seed.InstalledRecordSHA256) != 64 || !composeRequestSHAPattern.MatchString(seed.InstalledRecordSHA256) {
		return memcachedUnixControlSeed{}, core.ErrMemcachedUnixControl
	}
	return seed, nil
}
func (j *memcachedUnixControlJournal) current() bool {
	if j == nil || j.d == nil || !j.d.current() || len(j.d.roots) < 2 {
		return false
	}
	for _, root := range j.d.roots[len(j.d.roots)-2:] {
		info, err := root.Stat(".")
		if err != nil || !memcachedUnixJournalRootInfo(info) {
			return false
		}
	}
	return true
}
func (s memcachedUnixControlJournalStore) open(id string) (*memcachedUnixControlJournal, error) {
	d, err := openComposeUpdateDirectory(s.base, id)
	if err != nil {
		return nil, err
	}
	j := &memcachedUnixControlJournal{d: d, id: id}
	if !j.current() {
		j.Close()
		return nil, core.ErrMemcachedUnixControl
	}
	return j, nil
}
func (j *memcachedUnixControlJournal) inventory() (map[string]os.FileInfo, error) {
	if !j.current() {
		return nil, core.ErrMemcachedUnixControl
	}
	dir, err := j.d.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := dir.ReadDir(6)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 5 {
		return nil, core.ErrMemcachedUnixControl
	}
	out := map[string]os.FileInfo{}
	for _, entry := range entries {
		name := entry.Name()
		limit, known := memcachedUnixControlLeafLimit(name)
		info, err := j.d.root.Lstat(name)
		if !known || name == "store.lock" || err != nil || !memcachedUnixJournalFileInfo(info, limit, name == "run.lock") {
			return nil, core.ErrMemcachedUnixControl
		}
		out[name] = info
	}
	if out["operation.json"] == nil || out["run.lock"] == nil {
		return nil, core.ErrMemcachedUnixControl
	}
	return out, nil
}
func (j *memcachedUnixControlJournal) read() (memcachedUnixControlSnapshot, error) {
	var out memcachedUnixControlSnapshot
	before, err := j.inventory()
	if err != nil {
		return out, err
	}
	raw, err := geoStoreRead(j.d.root, "operation.json", memcachedUnixControlSeedLimit)
	if err != nil {
		return out, err
	}
	seed, err := memcachedUnixControlDecodeSeed(raw)
	if err != nil || seed.Operation.RequestID != j.id {
		return out, core.ErrMemcachedUnixControl
	}
	out.Seed = seed
	if before["issued.json"] != nil {
		b, err := geoStoreRead(j.d.root, "issued.json", memcachedUnixControlSeedLimit)
		var value memcachedUnixControlIssued
		if err != nil || json.Unmarshal(b, &value) != nil {
			return out, core.ErrMemcachedUnixControl
		}
		canonical, _ := json.Marshal(value)
		stopped := seed.Operation.Input.Action == "start" || seed.Operation.Input.Action == "retire"
		if !bytes.Equal(b, canonical) || value.Format != 1 || value.SeedSHA256 != core.Hash(string(raw)) || len(value.ContainerID) != 64 || !dockerObjectPattern.MatchString(value.ContainerID) || value.InitialPID < 0 || stopped && value.InitialPID != 0 || !stopped && value.InitialPID < 2 || value.InitialStartedAt == "" || len(value.InitialStartedAt) > 64 {
			return out, core.ErrMemcachedUnixControl
		}
		out.Issued = &value
		if _, err := time.Parse(time.RFC3339Nano, value.InitialStartedAt); err != nil {
			return out, core.ErrMemcachedUnixControl
		}
	}
	if before["result.json"] != nil {
		b, err := geoStoreRead(j.d.root, "result.json", memcachedUnixControlSeedLimit)
		var value core.MemcachedUnixControlResult
		if err != nil || json.Unmarshal(b, &value) != nil || core.ValidateMemcachedUnixControlResult(seed.Operation, value) != nil {
			return out, core.ErrMemcachedUnixControl
		}
		canonical, _ := json.Marshal(value)
		if !bytes.Equal(b, canonical) || value.State == "observed" || value.State == "completed" && out.Issued == nil || value.State == "refused" && out.Issued != nil {
			return out, core.ErrMemcachedUnixControl
		}
		out.Result = &value
	}
	if before["observation.json"] != nil {
		raw, err := geoStoreRead(j.d.root, "observation.json", memcachedUnixControlSeedLimit)
		observation, decodeErr := decodeMemcachedUnixControlObservation(raw, out)
		if err != nil || decodeErr != nil {
			return out, core.ErrMemcachedUnixControl
		}
		out.Observation = &observation
	}
	after, err := j.inventory()
	if err != nil || len(before) != len(after) {
		return out, core.ErrMemcachedUnixControl
	}
	for name, info := range before {
		if !geoStoreStableInfo(info, after[name]) {
			return out, core.ErrMemcachedUnixControl
		}
	}
	return out, nil
}
func (j *memcachedUnixControlJournal) lease() (*memcachedUnixControlLease, error) {
	if _, err := j.read(); err != nil {
		return nil, err
	}
	file, err := memcachedUnixJournalLock(j.d.root, "run.lock", false)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	lease := &memcachedUnixControlLease{j: j, file: file, info: info}
	if !lease.current() {
		lease.Close()
		return nil, core.ErrMemcachedUnixControl
	}
	return lease, nil
}
func (l *memcachedUnixControlLease) current() bool {
	return l != nil && l.j != nil && l.j.current() && memcachedUnixJournalHeld(l.j.d.root, "run.lock", l.file, l.info)
}
func (l *memcachedUnixControlLease) issued(value memcachedUnixControlIssued) error {
	if !l.current() {
		return core.ErrMemcachedUnixControl
	}
	before, err := l.j.read()
	if err != nil || before.Result != nil || before.Issued != nil || before.Observation != nil {
		return core.ErrMemcachedUnixControl
	}
	raw, _ := json.Marshal(value)
	if memcachedUnixControlWrite(l.j.d.root, "issued.json", raw) != nil {
		return core.ErrMemcachedUnixControl
	}
	after, err := l.j.read()
	if err != nil || after.Issued == nil || *after.Issued != value || !l.current() {
		return core.ErrMemcachedUnixControl
	}
	return nil
}
func (l *memcachedUnixControlLease) finish(value core.MemcachedUnixControlResult) error {
	if !l.current() {
		return core.ErrMemcachedUnixControl
	}
	before, err := l.j.read()
	if err != nil || before.Result != nil || before.Observation != nil || value.State == "observed" || core.ValidateMemcachedUnixControlResult(before.Seed.Operation, value) != nil || value.State == "completed" && before.Issued == nil || value.State == "refused" && before.Issued != nil {
		return core.ErrMemcachedUnixControl
	}
	raw, _ := json.Marshal(value)
	if memcachedUnixControlWrite(l.j.d.root, "result.json", raw) != nil {
		return core.ErrMemcachedUnixControl
	}
	after, err := l.j.read()
	if err != nil || after.Result == nil || *after.Result != value || !l.current() {
		return core.ErrMemcachedUnixControl
	}
	return nil
}

// Framing and persistence only. The real caller must verify original signed
// installation, fresh Core reservation and runtime ownership before claiming.
func (s memcachedUnixControlJournalStore) prepare(seed memcachedUnixControlSeed) (*memcachedUnixControlJournal, bool, error) {
	raw, _ := json.Marshal(seed)
	if _, err := memcachedUnixControlDecodeSeed(raw); err != nil {
		return nil, false, err
	}
	anchor, err := memcachedUnixBaseAt(s.base, 0700)
	if err != nil {
		return nil, false, err
	}
	anchor.Close()
	base, err := geoJobDirectory(s.base, false)
	if err != nil {
		return nil, false, err
	}
	defer base.Close()
	info, err := base.Stat(".")
	if err != nil || !memcachedUnixJournalRootInfo(info) {
		return nil, false, core.ErrMemcachedUnixControl
	}
	if _, err = base.Lstat("store.lock"); errors.Is(err, os.ErrNotExist) {
		if memcachedUnixControlWrite(base.Root, "store.lock", nil) != nil {
			return nil, false, core.ErrMemcachedUnixControl
		}
	} else if err != nil {
		return nil, false, err
	}
	lock, err := memcachedUnixJournalLock(base.Root, "store.lock", false)
	if err != nil {
		return nil, false, err
	}
	defer lock.Close()
	original, err := lock.Stat()
	if err != nil {
		return nil, false, err
	}
	inventory, err := memcachedUnixControlInventory(base)
	if err != nil {
		return nil, false, err
	}
	var retained *memcachedUnixControlJournal
	fail := func(e error) (*memcachedUnixControlJournal, bool, error) {
		if retained != nil {
			retained.Close()
		}
		return nil, false, e
	}
	for id := range inventory {
		if id == "store.lock" {
			continue
		}
		j, err := s.open(id)
		if err != nil {
			return fail(err)
		}
		value, err := j.read()
		if err != nil {
			j.Close()
			return fail(err)
		}
		if id == seed.Operation.RequestID {
			if value.Seed != seed {
				j.Close()
				return fail(core.ErrMemcachedUnixControl)
			}
			retained = j
		} else {
			j.Close()
			if value.outcome() == nil || value.outcome().State == "unknown" {
				return fail(core.ErrMemcachedUnixControl)
			}
		}
	}
	if !base.current() || !memcachedUnixJournalHeld(base.Root, "store.lock", lock, original) {
		return fail(core.ErrMemcachedUnixControl)
	}
	if retained != nil {
		return retained, false, nil
	}
	if len(inventory) >= memcachedUnixControlRootLimit+1 {
		return fail(core.ErrMemcachedUnixControl)
	}
	id := seed.Operation.RequestID
	if base.Mkdir(id, 0700) != nil || ruleFeedStoreSync(base.Root) != nil {
		return fail(core.ErrMemcachedUnixControl)
	}
	child, err := base.OpenRoot(id)
	if err != nil {
		return fail(err)
	}
	file, err := child.Open(".")
	if err != nil {
		child.Close()
		return fail(err)
	}
	err = file.Chown(0, 0)
	if err == nil {
		err = file.Chmod(0700)
	}
	if err == nil {
		err = file.Sync()
	}
	file.Close()
	child.Close()
	if err != nil || ruleFeedStoreSync(base.Root) != nil {
		return fail(core.ErrMemcachedUnixControl)
	}
	j, err := s.open(id)
	if err != nil {
		return fail(err)
	}
	for _, item := range []struct {
		name string
		raw  []byte
	}{{"operation.json", raw}, {"run.lock", nil}} {
		if !j.current() || !base.current() || !memcachedUnixJournalHeld(base.Root, "store.lock", lock, original) || memcachedUnixControlWrite(j.d.root, item.name, item.raw) != nil {
			j.Close()
			return fail(core.ErrMemcachedUnixControl)
		}
	}
	if _, err := j.read(); err != nil {
		j.Close()
		return fail(err)
	}
	return j, true, nil
}
func memcachedUnixControlInventory(base *statisticsGeoDirectory) (map[string]os.FileInfo, error) {
	if base == nil || !base.current() {
		return nil, core.ErrMemcachedUnixControl
	}
	dir, err := base.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := dir.ReadDir(memcachedUnixControlRootLimit + 2)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > memcachedUnixControlRootLimit+1 {
		return nil, core.ErrMemcachedUnixControl
	}
	out := map[string]os.FileInfo{}
	for _, entry := range entries {
		info, err := base.Lstat(entry.Name())
		if err != nil {
			return nil, err
		}
		if entry.Name() == "store.lock" {
			if !memcachedUnixJournalFileInfo(info, 0, true) {
				return nil, core.ErrMemcachedUnixControl
			}
		} else if !core.ValidID(entry.Name()) || !memcachedUnixJournalRootInfo(info) {
			return nil, core.ErrMemcachedUnixControl
		}
		out[entry.Name()] = info
	}
	if out["store.lock"] == nil {
		return nil, core.ErrMemcachedUnixControl
	}
	return out, nil
}

type memcachedUnixControlRun struct {
	lease    *memcachedUnixControlLease
	original *memcachedUnixProjectOriginal
	review   *core.MemcachedUnixControlReviewRequest
}

func memcachedUnixControlMatchesOriginal(value memcachedUnixControlSnapshot, p *memcachedUnixProjectOriginal) bool {
	return p != nil && p.head.Phase == "committed" && value.Seed.InstalledRecordSHA256 == memcachedUnixControlInstalledSHA(p.head) && value.Seed.Operation.ProjectID == p.head.Operation.ProjectID && (value.Issued == nil || value.Issued.ContainerID == p.head.ContainerID)
}

func (own *memcachedUnixControlRun) current(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || own == nil || own.lease == nil || !own.lease.current() || own.original == nil || own.original.current(ctx) != nil {
		return core.ErrMemcachedUnixControl
	}
	j := own.lease.j
	if len(j.d.paths) < 2 || j.d.paths[len(j.d.paths)-2] != memcachedUnixControlsRoot || j.d.paths[len(j.d.paths)-1] != filepath.Join(memcachedUnixControlsRoot, j.id) {
		return core.ErrMemcachedUnixControl
	}
	value, err := j.read()
	if err != nil || !memcachedUnixControlMatchesOriginal(value, own.original) || value.Observation != nil {
		return core.ErrMemcachedUnixControl
	}
	if own.review == nil {
		if value.Result != nil {
			return core.ErrMemcachedUnixControl
		}
	} else if core.ValidateMemcachedUnixControlReviewRequest(*own.review) != nil || own.review.Operation != value.Seed.Operation || value.Issued == nil || value.Result != nil && value.Result.State != "unknown" {
		return core.ErrMemcachedUnixControl
	}
	return nil
}
func (s memcachedUnixControlJournalStore) checkTransactions(ctx context.Context, own *memcachedUnixControlRun) error {
	if ctx == nil || ctx.Err() != nil {
		return core.ErrMemcachedUnixControl
	}
	base, err := geoJobDirectory(s.base, false)
	if errors.Is(err, os.ErrNotExist) {
		if own != nil {
			return core.ErrMemcachedUnixControl
		}
		return nil
	}
	if err != nil {
		return err
	}
	defer base.Close()
	info, err := base.Stat(".")
	if err != nil || !memcachedUnixJournalRootInfo(info) {
		return core.ErrMemcachedUnixControl
	}
	file, err := base.OpenFile("store.lock", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	identity, err := file.Stat()
	if err != nil || !memcachedUnixJournalHeld(base.Root, "store.lock", file, identity) || unix.Flock(int(file.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
		return core.ErrMemcachedUnixControl
	}
	before, err := memcachedUnixControlInventory(base)
	if err != nil {
		return err
	}
	originals := map[string]*memcachedUnixProjectOriginal{}
	defer func() {
		for _, p := range originals {
			p.Close()
		}
	}()
	for id := range before {
		if id == "store.lock" {
			continue
		}
		if ctx.Err() != nil {
			return core.ErrMemcachedUnixControl
		}
		if own != nil && own.lease.j.id == id {
			if s.base != memcachedUnixControlsRoot || own.current(ctx) != nil {
				return core.ErrMemcachedUnixControl
			}
			continue
		}
		j, err := s.open(id)
		if err != nil {
			return err
		}
		lease, err := holdMemcachedReadOnlyRun(j.d.root, j.current, func(info os.FileInfo) bool {
			return memcachedUnixJournalFileInfo(info, 0, true)
		})
		if err != nil {
			j.Close()
			return err
		}
		value, err := j.read()
		valid := err == nil && value.outcome() != nil && value.outcome().State != "unknown" && lease.current()
		if valid {
			project := value.Seed.Operation.ProjectID
			p := originals[project]
			if p == nil {
				p, err = openMemcachedUnixProjectOriginal(ctx, project)
				if err == nil {
					originals[project] = p
				}
			}
			valid = err == nil && memcachedUnixControlMatchesOriginal(value, p)
		}
		lease.Close()
		j.Close()
		if !valid {
			return core.ErrMemcachedUnixControl
		}
	}
	after, err := memcachedUnixControlInventory(base)
	if err != nil || len(before) != len(after) || !memcachedUnixJournalHeld(base.Root, "store.lock", file, identity) {
		return core.ErrMemcachedUnixControl
	}
	for name, info := range before {
		if !geoStoreStableInfo(info, after[name]) {
			return core.ErrMemcachedUnixControl
		}
	}
	for _, p := range originals {
		if p.current(ctx) != nil {
			return core.ErrMemcachedUnixControl
		}
	}
	if own != nil && own.current(ctx) != nil {
		return core.ErrMemcachedUnixControl
	}
	return ctx.Err()
}
