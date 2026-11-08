//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

const memcachedUnixInstallJobsRoot = "/var/lib/panel-executor/memcached-unix-installs"
const memcachedUnixInstallJobLimit = 128

var errMemcachedUnixJournal = errors.New("Memcached Socket 原安装事务、独占锁或完整事件不可核对；保留原证据，不重发")

func coreEncodeMemcachedUnixInstallRecord(record core.MemcachedUnixInstallRecord) ([]byte, error) {
	if core.ValidateMemcachedUnixInstallRecord(record) != nil {
		return nil, errMemcachedUnixJournal
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	decoded, err := core.DecodeMemcachedUnixInstallRecord(raw)
	if err != nil || decoded != record {
		return nil, errMemcachedUnixJournal
	}
	return raw, nil
}

// Independent evidence namespace, never the compat2 TCP update/recovery store.
// The explicit private path seam is only for trusted Root filesystem fixtures.
// No RPC/config/environment path or command runner is accepted by this store.
type memcachedUnixJournalStore struct{ base string }
type memcachedUnixJournal struct {
	d  *composeUpdateDirectory
	id string
}
type memcachedUnixJournalLease struct {
	j    *memcachedUnixJournal
	file *os.File
	info os.FileInfo
}

func (j *memcachedUnixJournal) Close() { j.d.Close() }
func (l *memcachedUnixJournalLease) Close() {
	if l != nil && l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}
func memcachedUnixJournalRootInfo(info os.FileInfo) bool {
	if info == nil || !moduleRecordInfo(info, true, false) {
		return false
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	return ok && value.Uid == 0 && value.Gid == 0
}
func memcachedUnixJournalFileInfo(info os.FileInfo, limit int64, empty bool) bool {
	if info == nil || !moduleRecordInfo(info, false, false) || info.Size() < 0 || info.Size() > limit || (info.Size() == 0) != empty {
		return false
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	return ok && value.Uid == 0 && value.Gid == 0
}
func (j *memcachedUnixJournal) current() bool {
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
func (s memcachedUnixJournalStore) open(id string) (*memcachedUnixJournal, error) {
	d, err := openComposeUpdateDirectory(s.base, id)
	if err != nil {
		return nil, err
	}
	j := &memcachedUnixJournal{d: d, id: id}
	if !j.current() {
		j.Close()
		return nil, errMemcachedUnixJournal
	}
	return j, nil
}
func memcachedUnixJournalLimit(name string) (int64, bool) {
	switch name {
	case "submission.json":
		return core.MaxMemcachedUnixInstallSubmissionBytes, true
	case "run.lock":
		return 0, true
	}
	for i := 0; i < core.MemcachedUnixInstallEvents; i++ {
		if name == fmt.Sprintf("event-%04d.json", i) {
			return core.MaxMemcachedUnixInstallRecordBytes, true
		}
	}
	return 0, false
}
func (j *memcachedUnixJournal) inventory() (map[string]os.FileInfo, error) {
	if !j.current() {
		return nil, errMemcachedUnixJournal
	}
	dir, err := j.d.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(core.MemcachedUnixInstallEvents + 3)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > core.MemcachedUnixInstallEvents+2 {
		return nil, errMemcachedUnixJournal
	}
	out := map[string]os.FileInfo{}
	for _, entry := range entries {
		limit, known := memcachedUnixJournalLimit(entry.Name())
		info, err := j.d.root.Lstat(entry.Name())
		if !known || err != nil || !memcachedUnixJournalFileInfo(info, limit, entry.Name() == "run.lock") {
			return nil, errMemcachedUnixJournal
		}
		out[entry.Name()] = info
	}
	for _, name := range []string{"submission.json", "run.lock", "event-0000.json"} {
		if out[name] == nil {
			return nil, errMemcachedUnixJournal
		}
	}
	return out, nil
}
func (j *memcachedUnixJournal) readChain() ([]core.MemcachedUnixInstallRecord, error) {
	before, err := j.inventory()
	if err != nil {
		return nil, err
	}
	raw, err := geoStoreRead(j.d.root, "submission.json", core.MaxMemcachedUnixInstallSubmissionBytes)
	if err != nil {
		return nil, err
	}
	submission, err := core.DecodeMemcachedUnixInstallSubmission(raw)
	if err != nil {
		return nil, err
	}
	first, err := core.NewMemcachedUnixInstallRecord(submission)
	if err != nil || first.Operation.JobID != j.id {
		return nil, errMemcachedUnixJournal
	}
	chain := []core.MemcachedUnixInstallRecord{}
	count := len(before) - 2
	if count < 1 || count > core.MemcachedUnixInstallEvents {
		return nil, errMemcachedUnixJournal
	}
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("event-%04d.json", i)
		if before[name] == nil {
			return nil, errMemcachedUnixJournal
		}
		event, err := geoStoreRead(j.d.root, name, core.MaxMemcachedUnixInstallRecordBytes)
		if err != nil {
			return nil, err
		}
		record, err := core.DecodeMemcachedUnixInstallRecord(event)
		if err != nil || i == 0 && record != first || i > 0 && core.ValidateMemcachedUnixInstallTransition(chain[i-1], record) != nil {
			return nil, errMemcachedUnixJournal
		}
		chain = append(chain, record)
	}
	after, err := j.inventory()
	if err != nil || len(after) != len(before) || !j.current() {
		return nil, errMemcachedUnixJournal
	}
	for name, info := range before {
		if !geoStoreStableInfo(info, after[name]) {
			return nil, errMemcachedUnixJournal
		}
	}
	return chain, nil
}
func (j *memcachedUnixJournal) read() (core.MemcachedUnixInstallRecord, error) {
	chain, err := j.readChain()
	if err != nil {
		return core.MemcachedUnixInstallRecord{}, err
	}
	return chain[len(chain)-1], nil
}

// Exclusive publication only. Existing files, partial writes, uncertain fsyncs
// and unexpected modes/owners are never deleted, truncated or repaired.
func memcachedUnixJournalWrite(root *os.Root, name string, raw []byte) error {
	limit, known := memcachedUnixJournalLimit(name)
	if name == "store.lock" {
		limit, known = 0, true
	}
	if !known || int64(len(raw)) > limit || (len(raw) == 0) != (name == "run.lock" || name == "store.lock") {
		return errMemcachedUnixJournal
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if file.Chown(0, 0) != nil || file.Chmod(0600) != nil {
		return errMemcachedUnixJournal
	}
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		return errMemcachedUnixJournal
	}
	if file.Sync() != nil || ruleFeedStoreSync(root) != nil {
		return errMemcachedUnixJournal
	}
	info, e1 := file.Stat()
	named, e2 := root.Lstat(name)
	if e1 != nil || e2 != nil || !memcachedUnixJournalFileInfo(info, limit, len(raw) == 0) || !geoStoreStableInfo(info, named) {
		return errMemcachedUnixJournal
	}
	return nil
}
func memcachedUnixJournalLock(root *os.Root, name string, create bool) (*os.File, error) {
	if name != "store.lock" && name != "run.lock" {
		return nil, errMemcachedUnixJournal
	}
	if create {
		if _, err := root.Lstat(name); errors.Is(err, os.ErrNotExist) {
			if err = memcachedUnixJournalWrite(root, name, nil); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
	}
	file, err := root.OpenFile(name, os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, e1 := file.Stat()
	named, e2 := root.Lstat(name)
	if e1 != nil || e2 != nil || !memcachedUnixJournalFileInfo(info, 0, true) || !geoStoreStableInfo(info, named) || unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		file.Close()
		return nil, errMemcachedUnixJournal
	}
	return file, nil
}
func memcachedUnixJournalHeld(root *os.Root, name string, file *os.File, expected os.FileInfo) bool {
	if file == nil {
		return false
	}
	info, e1 := file.Stat()
	named, e2 := root.Lstat(name)
	return e1 == nil && e2 == nil && memcachedUnixJournalFileInfo(info, 0, true) && geoStoreStableInfo(expected, info) && geoStoreStableInfo(expected, named)
}

// Framing-only persistence. Native admission MUST independently verify the
// compiled official key AND fresh exact Core reservation before calling this;
// no saved hash, sequence or canonical encoding grants Docker/account authority.
func (s memcachedUnixJournalStore) prepare(raw []byte) (core.MemcachedUnixInstallRecord, bool, error) {
	var empty core.MemcachedUnixInstallRecord
	raw = bytes.Clone(raw)
	submission, err := core.DecodeMemcachedUnixInstallSubmission(raw)
	if err != nil {
		return empty, false, err
	}
	first, err := core.NewMemcachedUnixInstallRecord(submission)
	if err != nil {
		return empty, false, err
	}
	anchor, err := memcachedUnixBaseAt(s.base, 0700)
	if err != nil {
		return empty, false, err
	}
	anchor.Close()
	base, err := geoJobDirectory(s.base, false)
	if err != nil {
		return empty, false, err
	}
	defer base.Close()
	info, err := base.Stat(".")
	if err != nil || !memcachedUnixJournalRootInfo(info) || !base.current() {
		return empty, false, errMemcachedUnixJournal
	}
	lock, err := memcachedUnixJournalLock(base.Root, "store.lock", true)
	if err != nil {
		return empty, false, err
	}
	defer lock.Close()
	identity, err := lock.Stat()
	if err != nil {
		return empty, false, err
	}
	dir, err := base.Open(".")
	if err != nil {
		return empty, false, err
	}
	entries, err := dir.ReadDir(memcachedUnixInstallJobLimit + 2)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > memcachedUnixInstallJobLimit+1 {
		return empty, false, errMemcachedUnixJournal
	}
	var retained *core.MemcachedUnixInstallRecord
	count := 0
	for _, entry := range entries {
		if entry.Name() == "store.lock" {
			continue
		}
		if !core.ValidID(entry.Name()) {
			return empty, false, errMemcachedUnixJournal
		}
		count++
		original, err := s.open(entry.Name())
		if err != nil {
			return empty, false, err
		}
		chain, err := original.readChain()
		original.Close()
		if err != nil {
			return empty, false, err
		}
		if chain[0].Operation.JobID == first.Operation.JobID {
			if chain[0] != first {
				return empty, false, errMemcachedUnixJournal
			}
			value := chain[len(chain)-1]
			retained = &value
		} else if chain[0].Operation.ProjectID == first.Operation.ProjectID {
			return empty, false, errMemcachedUnixJournal
		}
	}
	if !base.current() || !memcachedUnixJournalHeld(base.Root, "store.lock", lock, identity) {
		return empty, false, errMemcachedUnixJournal
	}
	if retained != nil {
		return *retained, false, nil
	}
	if count >= memcachedUnixInstallJobLimit {
		return empty, false, errMemcachedUnixJournal
	}
	id := first.Operation.JobID
	if base.Mkdir(id, 0700) != nil || ruleFeedStoreSync(base.Root) != nil {
		return empty, false, errMemcachedUnixJournal
	}
	// Only our newly exclusive private child receives fixed ownership.
	child, err := base.OpenRoot(id)
	if err != nil {
		return empty, false, err
	}
	file, err := child.Open(".")
	if err != nil {
		child.Close()
		return empty, false, err
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
		return empty, false, errMemcachedUnixJournal
	}
	j, err := s.open(id)
	if err != nil {
		return empty, false, err
	}
	defer j.Close()
	event, err := coreEncodeMemcachedUnixInstallRecord(first)
	if err != nil {
		return empty, false, err
	}
	for _, item := range []struct {
		name string
		raw  []byte
	}{{"submission.json", raw}, {"run.lock", nil}, {"event-0000.json", event}} {
		if !j.current() || !base.current() || !memcachedUnixJournalHeld(base.Root, "store.lock", lock, identity) {
			return empty, false, errMemcachedUnixJournal
		}
		if err = memcachedUnixJournalWrite(j.d.root, item.name, item.raw); err != nil {
			return empty, false, err
		}
	}
	read, err := j.read()
	if err != nil || read != first || !base.current() || !memcachedUnixJournalHeld(base.Root, "store.lock", lock, identity) {
		return empty, false, errMemcachedUnixJournal
	}
	return read, true, nil
}
func (j *memcachedUnixJournal) lease() (*memcachedUnixJournalLease, error) {
	if _, err := j.read(); err != nil {
		return nil, err
	}
	file, err := memcachedUnixJournalLock(j.d.root, "run.lock", false)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !j.current() {
		file.Close()
		return nil, errMemcachedUnixJournal
	}
	return &memcachedUnixJournalLease{j, file, info}, nil
}
func (l *memcachedUnixJournalLease) current() bool {
	return l != nil && l.j != nil && l.j.current() && memcachedUnixJournalHeld(l.j.d.root, "run.lock", l.file, l.info)
}
func (l *memcachedUnixJournalLease) append(after core.MemcachedUnixInstallRecord) error {
	if !l.current() {
		return errMemcachedUnixJournal
	}
	before, err := l.j.read()
	if err != nil || core.ValidateMemcachedUnixInstallTransition(before, after) != nil {
		return errMemcachedUnixJournal
	}
	raw, err := coreEncodeMemcachedUnixInstallRecord(after)
	if err != nil || !l.current() {
		return errMemcachedUnixJournal
	}
	if err = memcachedUnixJournalWrite(l.j.d.root, fmt.Sprintf("event-%04d.json", after.Sequence), raw); err != nil {
		return err
	}
	got, err := l.j.read()
	if err != nil || got != after || !l.current() {
		return errMemcachedUnixJournal
	}
	return nil
}
func (j *memcachedUnixJournal) officialAuthority(ctx context.Context) (appcatalog.MemcachedUnixReleaseAuthority, error) {
	var empty appcatalog.MemcachedUnixReleaseAuthority
	before, err := j.read()
	if err != nil {
		return empty, err
	}
	raw, err := geoStoreRead(j.d.root, "submission.json", core.MaxMemcachedUnixInstallSubmissionBytes)
	if err != nil || core.Hash(string(raw)) != before.SubmissionSHA256 {
		return empty, errMemcachedUnixJournal
	}
	in, err := core.DecodeMemcachedUnixInstallSubmission(raw)
	if err != nil {
		return empty, err
	}
	authority, err := appcatalog.VerifyMemcachedUnixReleaseEnvelope(ctx, in.Envelope, in.Binding.Version, in.Binding.ManifestSHA256)
	if err != nil || !authority.Matches(before.Binding.Version, before.Binding.ManifestSHA256) || authority.CatalogSHA256() != before.CatalogSHA256 {
		return empty, errMemcachedUnixJournal
	}
	after, err := j.read()
	if err != nil || after != before || !j.current() {
		return empty, errMemcachedUnixJournal
	}
	return authority, nil
}
