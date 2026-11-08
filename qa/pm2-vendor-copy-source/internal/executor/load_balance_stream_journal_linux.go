//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const loadBalanceStreamJobsRoot = "/var/lib/panel-executor/load-balance-stream-jobs"

var errLoadBalanceStreamJournal = errors.New("TCP/UDP 原始私有事务文件、持有描述符或运行租约无法核对；保留原始结果，不重放或修复")
var streamJournalEventName = regexp.MustCompile(`^event-[0-9]{4}\.json$`)

// Only a newly exclusive creator has append permission. An existing completed
// or incomplete journal can be read but NEVER reopened for mutation/recovery.
// Original actor/module/kernel authority and global leases remain mandatory in
// the forthcoming fixed controller; this private filesystem seam grants none.
type loadBalanceStreamJournal struct {
	root    *os.Root
	path    string
	before  os.FileInfo
	lock    *os.File
	seed    []byte
	creator bool
	owned   map[string]os.FileInfo
	records [][]byte
	unknown bool
}

func streamJournalFileInfo(info os.FileInfo, limit int64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 0 || info.Size() > limit ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	return ok && value.Uid == 0 && value.Gid == 0 && value.Nlink == 1
}

func (j *loadBalanceStreamJournal) current() bool {
	if j == nil || j.root == nil || threatIDSTrustedParents(filepath.Dir(j.path), false) != nil {
		return false
	}
	held, e1 := j.root.Stat(".")
	visible, e2 := os.Lstat(j.path)
	return e1 == nil && e2 == nil && memcachedUnixAdminDirectoryInfo(held) && memcachedUnixAdminDirectoryInfo(visible) &&
		geoStoreStableInfo(j.before, held) && geoStoreStableInfo(held, visible)
}

func (j *loadBalanceStreamJournal) close() error {
	if j == nil {
		return nil
	}
	clear(j.seed)
	j.creator = false
	if j.lock != nil {
		j.lock.Close()
		j.lock = nil
	}
	if j.root != nil {
		err := j.root.Close()
		j.root = nil
		return err
	}
	return nil
}

func streamJournalAnchor(path string) (*os.Root, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || threatIDSTrustedParents(path, false) != nil {
		return nil, errLoadBalanceStreamJournal
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errLoadBalanceStreamJournal
	}
	held, e1 := root.Stat(".")
	visible, e2 := os.Lstat(path)
	if e1 != nil || e2 != nil || !memcachedUnixAdminDirectoryInfo(held) || !memcachedUnixAdminDirectoryInfo(visible) || !geoStoreStableInfo(held, visible) {
		root.Close()
		return nil, errLoadBalanceStreamJournal
	}
	return root, nil
}

// Read-only existing-case opener. It cannot create paths, acquire an old run
// for mutation, remove stale state, adopt another directory or repair a mode.
func openLoadBalanceStreamJournalReadOnlyAt(path, request string) (*loadBalanceStreamJournal, error) {
	if !core.ValidID(request) {
		return nil, errLoadBalanceStreamJournal
	}
	anchor, err := streamJournalAnchor(path)
	if err != nil {
		return nil, err
	}
	defer anchor.Close()
	root, err := anchor.OpenRoot(request)
	if err != nil {
		return nil, errLoadBalanceStreamJournal
	}
	before, err := root.Stat(".")
	j := &loadBalanceStreamJournal{root: root, path: filepath.Join(path, request), before: before}
	if err != nil || !j.current() {
		j.close()
		return nil, errLoadBalanceStreamJournal
	}
	return j, nil
}

func (j *loadBalanceStreamJournal) names() ([]string, error) {
	if !j.current() {
		return nil, errLoadBalanceStreamJournal
	}
	dir, err := j.root.Open(".")
	if err != nil {
		return nil, errLoadBalanceStreamJournal
	}
	defer dir.Close()
	entries, err := dir.ReadDir(15)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 14 {
		return nil, errLoadBalanceStreamJournal
	}
	found, names := map[string]bool{}, []string{}
	for _, entry := range entries {
		name := entry.Name()
		if name != "seed.json" && name != "run.lock" && !streamJournalEventName.MatchString(name) || found[name] {
			return nil, errLoadBalanceStreamJournal
		}
		found[name] = true
		limit := int64(2048)
		if name == "seed.json" {
			limit = loadbalancestream.MaxControlSeedBytes
		} else if name == "run.lock" {
			limit = 0
		}
		info, err := j.root.Lstat(name)
		if err != nil || !streamJournalFileInfo(info, limit) {
			return nil, errLoadBalanceStreamJournal
		}
		names = append(names, name)
	}
	if !j.current() {
		return nil, errLoadBalanceStreamJournal
	}
	return names, nil
}

type streamHeldJournalFile struct {
	j      *loadBalanceStreamJournal
	name   string
	file   *os.File
	before os.FileInfo
	raw    []byte
}

func (f *streamHeldJournalFile) current() bool {
	if f == nil || f.file == nil || !f.j.current() {
		return false
	}
	held, e1 := f.file.Stat()
	visible, e2 := f.j.root.Lstat(f.name)
	return e1 == nil && e2 == nil && geoStoreStableInfo(f.before, held) && geoStoreStableInfo(held, visible)
}
func (f *streamHeldJournalFile) close() { clear(f.raw); f.file.Close() }

func (j *loadBalanceStreamJournal) read(name string, limit int64) (*streamHeldJournalFile, error) {
	expected := int64(2048)
	if name == "seed.json" {
		expected = loadbalancestream.MaxControlSeedBytes
	} else if name == "run.lock" {
		expected = 0
	} else if !streamJournalEventName.MatchString(name) {
		return nil, errLoadBalanceStreamJournal
	}
	if limit != expected || !j.current() {
		return nil, errLoadBalanceStreamJournal
	}
	file, err := j.root.OpenFile(name, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errLoadBalanceStreamJournal
	}
	before, err := file.Stat()
	if err != nil || !streamJournalFileInfo(before, limit) {
		file.Close()
		return nil, errLoadBalanceStreamJournal
	}
	held := &streamHeldJournalFile{j: j, name: name, file: file, before: before}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != before.Size() || !held.current() {
		file.Close()
		return nil, errLoadBalanceStreamJournal
	}
	held.raw = raw
	return held, nil
}

func (j *loadBalanceStreamJournal) original(ctx context.Context) ([]byte, [][]byte, loadbalancestream.ControlChain, error) {
	empty := loadbalancestream.ControlChain{}
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, empty, errLoadBalanceStreamJournal
	}
	names, err := j.names()
	if err != nil || len(names) < 3 {
		return nil, nil, empty, errLoadBalanceStreamJournal
	}
	found := map[string]bool{}
	for _, name := range names {
		found[name] = true
	}
	if !found["seed.json"] || !found["run.lock"] {
		return nil, nil, empty, errLoadBalanceStreamJournal
	}
	seed, err := j.read("seed.json", loadbalancestream.MaxControlSeedBytes)
	if err != nil {
		return nil, nil, empty, errLoadBalanceStreamJournal
	}
	defer seed.close()
	lock, err := j.read("run.lock", 0)
	if err != nil {
		return nil, nil, empty, errLoadBalanceStreamJournal
	}
	defer lock.close()
	if j.creator {
		owned, err := j.lock.Stat()
		if err != nil || !geoStoreStableInfo(owned, lock.before) || len(names) != len(j.owned) || !geoStoreStableInfo(j.owned["seed.json"], seed.before) || !geoStoreStableInfo(j.owned["run.lock"], lock.before) {
			return nil, nil, empty, errLoadBalanceStreamJournal
		}
	}
	decodedSeed, err := loadbalancestream.DecodeControlSeed(seed.raw)
	if err != nil || decodedSeed.Operation.RequestID != filepath.Base(j.path) {
		return nil, nil, empty, errLoadBalanceStreamJournal
	}
	if len(j.seed) > 0 && !bytes.Equal(seed.raw, j.seed) {
		return nil, nil, empty, errLoadBalanceStreamJournal
	}
	records := make([][]byte, 0, len(names)-2)
	var holds []*streamHeldJournalFile
	defer func() {
		for _, held := range holds {
			held.close()
		}
	}()
	for sequence := 0; sequence < len(names)-2; sequence++ {
		if ctx.Err() != nil {
			return nil, nil, empty, errLoadBalanceStreamJournal
		}
		name := fmt.Sprintf("event-%04d.json", sequence)
		if !found[name] {
			return nil, nil, empty, errLoadBalanceStreamJournal
		}
		held, err := j.read(name, 2048)
		if err != nil {
			return nil, nil, empty, errLoadBalanceStreamJournal
		}
		holds = append(holds, held)
		if j.creator && !geoStoreStableInfo(j.owned[name], held.before) {
			return nil, nil, empty, errLoadBalanceStreamJournal
		}
		records = append(records, bytes.Clone(held.raw))
	}
	if j.creator {
		if len(records) != len(j.records) {
			return nil, nil, empty, errLoadBalanceStreamJournal
		}
		for i := range records {
			if !bytes.Equal(records[i], j.records[i]) {
				return nil, nil, empty, errLoadBalanceStreamJournal
			}
		}
	}
	chain, err := loadbalancestream.DecodeControlChain(seed.raw, records)
	if err != nil || ctx.Err() != nil || !seed.current() || !lock.current() {
		return nil, nil, empty, errLoadBalanceStreamJournal
	}
	for _, held := range holds {
		if !held.current() {
			return nil, nil, empty, errLoadBalanceStreamJournal
		}
	}
	finalNames, err := j.names()
	if err != nil || len(finalNames) != len(names) {
		return nil, nil, empty, errLoadBalanceStreamJournal
	}
	for _, name := range finalNames {
		if !found[name] {
			return nil, nil, empty, errLoadBalanceStreamJournal
		}
	}
	return bytes.Clone(seed.raw), records, chain, nil
}

// Every write is exclusive and durable. Unknown/partial bytes remain in place;
// no deletion, retry, permissions repair or existing record overwrite exists.
func (j *loadBalanceStreamJournal) writeNew(name string, raw []byte) error {
	if !j.creator || j.lock == nil || !j.current() {
		return errLoadBalanceStreamJournal
	}
	if name != "seed.json" && !streamJournalEventName.MatchString(name) || len(raw) == 0 {
		return errLoadBalanceStreamJournal
	}
	limit := 2048
	if name == "seed.json" {
		limit = loadbalancestream.MaxControlSeedBytes
	}
	if len(raw) > limit {
		return errLoadBalanceStreamJournal
	}
	before := j.before
	file, err := j.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return errLoadBalanceStreamJournal
	}
	defer file.Close()
	if file.Chown(0, 0) != nil || file.Chmod(0600) != nil {
		return errLoadBalanceStreamJournal
	}
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		return errLoadBalanceStreamJournal
	}
	if file.Sync() != nil || ruleFeedStoreSync(j.root) != nil {
		return errLoadBalanceStreamJournal
	}
	held, e1 := file.Stat()
	visible, e2 := j.root.Lstat(name)
	if e1 != nil || e2 != nil || !streamJournalFileInfo(held, int64(limit)) || !geoStoreStableInfo(held, visible) {
		return errLoadBalanceStreamJournal
	}
	now, err := j.root.Stat(".")
	if err != nil || !memcachedUnixAdminDirectoryInfo(now) || !os.SameFile(before, now) {
		return errLoadBalanceStreamJournal
	}
	j.before = now
	j.owned[name] = held
	_, err = j.names()
	return err
}

func (j *loadBalanceStreamJournal) appendOriginal(ctx context.Context, evidence loadbalancestream.ControlAdvanceEvidence) error {
	if j == nil || !j.creator || j.unknown || j.lock == nil || ctx == nil || ctx.Err() != nil {
		return errLoadBalanceStreamJournal
	}
	seed, records, chain, err := j.original(ctx)
	if err != nil || chain.Complete {
		return errLoadBalanceStreamJournal
	}
	next, err := loadbalancestream.NextControlEvent(seed, records, evidence)
	if err != nil || ctx.Err() != nil {
		return errLoadBalanceStreamJournal
	}
	j.unknown = true
	if err := j.writeNew(fmt.Sprintf("event-%04d.json", len(records)), next); err != nil {
		return err
	}
	j.records = append(j.records, bytes.Clone(next))
	currentSeed, currentRecords, _, err := j.original(ctx)
	if err != nil || !bytes.Equal(currentSeed, seed) || len(currentRecords) != len(records)+1 || !bytes.Equal(currentRecords[len(records)], next) {
		return errLoadBalanceStreamJournal
	}
	for i := range records {
		if !bytes.Equal(currentRecords[i], records[i]) {
			return errLoadBalanceStreamJournal
		}
	}
	j.unknown = false
	return nil
}

// Private fixed-controller filesystem seam only. The production caller must
// select loadBalanceStreamJobsRoot, independently authorize the original Core
// operation, hold global leases and recheck live authority before calling it.
// This never initializes/repairs an anchor or adopts an existing request ID.
func createLoadBalanceStreamJournalAt(ctx context.Context, path string, seedRaw []byte) (*loadBalanceStreamJournal, error) {
	seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
	if ctx == nil || ctx.Err() != nil || err != nil || os.Geteuid() != 0 {
		return nil, errLoadBalanceStreamJournal
	}
	anchor, err := streamJournalAnchor(path)
	if err != nil {
		return nil, err
	}
	defer anchor.Close()
	// Bounded retained inventory; no automatic pruning or old-case adoption.
	dir, err := anchor.Open(".")
	if err != nil {
		return nil, errLoadBalanceStreamJournal
	}
	entries, readErr := dir.ReadDir(129)
	dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) >= 128 {
		return nil, errLoadBalanceStreamJournal
	}
	for _, entry := range entries {
		if !core.ValidID(entry.Name()) || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, errLoadBalanceStreamJournal
		}
		info, err := anchor.Lstat(entry.Name())
		if err != nil || !memcachedUnixAdminDirectoryInfo(info) {
			return nil, errLoadBalanceStreamJournal
		}
	}
	request := seed.Operation.RequestID
	if ctx.Err() != nil || createStreamRootPrivateDirectory(anchor, request) != nil {
		return nil, errLoadBalanceStreamJournal
	}
	root, err := anchor.OpenRoot(request)
	if err != nil {
		return nil, errLoadBalanceStreamJournal
	}
	before, err := root.Stat(".")
	j := &loadBalanceStreamJournal{root: root, path: filepath.Join(path, request), before: before, creator: true, owned: map[string]os.FileInfo{}}
	fail := func() (*loadBalanceStreamJournal, error) { j.close(); return nil, errLoadBalanceStreamJournal }
	if err != nil || !j.current() {
		return fail()
	}
	lock, err := root.OpenFile("run.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return fail()
	}
	j.lock = lock
	if lock.Chown(0, 0) != nil || lock.Chmod(0600) != nil || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil || lock.Sync() != nil || ruleFeedStoreSync(root) != nil {
		return fail()
	}
	lockInfo, e1 := lock.Stat()
	lockVisible, e2 := root.Lstat("run.lock")
	now, e3 := root.Stat(".")
	if e1 != nil || e2 != nil || e3 != nil || !streamJournalFileInfo(lockInfo, 0) || !geoStoreStableInfo(lockInfo, lockVisible) || !os.SameFile(before, now) || !memcachedUnixAdminDirectoryInfo(now) {
		return fail()
	}
	j.before = now
	j.owned["run.lock"] = lockInfo
	if ctx.Err() != nil || j.writeNew("seed.json", seedRaw) != nil {
		return fail()
	}
	j.seed = bytes.Clone(seedRaw)
	prepared, err := loadbalancestream.NextControlEvent(seedRaw, nil, loadbalancestream.ControlAdvanceEvidence{})
	if err != nil || ctx.Err() != nil || j.writeNew("event-0000.json", prepared) != nil {
		return fail()
	}
	j.records = [][]byte{bytes.Clone(prepared)}
	_, _, chain, err := j.original(ctx)
	if err != nil || chain.Complete || !chain.OriginalUnknown || len(chain.Events) != 1 {
		return fail()
	}
	return j, nil
}
