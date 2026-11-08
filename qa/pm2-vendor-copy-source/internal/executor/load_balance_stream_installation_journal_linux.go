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
	"syscall"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const loadBalanceStreamInstallationJobsRoot = "/var/lib/panel-executor/load-balance-stream-install-jobs"
const loadBalanceStreamInstallationSubmissionLimit = appcatalog.MaxMemcachedReleaseEnvelopeBytes

var errLoadBalanceStreamInstallationJournal = errors.New("TCP/UDP 原始私有事务文件、持有描述符或运行租约无法核对；保留原始结果，不重放或修复")

// Only a newly exclusive creator has append permission. An existing completed
// or incomplete journal can be read but NEVER reopened for mutation/recovery.
// Original actor/module/kernel authority and global leases remain mandatory in
// the forthcoming fixed controller; this private filesystem seam grants none.
type loadBalanceStreamInstallationJournal struct {
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

func (j *loadBalanceStreamInstallationJournal) current() bool {
	if j == nil || j.root == nil || threatIDSTrustedParents(filepath.Dir(j.path), false) != nil {
		return false
	}
	held, e1 := j.root.Stat(".")
	visible, e2 := os.Lstat(j.path)
	return e1 == nil && e2 == nil && memcachedUnixAdminDirectoryInfo(held) && memcachedUnixAdminDirectoryInfo(visible) &&
		geoStoreStableInfo(j.before, held) && geoStoreStableInfo(held, visible)
}

func (j *loadBalanceStreamInstallationJournal) close() error {
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

// Read-only existing-case opener. It cannot create paths, acquire an old run
// for mutation, remove stale state, adopt another directory or repair a mode.
func openLoadBalanceStreamInstallationJournalReadOnlyAt(path, request string) (*loadBalanceStreamInstallationJournal, error) {
	if !core.ValidID(request) {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	anchor, err := streamJournalAnchor(path)
	if err != nil {
		return nil, err
	}
	defer anchor.Close()
	root, err := anchor.OpenRoot(request)
	if err != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	before, err := root.Stat(".")
	j := &loadBalanceStreamInstallationJournal{root: root, path: filepath.Join(path, request), before: before}
	if err != nil || !j.current() {
		j.close()
		return nil, errLoadBalanceStreamInstallationJournal
	}
	return j, nil
}

func (j *loadBalanceStreamInstallationJournal) names() ([]string, error) {
	if !j.current() {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	dir, err := j.root.Open(".")
	if err != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	defer dir.Close()
	entries, err := dir.ReadDir(10)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 9 {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	found, names := map[string]bool{}, []string{}
	for _, entry := range entries {
		name := entry.Name()
		if name != "seed.json" && name != "run.lock" && name != "submission.json" && !streamJournalEventName.MatchString(name) || found[name] {
			return nil, errLoadBalanceStreamInstallationJournal
		}
		found[name] = true
		limit := int64(2048)
		if name == "seed.json" {
			limit = loadbalancestream.MaxInstallationSeedBytes
		} else if name == "submission.json" {
			limit = loadBalanceStreamInstallationSubmissionLimit
		} else if name == "run.lock" {
			limit = 0
		}
		info, err := j.root.Lstat(name)
		if err != nil || !streamJournalFileInfo(info, limit) {
			return nil, errLoadBalanceStreamInstallationJournal
		}
		names = append(names, name)
	}
	if !j.current() {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	return names, nil
}

type streamHeldInstallationJournalFile struct {
	j      *loadBalanceStreamInstallationJournal
	name   string
	file   *os.File
	before os.FileInfo
	raw    []byte
}

func (f *streamHeldInstallationJournalFile) current() bool {
	if f == nil || f.file == nil || !f.j.current() {
		return false
	}
	held, e1 := f.file.Stat()
	visible, e2 := f.j.root.Lstat(f.name)
	return e1 == nil && e2 == nil && geoStoreStableInfo(f.before, held) && geoStoreStableInfo(held, visible)
}
func (f *streamHeldInstallationJournalFile) close() { clear(f.raw); f.file.Close() }

func (j *loadBalanceStreamInstallationJournal) read(name string, limit int64) (*streamHeldInstallationJournalFile, error) {
	expected := int64(2048)
	if name == "seed.json" {
		expected = loadbalancestream.MaxInstallationSeedBytes
	} else if name == "submission.json" {
		expected = loadBalanceStreamInstallationSubmissionLimit
	} else if name == "run.lock" {
		expected = 0
	} else if !streamJournalEventName.MatchString(name) {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	if limit != expected || !j.current() {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	file, err := j.root.OpenFile(name, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	before, err := file.Stat()
	if err != nil || !streamJournalFileInfo(before, limit) {
		file.Close()
		return nil, errLoadBalanceStreamInstallationJournal
	}
	held := &streamHeldInstallationJournalFile{j: j, name: name, file: file, before: before}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != before.Size() || !held.current() {
		file.Close()
		return nil, errLoadBalanceStreamInstallationJournal
	}
	held.raw = raw
	return held, nil
}

func (j *loadBalanceStreamInstallationJournal) original(ctx context.Context) ([]byte, [][]byte, loadbalancestream.InstallationChain, error) {
	empty := loadbalancestream.InstallationChain{}
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	names, err := j.names()
	if err != nil || len(names) < 4 {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	found := map[string]bool{}
	for _, name := range names {
		found[name] = true
	}
	if !found["seed.json"] || !found["run.lock"] || !found["submission.json"] {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	seed, err := j.read("seed.json", loadbalancestream.MaxInstallationSeedBytes)
	if err != nil {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	defer seed.close()
	lock, err := j.read("run.lock", 0)
	if err != nil {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	defer lock.close()
	if j.creator {
		owned, err := j.lock.Stat()
		if err != nil || !geoStoreStableInfo(owned, lock.before) || len(names) != len(j.owned) || !geoStoreStableInfo(j.owned["seed.json"], seed.before) || !geoStoreStableInfo(j.owned["run.lock"], lock.before) {
			return nil, nil, empty, errLoadBalanceStreamInstallationJournal
		}
	}
	decodedSeed, err := loadbalancestream.DecodeInstallationSeed(seed.raw)
	if err != nil || decodedSeed.JobID != filepath.Base(j.path) {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	submission, err := j.read("submission.json", loadBalanceStreamInstallationSubmissionLimit)
	if err != nil {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	defer submission.close()
	if core.Hash(string(submission.raw)) != decodedSeed.SubmissionSHA256 {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	if _, err := appcatalog.DecodeLoadBalanceStreamReleaseEnvelope(submission.raw); err != nil {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	if j.creator && !geoStoreStableInfo(j.owned["submission.json"], submission.before) {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	if len(j.seed) > 0 && !bytes.Equal(seed.raw, j.seed) {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	records := make([][]byte, 0, len(names)-3)
	var holds []*streamHeldInstallationJournalFile
	defer func() {
		for _, held := range holds {
			held.close()
		}
	}()
	for sequence := 0; sequence < len(names)-3; sequence++ {
		if ctx.Err() != nil {
			return nil, nil, empty, errLoadBalanceStreamInstallationJournal
		}
		name := fmt.Sprintf("event-%04d.json", sequence)
		if !found[name] {
			return nil, nil, empty, errLoadBalanceStreamInstallationJournal
		}
		held, err := j.read(name, 2048)
		if err != nil {
			return nil, nil, empty, errLoadBalanceStreamInstallationJournal
		}
		holds = append(holds, held)
		if j.creator && !geoStoreStableInfo(j.owned[name], held.before) {
			return nil, nil, empty, errLoadBalanceStreamInstallationJournal
		}
		records = append(records, bytes.Clone(held.raw))
	}
	if j.creator {
		if len(records) != len(j.records) {
			return nil, nil, empty, errLoadBalanceStreamInstallationJournal
		}
		for i := range records {
			if !bytes.Equal(records[i], j.records[i]) {
				return nil, nil, empty, errLoadBalanceStreamInstallationJournal
			}
		}
	}
	chain, err := loadbalancestream.DecodeInstallationChain(seed.raw, records)
	if err != nil || ctx.Err() != nil || !seed.current() || !lock.current() || !submission.current() {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	for _, held := range holds {
		if !held.current() {
			return nil, nil, empty, errLoadBalanceStreamInstallationJournal
		}
	}
	finalNames, err := j.names()
	if err != nil || len(finalNames) != len(names) {
		return nil, nil, empty, errLoadBalanceStreamInstallationJournal
	}
	for _, name := range finalNames {
		if !found[name] {
			return nil, nil, empty, errLoadBalanceStreamInstallationJournal
		}
	}
	return bytes.Clone(seed.raw), records, chain, nil
}

// Every write is exclusive and durable. Unknown/partial bytes remain in place;
// no deletion, retry, permissions repair or existing record overwrite exists.
func (j *loadBalanceStreamInstallationJournal) writeNew(name string, raw []byte) error {
	if !j.creator || j.lock == nil || !j.current() {
		return errLoadBalanceStreamInstallationJournal
	}
	if name != "seed.json" && name != "submission.json" && !streamJournalEventName.MatchString(name) || len(raw) == 0 {
		return errLoadBalanceStreamInstallationJournal
	}
	limit := 2048
	if name == "seed.json" {
		limit = loadbalancestream.MaxInstallationSeedBytes
	} else if name == "submission.json" {
		limit = loadBalanceStreamInstallationSubmissionLimit
	}
	if len(raw) > limit {
		return errLoadBalanceStreamInstallationJournal
	}
	before := j.before
	file, err := j.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	defer file.Close()
	if file.Chown(0, 0) != nil || file.Chmod(0600) != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		return errLoadBalanceStreamInstallationJournal
	}
	if file.Sync() != nil || ruleFeedStoreSync(j.root) != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	held, e1 := file.Stat()
	visible, e2 := j.root.Lstat(name)
	if e1 != nil || e2 != nil || !streamJournalFileInfo(held, int64(limit)) || !geoStoreStableInfo(held, visible) {
		return errLoadBalanceStreamInstallationJournal
	}
	now, err := j.root.Stat(".")
	if err != nil || !memcachedUnixAdminDirectoryInfo(now) || !os.SameFile(before, now) {
		return errLoadBalanceStreamInstallationJournal
	}
	j.before = now
	j.owned[name] = held
	_, err = j.names()
	return err
}

func (j *loadBalanceStreamInstallationJournal) appendOriginal(ctx context.Context, evidence loadbalancestream.InstallationEvidence) error {
	if j == nil || !j.creator || j.unknown || j.lock == nil || ctx == nil || ctx.Err() != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	seed, records, chain, err := j.original(ctx)
	if err != nil || chain.Complete {
		return errLoadBalanceStreamInstallationJournal
	}
	next, err := loadbalancestream.NextInstallationEvent(seed, records, evidence)
	if err != nil || ctx.Err() != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	j.unknown = true
	if err := j.writeNew(fmt.Sprintf("event-%04d.json", len(records)), next); err != nil {
		return err
	}
	j.records = append(j.records, bytes.Clone(next))
	currentSeed, currentRecords, _, err := j.original(ctx)
	if err != nil || !bytes.Equal(currentSeed, seed) || len(currentRecords) != len(records)+1 || !bytes.Equal(currentRecords[len(records)], next) {
		return errLoadBalanceStreamInstallationJournal
	}
	for i := range records {
		if !bytes.Equal(currentRecords[i], records[i]) {
			return errLoadBalanceStreamInstallationJournal
		}
	}
	j.unknown = false
	return nil
}

// Private fixed-controller filesystem seam only. The production caller must
// select loadBalanceStreamInstallationJobsRoot, independently authorize the original Core
// operation, hold global leases and recheck live authority before calling it.
// This never initializes/repairs an anchor or adopts an existing request ID.
func createLoadBalanceStreamInstallationJournalAt(ctx context.Context, path string, seedRaw, submissionRaw []byte) (*loadBalanceStreamInstallationJournal, error) {
	seed, err := loadbalancestream.DecodeInstallationSeed(seedRaw)
	if ctx == nil || ctx.Err() != nil || err != nil || os.Getegid() != 0 {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	if len(submissionRaw) == 0 || len(submissionRaw) > loadBalanceStreamInstallationSubmissionLimit || core.Hash(string(submissionRaw)) != seed.SubmissionSHA256 {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	if _, err := appcatalog.DecodeLoadBalanceStreamReleaseEnvelope(submissionRaw); err != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	anchor, err := streamJournalAnchor(path)
	if err != nil {
		return nil, err
	}
	defer anchor.Close()
	// Bounded retained inventory; no automatic pruning or old-case adoption.
	dir, err := anchor.Open(".")
	if err != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	entries, readErr := dir.ReadDir(129)
	dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) >= 128 {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	for _, entry := range entries {
		if !core.ValidID(entry.Name()) || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, errLoadBalanceStreamInstallationJournal
		}
		info, err := anchor.Lstat(entry.Name())
		if err != nil || !memcachedUnixAdminDirectoryInfo(info) {
			return nil, errLoadBalanceStreamInstallationJournal
		}
	}
	request := seed.JobID
	if ctx.Err() != nil || anchor.Mkdir(request, 0700) != nil || ruleFeedStoreSync(anchor) != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	root, err := anchor.OpenRoot(request)
	if err != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	before, err := root.Stat(".")
	j := &loadBalanceStreamInstallationJournal{root: root, path: filepath.Join(path, request), before: before, creator: true, owned: map[string]os.FileInfo{}}
	fail := func() (*loadBalanceStreamInstallationJournal, error) {
		j.close()
		return nil, errLoadBalanceStreamInstallationJournal
	}
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
	if ctx.Err() != nil || j.writeNew("submission.json", submissionRaw) != nil {
		return fail()
	}
	j.seed = bytes.Clone(seedRaw)
	prepared, err := loadbalancestream.NextInstallationEvent(seedRaw, nil, loadbalancestream.InstallationEvidence{})
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

// Offline signed metadata is an independent prerequisite, NEVER the Core grant,
// original parent run lease, account ownership or permission to execute an effect.
func (j *loadBalanceStreamInstallationJournal) officialAuthority(ctx context.Context) (appcatalog.LoadBalanceStreamReleaseAuthority, error) {
	var empty appcatalog.LoadBalanceStreamReleaseAuthority
	seedRaw, _, _, err := j.original(ctx)
	if err != nil {
		return empty, err
	}
	seed, err := loadbalancestream.DecodeInstallationSeed(seedRaw)
	if err != nil {
		return empty, err
	}
	submission, err := j.read("submission.json", loadBalanceStreamInstallationSubmissionLimit)
	if err != nil {
		return empty, err
	}
	defer submission.close()
	if core.Hash(string(submission.raw)) != seed.SubmissionSHA256 {
		return empty, errLoadBalanceStreamInstallationJournal
	}
	envelope, err := appcatalog.DecodeLoadBalanceStreamReleaseEnvelope(submission.raw)
	if err != nil {
		return empty, err
	}
	authority, err := appcatalog.VerifyLoadBalanceStreamReleaseEnvelope(ctx, envelope, seed.AppVersion, seed.ManifestSHA256)
	if err != nil || !authority.Matches(seed.AppVersion, seed.ManifestSHA256) || authority.CatalogSHA256() != seed.CatalogSHA256 || !submission.current() {
		return empty, errLoadBalanceStreamInstallationJournal
	}
	after, _, _, err := j.original(ctx)
	if err != nil || !bytes.Equal(seedRaw, after) {
		return empty, errLoadBalanceStreamInstallationJournal
	}
	return authority, nil
}
