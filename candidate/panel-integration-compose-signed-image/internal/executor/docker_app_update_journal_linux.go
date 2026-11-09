//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

const memcachedUpdateJobsRoot = "/var/lib/panel-executor/memcached-app-updates"
const memcachedUpdateJobLimit = 128

// Unexported path/fault seam is for trusted-root filesystem fixtures only.
// Future production admission/worker routes must use memcachedUpdateJobsRoot,
// independently verify the official envelope and fresh live project, and hold
// the original run lease before Docker effects. This store by itself only
// preserves evidence; it does not authorize or perform Docker operations.
type memcachedUpdateJournalStore struct {
	base  string
	fault func(string) error
}

type memcachedUpdateJournal struct {
	d     *composeUpdateDirectory
	id    string
	fault func(string) error
}

type memcachedUpdateJournalLease struct {
	j        *memcachedUpdateJournal
	file     *os.File
	identity os.FileInfo
}

type memcachedUpdateJournalSeed struct {
	Record           core.MemcachedUpdateRecord
	Envelope         []byte
	OriginalCompose  []byte
	OriginalMetadata []byte
}

func (j *memcachedUpdateJournal) Close() { j.d.Close() }
func (l *memcachedUpdateJournalLease) Close() {
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}

func memcachedUpdateSeedValid(in memcachedUpdateJournalSeed) error {
	bad := errors.New("Memcached 原事务交付或回滚副本绑定无效，未改写项目")
	r := in.Record
	if core.ValidateMemcachedUpdateRecord(r) != nil || r.Phase != "prepared" || r.Sequence != 0 ||
		len(in.OriginalCompose) == 0 || len(in.OriginalCompose) > 48<<10 || len(in.OriginalMetadata) == 0 || len(in.OriginalMetadata) > 16<<10 ||
		core.Hash(string(in.OriginalCompose)) != r.Plan.ComposeSHA256 || core.Hash(string(in.OriginalMetadata)) != r.Plan.MetadataSHA256 || core.Hash(string(in.Envelope)) != r.EnvelopeSHA256 {
		return bad
	}
	envelope, err := appcatalog.DecodeMemcachedReleaseEnvelope(in.Envelope)
	if err != nil || core.Hash(string(envelope.Catalog)) != r.CatalogSHA256 || core.Hash(string(envelope.AppManifest)) != r.Dispatch.Input.ExpectedSHA256 {
		return bad
	}
	m, err := decodeComposeUpdateMetadata(in.OriginalMetadata, r.Dispatch.ProjectID)
	if err != nil {
		return bad
	}
	plan, err := core.MemcachedComposeUpdatePlan(m.ID, core.Hash(string(in.OriginalMetadata)), in.OriginalCompose, m.HostPort, r.Plan.ContainerID, r.Plan.RuntimeImageID, r.Plan.RuntimeConfigSHA256)
	if err != nil || plan != r.Plan {
		return bad
	}
	return nil
}

func (s memcachedUpdateJournalStore) open(id string) (*memcachedUpdateJournal, error) {
	d, err := openComposeUpdateDirectory(s.base, id)
	if err != nil {
		return nil, err
	}
	return &memcachedUpdateJournal{d: d, id: id, fault: s.fault}, nil
}

func memcachedUpdateFileLimit(name string) (int64, bool) {
	switch name {
	case "envelope.json":
		return appcatalog.MaxMemcachedReleaseEnvelopeBytes, true
	case "compose.original.yaml":
		return 48 << 10, true
	case "metadata.original.json":
		return 16 << 10, true
	case "run.lock":
		return 0, true
	case "image-retention.intent.json", "image-retention.receipt.json":
		return 4096, true
	}
	for i := 0; i < core.MemcachedUpdateJournalEvents; i++ {
		if name == fmt.Sprintf("event-%04d.json", i) {
			return core.MaxMemcachedUpdateRecordBytes, true
		}
	}
	return 0, false
}

func (j *memcachedUpdateJournal) inventory() (map[string]os.FileInfo, error) {
	bad := errors.New("Memcached 原事务目录含未知、超限或不受信成员")
	if !j.d.current() {
		return nil, bad
	}
	dir, err := j.d.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := dir.ReadDir(core.MemcachedUpdateJournalEvents + 7)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > core.MemcachedUpdateJournalEvents+6 {
		return nil, bad
	}
	files := map[string]os.FileInfo{}
	for _, entry := range entries {
		limit, known := memcachedUpdateFileLimit(entry.Name())
		info, err := j.d.root.Lstat(entry.Name())
		if !known || err != nil || !moduleRecordInfo(info, false, false) || info.Size() > limit || entry.Name() != "run.lock" && info.Size() == 0 || entry.Name() == "run.lock" && info.Size() != 0 {
			return nil, bad
		}
		files[entry.Name()] = info
	}
	for _, name := range []string{"envelope.json", "compose.original.yaml", "metadata.original.json", "run.lock", "event-0000.json"} {
		if files[name] == nil {
			return nil, bad
		}
	}
	return files, nil
}

// Reads never create or repair a lock/file and never infer a missing/invalid
// event to mean "fresh request". Contiguous complete canonical events only.
func (j *memcachedUpdateJournal) readChain() ([]core.MemcachedUpdateRecord, error) {
	var empty []core.MemcachedUpdateRecord
	before, err := j.inventory()
	if err != nil {
		return empty, err
	}
	names := []string{}
	for name := range before {
		if strings.HasPrefix(name, "event-") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var first, previous core.MemcachedUpdateRecord
	chain := []core.MemcachedUpdateRecord{}
	for i, name := range names {
		if name != fmt.Sprintf("event-%04d.json", i) {
			return empty, errors.New("Memcached 原事务事件缺口；不丢弃后续原证据")
		}
		raw, err := geoStoreRead(j.d.root, name, core.MaxMemcachedUpdateRecordBytes)
		if err != nil {
			return empty, err
		}
		record, err := core.DecodeMemcachedUpdateRecord(raw)
		if err != nil || record.Dispatch.JobID != j.id || record.Sequence != i || i == 0 && record.Phase != "prepared" || i > 0 && core.ValidateMemcachedUpdateTransition(previous, record) != nil {
			return empty, errors.New("Memcached 原事务事件身份或连续阶段无法核对")
		}
		if i == 0 {
			first = record
		}
		previous = record
		chain = append(chain, record)
	}
	envelope, err := geoStoreRead(j.d.root, "envelope.json", appcatalog.MaxMemcachedReleaseEnvelopeBytes)
	if err != nil {
		return empty, err
	}
	compose, err := geoStoreRead(j.d.root, "compose.original.yaml", 48<<10)
	if err != nil {
		return empty, err
	}
	metadata, err := geoStoreRead(j.d.root, "metadata.original.json", 16<<10)
	if err != nil {
		return empty, err
	}
	if err := memcachedUpdateSeedValid(memcachedUpdateJournalSeed{first, envelope, compose, metadata}); err != nil {
		return empty, err
	}
	if _, err := j.retentionEvidence(first); err != nil {
		return empty, err
	}
	after, err := j.inventory()
	if err != nil || len(after) != len(before) || !j.d.current() {
		return empty, errors.New("Memcached 原事务读取期间目录变化")
	}
	for name, info := range before {
		if !geoStoreStableInfo(info, after[name]) {
			return empty, errors.New("Memcached 原事务读取期间成员身份变化")
		}
	}
	return chain, nil
}

func (j *memcachedUpdateJournal) read() (core.MemcachedUpdateRecord, error) {
	chain, err := j.readChain()
	if err != nil {
		return core.MemcachedUpdateRecord{}, err
	}
	return chain[len(chain)-1], nil
}

// Evidence-only preparation. No signature is accepted as authority here and no
// command can run from this type. Native admission/worker must ALSO run the
// compiled-key verifier against these saved bytes before any Docker effect.
func (s memcachedUpdateJournalStore) prepare(in memcachedUpdateJournalSeed) (core.MemcachedUpdateRecord, bool, error) {
	var empty core.MemcachedUpdateRecord
	if err := memcachedUpdateSeedValid(in); err != nil {
		return empty, false, err
	}
	base, err := geoJobDirectory(s.base, true)
	if err != nil {
		return empty, false, err
	}
	defer base.Close()
	lock, err := geoStoreLock(base.Root)
	if err != nil {
		return empty, false, err
	}
	defer lock.Close()
	dir, err := base.Open(".")
	if err != nil {
		return empty, false, err
	}
	entries, err := dir.ReadDir(memcachedUpdateJobLimit + 2)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > memcachedUpdateJobLimit+1 {
		return empty, false, errors.New("Memcached 原事务库存超过128份；不自动删除历史")
	}
	count := 0
	var retained *core.MemcachedUpdateRecord
	for _, entry := range entries {
		if entry.Name() == "store.lock" {
			continue
		}
		if !core.ValidID(entry.Name()) {
			return empty, false, errors.New("Memcached 原事务库存含未知成员，未修复")
		}
		count++
		original, err := s.open(entry.Name())
		if err != nil {
			return empty, false, err
		}
		prior, err := original.read()
		original.Close()
		if err != nil {
			return empty, false, err
		}
		if prior.Dispatch.JobID == in.Record.Dispatch.JobID {
			if prior.Dispatch != in.Record.Dispatch || prior.Plan != in.Record.Plan || prior.EnvelopeSHA256 != in.Record.EnvelopeSHA256 || prior.CatalogSHA256 != in.Record.CatalogSHA256 || prior.TargetComposeSHA256 != in.Record.TargetComposeSHA256 {
				return empty, false, errors.New("Memcached 原任务ID已绑定不同请求，未覆盖或重发")
			}
			copy := prior
			retained = &copy
			continue
		}
		if prior.Dispatch.RequestID == in.Record.Dispatch.RequestID || prior.Dispatch.ProjectID == in.Record.Dispatch.ProjectID && !memcachedUpdateSafeTerminal(prior.Phase) {
			return empty, false, errors.New("Memcached 原请求或项目存在未核对事务；不换ID重发")
		}
	}
	if retained != nil {
		if !base.current() {
			return empty, false, errors.New("Memcached 原事务库存读取期间变化")
		}
		return *retained, false, nil
	}
	if count >= memcachedUpdateJobLimit || !base.current() {
		return empty, false, errors.New("Memcached 原事务库存已满或目录变化")
	}
	id := in.Record.Dispatch.JobID
	if err = base.Mkdir(id, 0700); err != nil {
		return empty, false, err
	}
	if err = ruleFeedStoreSync(base.Root); err != nil {
		return empty, false, err
	}
	j, err := s.open(id)
	if err != nil {
		return empty, false, err
	}
	defer j.Close()
	raw, _ := json.Marshal(in.Record)
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"envelope.json", in.Envelope}, {"compose.original.yaml", in.OriginalCompose}, {"metadata.original.json", in.OriginalMetadata}, {"run.lock", nil}, {"event-0000.json", raw}} {
		if !j.d.current() {
			return empty, false, errors.New("Memcached 原事务创建期间目录变化")
		}
		if err = ruleFeedStoreWrite(j.d.root, file.name, file.raw, 0600); err != nil {
			return empty, false, err
		}
		if s.fault != nil {
			if err = s.fault("prepared-" + file.name); err != nil {
				return empty, false, err
			}
		}
	}
	if err = ruleFeedStoreSync(j.d.root); err != nil {
		return empty, false, err
	}
	current, err := j.read()
	if err != nil || current != in.Record {
		return empty, false, errors.New("Memcached 新事务持久化后核对失败；保留原目录")
	}
	return current, true, nil
}

func memcachedUpdateSafeTerminal(phase string) bool {
	return phase == "committed" || phase == "rolled_back" || phase == "failed_safe"
}

func (j *memcachedUpdateJournal) lease() (*memcachedUpdateJournalLease, error) {
	if _, err := j.read(); err != nil {
		return nil, err
	}
	f, err := j.d.root.OpenFile("run.lock", os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	visible, ve := j.d.root.Lstat("run.lock")
	if err != nil || ve != nil || !geoStoreStableInfo(opened, visible) || !moduleRecordInfo(opened, false, false) || opened.Size() != 0 || !j.d.current() || unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, errors.New("Memcached 原事务运行锁不能独占；不重发")
	}
	return &memcachedUpdateJournalLease{j, f, opened}, nil
}

func (l *memcachedUpdateJournalLease) current() bool {
	if l == nil || l.file == nil || l.j == nil || !l.j.d.current() {
		return false
	}
	opened, oe := l.file.Stat()
	visible, ve := l.j.d.root.Lstat("run.lock")
	return oe == nil && ve == nil && geoStoreStableInfo(l.identity, opened) && geoStoreStableInfo(l.identity, visible) && moduleRecordInfo(visible, false, false)
}

// Every event is exclusive, file-synced then directory-synced. A partial or
// uncertain append remains evidence and can never be truncated or overwritten.
func (l *memcachedUpdateJournalLease) append(after core.MemcachedUpdateRecord) error {
	if !l.current() {
		return errors.New("Memcached 原事务运行锁或目录身份变化")
	}
	before, err := l.j.read()
	if err != nil {
		return err
	}
	if err = core.ValidateMemcachedUpdateTransition(before, after); err != nil {
		return err
	}
	raw, _ := json.Marshal(after)
	if !l.current() {
		return errors.New("Memcached 原事务追加前身份变化")
	}
	if err = ruleFeedStoreWrite(l.j.d.root, fmt.Sprintf("event-%04d.json", after.Sequence), raw, 0600); err != nil {
		return err
	}
	if l.j.fault != nil {
		if err = l.j.fault("event-file-synced-before-directory"); err != nil {
			return err
		}
	}
	if err = ruleFeedStoreSync(l.j.d.root); err != nil {
		return err
	}
	actual, err := l.j.read()
	if err != nil || actual != after || !l.current() {
		return errors.New("Memcached 原事务追加后身份或内容变化；保留原事件")
	}
	return nil
}

// Read and independently verify the saved bytes, never trust a record's hash
// framing as an Ed25519 verification flag. No key/client/path override exists.
func (j *memcachedUpdateJournal) officialAuthority(ctx context.Context) (appcatalog.MemcachedReleaseAuthority, error) {
	var empty appcatalog.MemcachedReleaseAuthority
	head, err := j.read()
	if err != nil {
		return empty, err
	}
	raw, err := geoStoreRead(j.d.root, "envelope.json", appcatalog.MaxMemcachedReleaseEnvelopeBytes)
	if err != nil || !j.d.current() || core.Hash(string(raw)) != head.EnvelopeSHA256 {
		return empty, errors.New("Memcached 原签名交付读取变化")
	}
	in, err := appcatalog.DecodeMemcachedReleaseEnvelope(raw)
	if err != nil {
		return empty, err
	}
	authority, err := appcatalog.VerifyMemcachedReleaseEnvelope(ctx, in, head.Dispatch.Input.ExpectedVersion, head.Dispatch.Input.ExpectedSHA256)
	if err != nil || authority.CatalogSHA256() != head.CatalogSHA256 {
		return empty, errors.New("Memcached 原交付未通过执行器独立官方验签")
	}
	after, err := j.read()
	if err != nil || after != head || !j.d.current() {
		return empty, errors.New("Memcached 原交付验签期间事务变化")
	}
	return authority, nil
}
