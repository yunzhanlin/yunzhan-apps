//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const loadBalanceStreamModulePublicationsRoot = "/var/lib/panel-executor/load-balance-stream-module-publications"

// Older HTTP records are Root:panel 0600. With no group permissions their
// exact original group is safe and MUST be retained, not rewritten to look
// like a new Root:Root native publication. New native records remain 0:0.
func streamModuleOriginalFileInfo(info os.FileInfo) bool {
	return info != nil && moduleRecordInfo(info, false, false) && info.Size() >= 1 && info.Size() <= loadBalanceStreamModuleLimit
}

type loadBalanceStreamHeldModule struct {
	root    *os.Root
	anchor  func() bool
	file    *os.File // nil means an explicitly observed missing installed.json.
	before  os.FileInfo
	raw     []byte
	missing bool
}

func (r *loadBalanceStreamHeldModule) close() {
	if r != nil {
		clear(r.raw)
		if r.file != nil {
			r.file.Close()
			r.file = nil
		}
	}
}

func (r *loadBalanceStreamHeldModule) current() bool {
	if r == nil || r.root == nil || r.anchor == nil || !r.anchor() {
		return false
	}
	visible, err := r.root.Lstat("installed.json")
	if r.missing {
		return r.file == nil && r.before == nil && len(r.raw) == 0 && errors.Is(err, os.ErrNotExist) && r.anchor()
	}
	if err != nil || r.file == nil {
		return false
	}
	held, err := r.file.Stat()
	return err == nil && streamModuleOriginalFileInfo(held) &&
		geoStoreStableInfo(r.before, held) && geoStoreStableInfo(held, visible) && r.anchor()
}

func holdLoadBalanceStreamModuleAt(root *os.Root, anchor func() bool) (*loadBalanceStreamHeldModule, error) {
	if os.Geteuid() != 0 || root == nil || anchor == nil || !anchor() {
		return nil, errLoadBalanceStreamModule
	}
	r := &loadBalanceStreamHeldModule{root: root, anchor: anchor}
	info, err := root.Lstat("installed.json")
	if errors.Is(err, os.ErrNotExist) {
		r.missing = true
		if r.current() {
			return r, nil
		}
		return nil, errLoadBalanceStreamModule
	}
	if err != nil || !streamModuleOriginalFileInfo(info) {
		return nil, errLoadBalanceStreamModule
	}
	r.file, err = root.OpenFile("installed.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errLoadBalanceStreamModule
	}
	fail := func() (*loadBalanceStreamHeldModule, error) { r.close(); return nil, errLoadBalanceStreamModule }
	r.before, err = r.file.Stat()
	if err != nil || !geoStoreStableInfo(info, r.before) {
		return fail()
	}
	r.raw, err = io.ReadAll(io.LimitReader(r.file, loadBalanceStreamModuleLimit+1))
	if err != nil || int64(len(r.raw)) != info.Size() || !r.current() {
		return fail()
	}
	v, err := decodeLoadBalanceStreamModule(r.raw)
	if err != nil || v["version"] == loadbalancestream.AppVersion && !streamJournalFileInfo(r.before, loadBalanceStreamModuleLimit) {
		return fail()
	}
	return r, nil
}

// Read only the fixed retained OLD module leaf; never relax the Root:Root
// contract of journals, handoffs, new records or installation receipts.
func readStreamRetainedOriginalModule(root *os.Root, job string) ([]byte, error) {
	if root == nil || !core.ValidID(job) {
		return nil, errLoadBalanceStreamModule
	}
	name := ".lbstream-publication-" + job + ".json"
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !streamModuleOriginalFileInfo(before) {
		return nil, errLoadBalanceStreamModule
	}
	raw, err := io.ReadAll(io.LimitReader(f, loadBalanceStreamModuleLimit+1))
	held, e1 := f.Stat()
	visible, e2 := root.Lstat(name)
	if err != nil || e1 != nil || e2 != nil || int64(len(raw)) != before.Size() || !geoStoreStableInfo(before, held) || !geoStoreStableInfo(held, visible) {
		clear(raw)
		return nil, errLoadBalanceStreamModule
	}
	return raw, nil
}

// A private retained copy records all original bytes and metadata; this is not
// a recovery/retry authority. Only a new original journal's controller creates
// the fixed JOB directory, under its runtime and module mutation leases.
type loadBalanceStreamModulePublication struct {
	original *loadBalanceStreamHeldModule
	root     *os.Root
	current  func() bool
	seed     []byte
	proposal []byte
	intent   []byte
	job      string
	unknown  bool
	done     bool
}

func (p *loadBalanceStreamModulePublication) close() {
	if p != nil {
		clear(p.seed)
		clear(p.proposal)
		clear(p.intent)
	}
}

func streamModulePublicationMatches(root *os.Root, name string, expected []byte) bool {
	if root == nil || len(expected) == 0 || len(expected) > loadBalanceStreamModuleLimit {
		return false
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !streamJournalFileInfo(before, loadBalanceStreamModuleLimit) || before.Size() != int64(len(expected)) {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(len(expected))+1))
	defer clear(raw)
	after, e1 := f.Stat()
	visible, e2 := root.Lstat(name)
	return err == nil && e1 == nil && e2 == nil && bytes.Equal(raw, expected) && geoStoreStableInfo(before, after) && geoStoreStableInfo(after, visible)
}

func (p *loadBalanceStreamModulePublication) originalsCurrent(published []byte) bool {
	if p == nil || p.root == nil || p.current == nil || !p.current() || p.original == nil {
		return false
	}
	expected := map[string][]byte{"intent.json": p.intent, "proposal.json": p.proposal}
	if !p.original.missing {
		expected["original.json"] = p.original.raw
	}
	if len(published) != 0 {
		expected["published.json"] = published
	}
	dir, err := p.root.Open(".")
	if err != nil {
		return false
	}
	entries, err := dir.ReadDir(5)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) != len(expected) {
		return false
	}
	for _, entry := range entries {
		raw, known := expected[entry.Name()]
		if !known || !streamModulePublicationMatches(p.root, entry.Name(), raw) {
			return false
		}
	}
	return p.current()
}

type loadBalanceStreamModuleOriginalIdentity struct {
	Exists      bool   `json:"exists"`
	SHA256      string `json:"sha256"`
	Device      uint64 `json:"device"`
	Inode       uint64 `json:"inode"`
	Mode        uint32 `json:"mode"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Links       uint64 `json:"links"`
	Bytes       int64  `json:"bytes"`
	MTimeSecond int64  `json:"mtime_second"`
	MTimeNano   int64  `json:"mtime_nanosecond"`
	CTimeSecond int64  `json:"ctime_second"`
	CTimeNano   int64  `json:"ctime_nanosecond"`
}

type loadBalanceStreamModulePublicationIntent struct {
	Format         int                                     `json:"format"`
	JobID          string                                  `json:"job_id"`
	SeedSHA256     string                                  `json:"seed_sha256"`
	ProposalSHA256 string                                  `json:"proposal_sha256"`
	Original       loadBalanceStreamModuleOriginalIdentity `json:"original"`
}

func streamModuleOriginalIdentity(r *loadBalanceStreamHeldModule) (loadBalanceStreamModuleOriginalIdentity, error) {
	if !r.current() {
		return loadBalanceStreamModuleOriginalIdentity{}, errLoadBalanceStreamModule
	}
	if r.missing {
		return loadBalanceStreamModuleOriginalIdentity{}, nil
	}
	s, ok := r.before.Sys().(*syscall.Stat_t)
	if !ok {
		return loadBalanceStreamModuleOriginalIdentity{}, errLoadBalanceStreamModule
	}
	return loadBalanceStreamModuleOriginalIdentity{true, core.Hash(string(r.raw)), uint64(s.Dev), s.Ino, s.Mode, s.Uid, s.Gid, uint64(s.Nlink), s.Size, s.Mtim.Sec, s.Mtim.Nsec, s.Ctim.Sec, s.Ctim.Nsec}, nil
}

func streamModulePublicationWrite(root *os.Root, name string, raw []byte) error {
	limit := loadBalanceStreamModuleLimit
	switch name {
	case "original.json", "proposal.json":
	case "intent.json", "published.json":
		limit = 8192
	default:
		return errLoadBalanceStreamModule
	}
	if root == nil || len(raw) == 0 || len(raw) > limit {
		return errLoadBalanceStreamModule
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errLoadBalanceStreamModule
	}
	defer f.Close()
	if f.Chown(0, 0) != nil || f.Chmod(0600) != nil {
		return errLoadBalanceStreamModule
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) || f.Sync() != nil || ruleFeedStoreSync(root) != nil {
		return errLoadBalanceStreamModule
	}
	held, e1 := f.Stat()
	visible, e2 := root.Lstat(name)
	if e1 != nil || e2 != nil || !streamJournalFileInfo(held, int64(limit)) || !geoStoreStableInfo(held, visible) {
		return errLoadBalanceStreamModule
	}
	return nil
}

// The caller supplies only its newly exclusive publication root and original
// held module. Arbitrary paths and an old incomplete publication cannot become
// a new writer. Callback injection is private for negative filesystem models;
// production binds it to the actual original gate and native leases.
func prepareLoadBalanceStreamModulePublicationAt(ctx context.Context, root *os.Root, current func() bool, original *loadBalanceStreamHeldModule, seedRaw, proposal []byte, authorize func(context.Context) error) (*loadBalanceStreamModulePublication, error) {
	if ctx == nil || ctx.Err() != nil || root == nil || current == nil || !current() || original == nil || !original.current() || authorize == nil || authorize(ctx) != nil {
		return nil, errLoadBalanceStreamModule
	}
	info, err := root.Stat(".")
	if err != nil || !memcachedUnixAdminDirectoryInfo(info) {
		return nil, errLoadBalanceStreamModule
	}
	seed, err := loadbalancestream.DecodeInstallationSeed(seedRaw)
	if err != nil || seed.Action == "install" && !original.missing || seed.Action == "update" && original.missing {
		return nil, errLoadBalanceStreamModule
	}
	// Regenerate, rather than trusting caller-supplied published bytes.
	decoded, err := decodeLoadBalanceStreamModule(proposal)
	if err != nil {
		return nil, errLoadBalanceStreamModule
	}
	stamp, _ := decoded["updated_at"].(string)
	now, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return nil, errLoadBalanceStreamModule
	}
	expected, err := loadBalanceStreamModuleProposal(seedRaw, original.raw, now)
	if err != nil || !bytes.Equal(proposal, expected) {
		return nil, errLoadBalanceStreamModule
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, errLoadBalanceStreamModule
	}
	entries, readErr := dir.ReadDir(1)
	dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) != 0 {
		return nil, errLoadBalanceStreamModule
	}
	identity, err := streamModuleOriginalIdentity(original)
	if err != nil || authorize(ctx) != nil || !current() {
		return nil, errLoadBalanceStreamModule
	}
	intent := loadBalanceStreamModulePublicationIntent{1, seed.JobID, core.Hash(string(seedRaw)), core.Hash(string(proposal)), identity}
	raw, err := json.Marshal(intent)
	if err != nil || streamModulePublicationWrite(root, "intent.json", append(raw, '\n')) != nil {
		return nil, errLoadBalanceStreamModule
	}
	if !original.missing && (authorize(ctx) != nil || !original.current() || !current() || streamModulePublicationWrite(root, "original.json", original.raw) != nil) {
		return nil, errLoadBalanceStreamModule
	}
	if authorize(ctx) != nil || !original.current() || !current() || streamModulePublicationWrite(root, "proposal.json", proposal) != nil {
		return nil, errLoadBalanceStreamModule
	}
	p := &loadBalanceStreamModulePublication{original: original, root: root, current: current, seed: bytes.Clone(seedRaw), proposal: bytes.Clone(proposal), intent: append(bytes.Clone(raw), '\n'), job: seed.JobID}
	if !p.originalsCurrent(nil) || !original.current() || authorize(ctx) != nil {
		p.close()
		return nil, errLoadBalanceStreamModule
	}
	return p, nil
}

// Publication has one irreversible original attempt. RENAME_EXCHANGE keeps
// the exact old inode in the private module directory; RENAME_NOREPLACE on a
// fresh installation can never overwrite a concurrently appeared record.
// Any post-effect uncertainty is retained without restore, adoption or retry.
func (p *loadBalanceStreamModulePublication) publish(ctx context.Context, authorize func(context.Context) error) (string, error) {
	if p == nil || p.unknown || p.done || ctx == nil || ctx.Err() != nil || authorize == nil || authorize(ctx) != nil || !p.originalsCurrent(nil) || !p.original.current() || !core.ValidID(p.job) {
		return "", errLoadBalanceStreamModule
	}
	name := ".lbstream-publication-" + p.job + ".json"
	p.unknown = true
	f, err := p.original.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return "", errLoadBalanceStreamModule
	}
	defer f.Close()
	if f.Chown(0, 0) != nil || f.Chmod(0600) != nil {
		return "", errLoadBalanceStreamModule
	}
	if n, err := f.Write(p.proposal); err != nil || n != len(p.proposal) || f.Sync() != nil || ruleFeedStoreSync(p.original.root) != nil {
		return "", errLoadBalanceStreamModule
	}
	candidate, e1 := f.Stat()
	visible, e2 := p.original.root.Lstat(name)
	if e1 != nil || e2 != nil || !streamJournalFileInfo(candidate, loadBalanceStreamModuleLimit) || !geoStoreStableInfo(candidate, visible) || !streamModulePublicationMatches(p.original.root, name, p.proposal) || authorize(ctx) != nil || !p.originalsCurrent(nil) || !p.original.current() {
		return "", errLoadBalanceStreamModule
	}
	dir, err := p.original.root.Open(".")
	if err != nil {
		return "", errLoadBalanceStreamModule
	}
	defer dir.Close()
	flags := uint(unix.RENAME_EXCHANGE)
	if p.original.missing {
		flags = unix.RENAME_NOREPLACE
	}
	if unix.Renameat2(int(dir.Fd()), name, int(dir.Fd()), "installed.json", flags) != nil || dir.Sync() != nil {
		return "", errLoadBalanceStreamModule
	}
	if authorize(ctx) != nil || !p.originalsCurrent(nil) || !p.original.anchor() {
		return "", errLoadBalanceStreamModule
	}
	published, err := holdLoadBalanceStreamModuleAt(p.original.root, p.original.anchor)
	if err != nil {
		return "", errLoadBalanceStreamModule
	}
	defer published.close()
	if !bytes.Equal(published.raw, p.proposal) || !os.SameFile(candidate, published.before) {
		return "", errLoadBalanceStreamModule
	}
	if !p.original.missing {
		old, e1 := p.original.file.Stat()
		namedOld, e2 := p.original.root.Lstat(name)
		x, ok := p.original.before.Sys().(*syscall.Stat_t)
		y, ok2 := func() (*syscall.Stat_t, bool) {
			if old == nil {
				return nil, false
			}
			v, ok := old.Sys().(*syscall.Stat_t)
			return v, ok
		}()
		// Rename changes ctime but no old data, ownership, mode, inode or mtime.
		if e1 != nil || e2 != nil || !ok || !ok2 || !geoStoreStableInfo(old, namedOld) || x.Dev != y.Dev || x.Ino != y.Ino || x.Mode != y.Mode || x.Uid != y.Uid || x.Gid != y.Gid || x.Nlink != y.Nlink || x.Size != y.Size || x.Mtim != y.Mtim {
			return "", errLoadBalanceStreamModule
		}
		oldBytes := make([]byte, len(p.original.raw))
		if n, err := p.original.file.ReadAt(oldBytes, 0); err != nil || n != len(oldBytes) || !bytes.Equal(oldBytes, p.original.raw) {
			clear(oldBytes)
			return "", errLoadBalanceStreamModule
		}
		clear(oldBytes)
	} else if _, err := p.original.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return "", errLoadBalanceStreamModule
	}
	if authorize(ctx) != nil || !published.current() || !p.originalsCurrent(nil) {
		return "", errLoadBalanceStreamModule
	}
	digest := core.Hash(string(p.proposal))
	receipt, err := json.Marshal(struct {
		Format                int    `json:"format"`
		JobID                 string `json:"job_id"`
		SeedSHA256            string `json:"seed_sha256"`
		PublishedSHA256       string `json:"published_sha256"`
		OriginalInodeRetained bool   `json:"original_inode_retained"`
	}{1, p.job, core.Hash(string(p.seed)), digest, !p.original.missing})
	if err != nil || streamModulePublicationWrite(p.root, "published.json", append(receipt, '\n')) != nil || !published.current() || !p.originalsCurrent(append(receipt, '\n')) || authorize(ctx) != nil {
		return "", errLoadBalanceStreamModule
	}
	p.done = true
	return digest, nil
}
