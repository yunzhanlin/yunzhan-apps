//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"syscall"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const loadBalanceStreamGenerationPublicationsRoot = "/var/lib/panel-executor/load-balance-stream-generations"

type loadBalanceStreamGenerationFile struct {
	root    *os.Root
	file    *os.File
	before  os.FileInfo
	raw     []byte
	missing bool
	anchor  func() bool
}

func (f *loadBalanceStreamGenerationFile) close() {
	if f != nil {
		if f.file != nil {
			f.file.Close()
			f.file = nil
		}
		clear(f.raw)
	}
}

func (f *loadBalanceStreamGenerationFile) current() bool {
	if f == nil || f.root == nil || f.anchor == nil || !f.anchor() {
		return false
	}
	visible, err := f.root.Lstat("current.json")
	if f.missing {
		return f.file == nil && errors.Is(err, os.ErrNotExist)
	}
	if f.file == nil || err != nil {
		return false
	}
	held, err := f.file.Stat()
	return err == nil && streamJournalFileInfo(held, loadbalancestream.MaxGenerationRecordBytes) && geoStoreStableInfo(f.before, held) && geoStoreStableInfo(held, visible)
}

func holdStreamGenerationFileAt(root *os.Root, anchor func() bool) (*loadBalanceStreamGenerationFile, error) {
	f := &loadBalanceStreamGenerationFile{root: root, anchor: anchor}
	if root == nil || anchor == nil || !anchor() {
		return nil, loadbalancestream.ErrGeneration
	}
	var err error
	f.file, err = root.OpenFile("current.json", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		f.missing = true
		if f.current() {
			return f, nil
		}
	}
	fail := func() (*loadBalanceStreamGenerationFile, error) {
		f.close()
		return nil, loadbalancestream.ErrGeneration
	}
	if err != nil {
		return fail()
	}
	f.before, err = f.file.Stat()
	if err != nil || !streamJournalFileInfo(f.before, loadbalancestream.MaxGenerationRecordBytes) {
		return fail()
	}
	f.raw, err = io.ReadAll(io.LimitReader(f.file, loadbalancestream.MaxGenerationRecordBytes+1))
	if err != nil || int64(len(f.raw)) != f.before.Size() || !f.current() {
		return fail()
	}
	if _, err = loadbalancestream.DecodeGenerationRecord(f.raw); err != nil {
		return fail()
	}
	return f, nil
}

type loadBalanceStreamGenerationIntent struct {
	Format         int                                     `json:"format"`
	RequestID      string                                  `json:"request_id"`
	InstallationID string                                  `json:"installation_id"`
	Generation     int64                                   `json:"generation"`
	SeedSHA256     string                                  `json:"seed_sha256"`
	ProposalSHA256 string                                  `json:"proposal_sha256"`
	Original       loadBalanceStreamModuleOriginalIdentity `json:"original"`
}

type loadBalanceStreamGenerationPublication struct {
	original *loadBalanceStreamGenerationFile
	root     *os.Root
	anchor   func() bool
	proposal []byte
	intent   []byte
	unknown  bool
	done     bool
}

func streamGenerationPrivateWrite(root *os.Root, name string, raw []byte) error {
	if root == nil || name != "intent.json" && name != "original.json" && name != "proposal.json" && name != "candidate.json" || len(raw) == 0 || len(raw) > loadbalancestream.MaxGenerationRecordBytes || name == "intent.json" && len(raw) > 8192 {
		return loadbalancestream.ErrGeneration
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return loadbalancestream.ErrGeneration
	}
	defer f.Close()
	if f.Chown(0, 0) != nil || f.Chmod(0600) != nil {
		return loadbalancestream.ErrGeneration
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) || f.Sync() != nil || ruleFeedStoreSync(root) != nil {
		return loadbalancestream.ErrGeneration
	}
	if !streamModulePublicationMatches(root, name, raw) {
		return loadbalancestream.ErrGeneration
	}
	return nil
}

// Only the original service-observed prefix can propose the next generation.
// The counter is derived from the HELD original state, never browser/version
// input. This private filesystem seam does not grant control authority; the
// production caller must bind authorize to its actual fresh control gate,
// runtime/mutation leases and independently verified native service/probes.
func prepareStreamGenerationPublicationAt(ctx context.Context, publication *os.Root, anchor func() bool, original *loadBalanceStreamGenerationFile, installation string, seedRaw []byte, records [][]byte, authorize func(context.Context) error) (*loadBalanceStreamGenerationPublication, error) {
	if ctx == nil || ctx.Err() != nil || publication == nil || anchor == nil || !anchor() || original == nil || !original.current() || authorize == nil || authorize(ctx) != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	info, err := publication.Stat(".")
	if err != nil || !memcachedUnixAdminDirectoryInfo(info) {
		return nil, loadbalancestream.ErrGeneration
	}
	seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
	if err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	next := int64(1)
	identity := loadBalanceStreamModuleOriginalIdentity{}
	if original.missing {
		if len(seed.Before) != 0 {
			return nil, loadbalancestream.ErrGeneration
		}
	} else {
		previous, err := loadbalancestream.DecodeGenerationRecord(original.raw)
		if err != nil || previous.InstallationID != installation || previous.Generation >= 128 || previous.RequestID == seed.Operation.RequestID || !reflect.DeepEqual(previous.Entries, seed.Before) || previous.ConfigurationSHA256 != seed.BeforeRuntimeSHA256 {
			return nil, loadbalancestream.ErrGeneration
		}
		next = previous.Generation + 1
		v, ok := original.before.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, loadbalancestream.ErrGeneration
		}
		identity = loadBalanceStreamModuleOriginalIdentity{true, core.Hash(string(original.raw)), uint64(v.Dev), v.Ino, v.Mode, v.Uid, v.Gid, uint64(v.Nlink), v.Size, v.Mtim.Sec, v.Mtim.Nsec, v.Ctim.Sec, v.Ctim.Nsec}
	}
	proposal, _, err := loadbalancestream.ProposeGenerationRecord(installation, next, seedRaw, records)
	if err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	dir, err := publication.Open(".")
	if err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	entries, err := dir.ReadDir(1)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) != 0 || authorize(ctx) != nil || !anchor() || !original.current() {
		return nil, loadbalancestream.ErrGeneration
	}
	intent := loadBalanceStreamGenerationIntent{1, seed.Operation.RequestID, installation, next, core.Hash(string(seedRaw)), core.Hash(string(proposal)), identity}
	raw, err := json.Marshal(intent)
	if err != nil {
		return nil, loadbalancestream.ErrGeneration
	}
	raw = append(raw, '\n')
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"intent.json", raw}, {"original.json", original.raw}, {"proposal.json", proposal}} {
		if file.name == "original.json" && original.missing {
			continue
		}
		if authorize(ctx) != nil || !anchor() || !original.current() || streamGenerationPrivateWrite(publication, file.name, file.raw) != nil {
			return nil, loadbalancestream.ErrGeneration
		}
	}
	p := &loadBalanceStreamGenerationPublication{original: original, root: publication, anchor: anchor, proposal: proposal, intent: raw}
	if !p.metadataCurrent() || authorize(ctx) != nil || !original.current() {
		return nil, loadbalancestream.ErrGeneration
	}
	return p, nil
}

func (p *loadBalanceStreamGenerationPublication) metadataCurrent() bool {
	if p == nil || p.original == nil || p.root == nil || p.anchor == nil || !p.anchor() || !streamModulePublicationMatches(p.root, "intent.json", p.intent) || !streamModulePublicationMatches(p.root, "proposal.json", p.proposal) {
		return false
	}
	if !p.original.missing && !streamModulePublicationMatches(p.root, "original.json", p.original.raw) {
		return false
	}
	want := map[string]bool{"intent.json": true, "proposal.json": true}
	if !p.original.missing {
		want["original.json"] = true
	}
	if p.unknown {
		if info, err := p.root.Lstat("candidate.json"); err == nil {
			if !streamJournalFileInfo(info, loadbalancestream.MaxGenerationRecordBytes) {
				return false
			}
			want["candidate.json"] = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	dir, err := p.root.Open(".")
	if err != nil {
		return false
	}
	entries, err := dir.ReadDir(5)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) != len(want) {
		return false
	}
	for _, entry := range entries {
		if !want[entry.Name()] {
			return false
		}
	}
	return true
}

// One original atomic attempt. Cross-directory EXCHANGE retains the ACTUAL
// previous inode in the private publication directory; copying bytes into a
// new inode can never stand in for it. Both directory fsyncs are mandatory.
// Failure after intent/effect is unknown: no restore/delete/retry/adoption.
func (p *loadBalanceStreamGenerationPublication) publish(ctx context.Context, authorize func(context.Context) error) error {
	if p == nil || p.unknown || p.done || ctx == nil || ctx.Err() != nil || authorize == nil || authorize(ctx) != nil || !p.metadataCurrent() || !p.original.current() {
		return loadbalancestream.ErrGeneration
	}
	p.unknown = true
	if streamGenerationPrivateWrite(p.root, "candidate.json", p.proposal) != nil || authorize(ctx) != nil || !p.metadataCurrent() || !p.original.current() {
		return loadbalancestream.ErrGeneration
	}
	candidate, err := p.root.Lstat("candidate.json")
	if err != nil || !streamJournalFileInfo(candidate, loadbalancestream.MaxGenerationRecordBytes) {
		return loadbalancestream.ErrGeneration
	}
	from, e1 := p.root.Open(".")
	to, e2 := p.original.root.Open(".")
	if e1 != nil || e2 != nil {
		if from != nil {
			from.Close()
		}
		if to != nil {
			to.Close()
		}
		return loadbalancestream.ErrGeneration
	}
	defer from.Close()
	defer to.Close()
	flag := uint(unix.RENAME_EXCHANGE)
	if p.original.missing {
		flag = unix.RENAME_NOREPLACE
	}
	if authorize(ctx) != nil || !p.metadataCurrent() || !p.original.current() || unix.Renameat2(int(from.Fd()), "candidate.json", int(to.Fd()), "current.json", flag) != nil || from.Sync() != nil || to.Sync() != nil {
		return loadbalancestream.ErrGeneration
	}
	if authorize(ctx) != nil || !p.metadataCurrent() || !p.original.anchor() {
		return loadbalancestream.ErrGeneration
	}
	current, err := holdStreamGenerationFileAt(p.original.root, p.original.anchor)
	if err != nil {
		return loadbalancestream.ErrGeneration
	}
	defer current.close()
	if current.missing || !bytes.Equal(current.raw, p.proposal) || !os.SameFile(candidate, current.before) {
		return loadbalancestream.ErrGeneration
	}
	if p.original.missing {
		if _, err := p.root.Lstat("candidate.json"); !errors.Is(err, os.ErrNotExist) {
			return loadbalancestream.ErrGeneration
		}
	} else {
		var intent loadBalanceStreamGenerationIntent
		if json.Unmarshal(p.intent, &intent) != nil {
			return loadbalancestream.ErrGeneration
		}
		old, err := p.original.file.Stat()
		named, e2 := p.root.Lstat("candidate.json")
		if err != nil || e2 != nil || !streamJournalFileInfo(old, loadbalancestream.MaxGenerationRecordBytes) || !geoStoreStableInfo(old, named) || !streamModuleRetainedIdentityMatches(intent.Original, old, core.Hash(string(p.original.raw))) || !streamModulePublicationMatches(p.root, "candidate.json", p.original.raw) {
			return loadbalancestream.ErrGeneration
		}
	}
	if authorize(ctx) != nil || !p.metadataCurrent() || !current.current() {
		return loadbalancestream.ErrGeneration
	}
	p.done = true
	return nil
}
