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
	"syscall"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const loadBalanceStreamConfigurationRoot = "/etc/panel/load-balance-stream"
const loadBalanceStreamConfigurationPublicationsRoot = "/var/lib/panel-executor/load-balance-stream-configurations"

// The service can read, never write its configuration or directory. PID and
// temporary runtime files are deliberately in the separate service-owned /run
// prefix and never select a process, executable or signal target for Root.
func streamConfigurationInfo(info os.FileInfo, gid uint32, directory bool) bool {
	if info == nil || gid < 100 || gid >= 1000 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	v, ok := info.Sys().(*syscall.Stat_t)
	if !ok || v.Uid != 0 || v.Gid != gid {
		return false
	}
	if directory {
		return info.IsDir() && info.Mode().Perm() == 0750
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0640 && v.Nlink == 1 && info.Size() > 0 && info.Size() <= loadbalancestream.MaxRuntimeBytes
}

type loadBalanceStreamConfigurationFile struct {
	root    *os.Root
	file    *os.File
	before  os.FileInfo
	raw     []byte
	gid     uint32
	missing bool
	anchor  func() bool
}

func (f *loadBalanceStreamConfigurationFile) close() {
	if f != nil {
		if f.file != nil {
			f.file.Close()
			f.file = nil
		}
		clear(f.raw)
	}
}

func (f *loadBalanceStreamConfigurationFile) current() bool {
	if f == nil || f.root == nil || f.anchor == nil || !f.anchor() {
		return false
	}
	dir, err := f.root.Stat(".")
	if err != nil || !streamConfigurationInfo(dir, f.gid, true) {
		return false
	}
	visible, err := f.root.Lstat("nginx.conf")
	if f.missing {
		return f.file == nil && errors.Is(err, os.ErrNotExist)
	}
	if err != nil || f.file == nil {
		return false
	}
	held, err := f.file.Stat()
	return err == nil && streamConfigurationInfo(held, f.gid, false) && geoStoreStableInfo(f.before, held) && geoStoreStableInfo(held, visible)
}

func holdStreamConfigurationAt(root *os.Root, gid uint32, anchor func() bool) (*loadBalanceStreamConfigurationFile, error) {
	f := &loadBalanceStreamConfigurationFile{root: root, gid: gid, anchor: anchor}
	if root == nil || anchor == nil || !anchor() {
		return nil, loadbalancestream.ErrRuntime
	}
	info, err := root.Stat(".")
	if err != nil || !streamConfigurationInfo(info, gid, true) {
		return nil, loadbalancestream.ErrRuntime
	}
	f.file, err = root.OpenFile("nginx.conf", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		f.missing = true
		if f.current() {
			return f, nil
		}
	}
	fail := func() (*loadBalanceStreamConfigurationFile, error) {
		f.close()
		return nil, loadbalancestream.ErrRuntime
	}
	if err != nil {
		return fail()
	}
	f.before, err = f.file.Stat()
	if err != nil || !streamConfigurationInfo(f.before, gid, false) {
		return fail()
	}
	f.raw, err = io.ReadAll(io.LimitReader(f.file, loadbalancestream.MaxRuntimeBytes+1))
	if err != nil || int64(len(f.raw)) != f.before.Size() || !f.current() {
		return fail()
	}
	return f, nil
}

type loadBalanceStreamConfigurationIntent struct {
	Format              int                                     `json:"format"`
	RequestID           string                                  `json:"request_id"`
	SeedSHA256          string                                  `json:"seed_sha256"`
	ConfigurationSHA256 string                                  `json:"configuration_sha256"`
	ServiceGID          uint32                                  `json:"service_gid"`
	Original            loadBalanceStreamModuleOriginalIdentity `json:"original"`
}

type loadBalanceStreamConfigurationPublication struct {
	original               *loadBalanceStreamConfigurationFile
	publication            *os.Root
	anchor                 func() bool
	seed, proposal, intent []byte
	stagedReceipt          []byte
	promotedReceipt        []byte
	candidate              *os.File
	candidateBefore        os.FileInfo
	request                string
	attempted, promoted    bool
	ownsPublication        bool
	syntaxIssued           bool
	syntaxVerified         bool
	serviceIssued          bool
	stopCleanupIssued      bool
	serviceReceiptIssued   bool
	serviceReceipt         []byte
	completionIssued       bool
	completionReceipt      []byte
	store                  *loadBalanceStreamConfigurationStore
}

func (p *loadBalanceStreamConfigurationPublication) close() {
	if p != nil {
		if p.candidate != nil {
			p.candidate.Close()
			p.candidate = nil
		}
		clear(p.seed)
		clear(p.proposal)
		clear(p.intent)
		clear(p.stagedReceipt)
		clear(p.promotedReceipt)
		clear(p.serviceReceipt)
		clear(p.completionReceipt)
		if p.ownsPublication && p.publication != nil {
			p.publication.Close()
			p.publication = nil
		}
	}
}

func (p *loadBalanceStreamConfigurationPublication) metadataCurrent() bool {
	if p == nil || p.original == nil || p.publication == nil || p.anchor == nil || !p.anchor() || !streamModulePublicationMatches(p.publication, "intent.json", p.intent) || !streamModulePublicationMatches(p.publication, "proposal.json", p.proposal) {
		return false
	}
	if !p.original.missing && !streamModulePublicationMatches(p.publication, "original.json", p.original.raw) {
		return false
	}
	want := map[string]bool{"intent.json": true, "proposal.json": true}
	for name, raw := range map[string][]byte{"staged.json": p.stagedReceipt, "promoted.json": p.promotedReceipt, "service.json": p.serviceReceipt, "controller-exit.json": p.completionReceipt} {
		if len(raw) != 0 {
			matched := false
			if name == "controller-exit.json" {
				matched = streamControlCompletionMatches(p.publication, raw)
			} else {
				matched = streamModulePublicationMatches(p.publication, name, raw)
			}
			if !matched {
				return false
			}
			want[name] = true
		}
	}
	if !p.original.missing {
		want["original.json"] = true
	}
	dir, err := p.publication.Open(".")
	if err != nil {
		return false
	}
	entries, err := dir.ReadDir(8)
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

// Private filesystem seam, not effect authorization. The production wrappers
// below bind it to the original live gate/three actual kernel leases and exact
// phase. The complete old bytes/metadata are durable BEFORE staging; no caller
// supplies a shell, renderer fragment, destination path or config SHA claim.
func stageStreamConfigurationAt(ctx context.Context, publication *os.Root, anchor func() bool, original *loadBalanceStreamConfigurationFile, seedRaw []byte, authorize func(context.Context) error) (*loadBalanceStreamConfigurationPublication, error) {
	if ctx == nil || ctx.Err() != nil || publication == nil || anchor == nil || !anchor() || original == nil || !original.current() || authorize == nil || authorize(ctx) != nil {
		return nil, loadbalancestream.ErrRuntime
	}
	info, err := publication.Stat(".")
	if err != nil || !memcachedUnixAdminDirectoryInfo(info) {
		return nil, loadbalancestream.ErrRuntime
	}
	seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
	if err != nil {
		return nil, loadbalancestream.ErrRuntime
	}
	facts := loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget}
	before, e1 := loadbalancestream.RenderRuntime(seed.Before, loadbalancestream.ServiceRuntimePrefix, facts)
	after, e2 := loadbalancestream.RenderRuntime(seed.After, loadbalancestream.ServiceRuntimePrefix, facts)
	if e1 != nil || e2 != nil || before.SHA256 != seed.BeforeRuntimeSHA256 || after.SHA256 != seed.AfterRuntimeSHA256 || original.missing != (len(seed.Before) == 0) || !original.missing && !bytes.Equal(before.Main, original.raw) {
		return nil, loadbalancestream.ErrRuntime
	}
	dir, err := publication.Open(".")
	if err != nil {
		return nil, loadbalancestream.ErrRuntime
	}
	entries, err := dir.ReadDir(1)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) != 0 {
		return nil, loadbalancestream.ErrRuntime
	}
	identity := loadBalanceStreamModuleOriginalIdentity{}
	if !original.missing {
		v, ok := original.before.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, loadbalancestream.ErrRuntime
		}
		identity = loadBalanceStreamModuleOriginalIdentity{true, core.Hash(string(original.raw)), uint64(v.Dev), v.Ino, v.Mode, v.Uid, v.Gid, uint64(v.Nlink), v.Size, v.Mtim.Sec, v.Mtim.Nsec, v.Ctim.Sec, v.Ctim.Nsec}
	}
	intent := loadBalanceStreamConfigurationIntent{1, seed.Operation.RequestID, core.Hash(string(seedRaw)), after.SHA256, original.gid, identity}
	raw, err := json.Marshal(intent)
	if err != nil {
		return nil, loadbalancestream.ErrRuntime
	}
	raw = append(raw, '\n')
	for _, row := range []struct {
		name string
		raw  []byte
	}{{"intent.json", raw}, {"original.json", original.raw}, {"proposal.json", after.Main}} {
		if row.name == "original.json" && original.missing {
			continue
		}
		if authorize(ctx) != nil || !anchor() || !original.current() || streamGenerationPrivateWrite(publication, row.name, row.raw) != nil {
			return nil, loadbalancestream.ErrRuntime
		}
	}
	p := &loadBalanceStreamConfigurationPublication{original: original, publication: publication, anchor: anchor, seed: bytes.Clone(seedRaw), proposal: bytes.Clone(after.Main), intent: raw, request: seed.Operation.RequestID}
	fail := func() (*loadBalanceStreamConfigurationPublication, error) {
		p.close()
		return nil, loadbalancestream.ErrRuntime
	}
	if authorize(ctx) != nil || !p.metadataCurrent() || !original.current() {
		return fail()
	}
	name := ".candidate-" + p.request + ".conf"
	p.candidate, err = original.root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fail()
	}
	if p.candidate.Chown(0, int(original.gid)) != nil || p.candidate.Chmod(0640) != nil {
		return fail()
	}
	if n, err := p.candidate.Write(p.proposal); err != nil || n != len(p.proposal) || p.candidate.Sync() != nil || ruleFeedStoreSync(original.root) != nil {
		return fail()
	}
	p.candidateBefore, err = p.candidate.Stat()
	visible, e2 := original.root.Lstat(name)
	if err != nil || e2 != nil || !streamConfigurationInfo(p.candidateBefore, original.gid, false) || !geoStoreStableInfo(p.candidateBefore, visible) || !p.candidateCurrent() || !p.metadataCurrent() || !original.current() || authorize(ctx) != nil {
		return fail()
	}
	p.stagedReceipt, err = p.fileReceipt("staged", p.candidateBefore)
	if err != nil || authorize(ctx) != nil || !p.original.current() || !p.candidateCurrent() || streamConfigurationReceiptWrite(publication, "staged.json", p.stagedReceipt) != nil || !p.metadataCurrent() || !p.candidateCurrent() || authorize(ctx) != nil {
		return fail()
	}
	return p, nil
}

func (p *loadBalanceStreamConfigurationPublication) candidateCurrent() bool {
	if p == nil || p.candidate == nil || p.original == nil || p.original.anchor == nil || !p.original.anchor() {
		return false
	}
	held, e1 := p.candidate.Stat()
	visible, e2 := p.original.root.Lstat(".candidate-" + p.request + ".conf")
	if e1 != nil || e2 != nil || !streamConfigurationInfo(held, p.original.gid, false) || !geoStoreStableInfo(p.candidateBefore, held) || !geoStoreStableInfo(held, visible) {
		return false
	}
	raw := make([]byte, len(p.proposal))
	defer clear(raw)
	n, err := p.candidate.ReadAt(raw, 0)
	return err == nil && n == len(raw) && bytes.Equal(raw, p.proposal)
}

// Atomic promotion is a one-shot original attempt, NEVER a health report or
// automatic rollback. It retains the old actual inode at the private managed
// candidate name; the service has directory read/execute but no write access.
func (p *loadBalanceStreamConfigurationPublication) promoteAt(ctx context.Context, authorize func(context.Context) error) (string, error) {
	if p == nil || p.attempted || p.promoted || ctx == nil || ctx.Err() != nil || authorize == nil || authorize(ctx) != nil || !p.metadataCurrent() || !p.original.current() || !p.candidateCurrent() {
		return "", loadbalancestream.ErrRuntime
	}
	p.attempted = true
	dir, err := p.original.root.Open(".")
	if err != nil {
		return "", loadbalancestream.ErrRuntime
	}
	defer dir.Close()
	flag := uint(unix.RENAME_EXCHANGE)
	if p.original.missing {
		flag = unix.RENAME_NOREPLACE
	}
	name := ".candidate-" + p.request + ".conf"
	if authorize(ctx) != nil || !p.metadataCurrent() || !p.original.current() || !p.candidateCurrent() || unix.Renameat2(int(dir.Fd()), name, int(dir.Fd()), "nginx.conf", flag) != nil || dir.Sync() != nil {
		return "", loadbalancestream.ErrRuntime
	}
	if authorize(ctx) != nil || !p.metadataCurrent() || !p.original.anchor() {
		return "", loadbalancestream.ErrRuntime
	}
	current, err := holdStreamConfigurationAt(p.original.root, p.original.gid, p.original.anchor)
	if err != nil {
		return "", loadbalancestream.ErrRuntime
	}
	defer current.close()
	if current.missing || !bytes.Equal(current.raw, p.proposal) || !os.SameFile(p.candidateBefore, current.before) {
		return "", loadbalancestream.ErrRuntime
	}
	if p.original.missing {
		if _, err := p.original.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return "", loadbalancestream.ErrRuntime
		}
	} else {
		old, e1 := p.original.file.Stat()
		visible, e2 := p.original.root.Lstat(name)
		var intent loadBalanceStreamConfigurationIntent
		if json.Unmarshal(p.intent, &intent) != nil || e1 != nil || e2 != nil || !streamConfigurationInfo(old, p.original.gid, false) || !geoStoreStableInfo(old, visible) || !streamModuleRetainedIdentityMatches(intent.Original, old, core.Hash(string(p.original.raw))) {
			return "", loadbalancestream.ErrRuntime
		}
		body := make([]byte, len(p.original.raw))
		n, err := p.original.file.ReadAt(body, 0)
		same := err == nil && n == len(body) && bytes.Equal(body, p.original.raw)
		clear(body)
		if !same {
			return "", loadbalancestream.ErrRuntime
		}
	}
	if authorize(ctx) != nil || !current.current() || !p.metadataCurrent() {
		return "", loadbalancestream.ErrRuntime
	}
	p.promotedReceipt, err = p.fileReceipt("promoted", current.before)
	if err != nil || authorize(ctx) != nil || !current.current() || streamConfigurationReceiptWrite(p.publication, "promoted.json", p.promotedReceipt) != nil || !p.metadataCurrent() || !current.current() || authorize(ctx) != nil {
		return "", loadbalancestream.ErrRuntime
	}
	p.promoted = true
	return core.Hash(string(p.proposal)), nil
}

func (w *loadBalanceStreamControlOwner) configurationPhase(ctx context.Context, phase string) ([]byte, error) {
	if w.current(ctx) != nil {
		return nil, errLoadBalanceStreamInstallationGate
	}
	raw, _, chain, err := w.gate.journal.original(ctx)
	if err != nil || chain.Complete || len(chain.Events) == 0 || chain.Events[len(chain.Events)-1].Phase != phase || !bytes.Equal(raw, w.gate.seed) {
		return nil, errLoadBalanceStreamInstallationGate
	}
	return raw, nil
}

func stageLoadBalanceStreamOwnedConfigurationAt(ctx context.Context, w *loadBalanceStreamControlOwner, pub *os.Root, pubCurrent func() bool, original *loadBalanceStreamConfigurationFile) (*loadBalanceStreamConfigurationPublication, error) {
	raw, err := w.configurationPhase(ctx, "configuration-intent")
	if err != nil || pub == nil || original == nil || original.root == nil || original.root.Name() != loadBalanceStreamConfigurationRoot || original.gid != w.gate.installed.identity.GID {
		return nil, errLoadBalanceStreamInstallationGate
	}
	seed, err := loadbalancestream.DecodeControlSeed(raw)
	if err != nil || pub.Name() != filepath.Join(loadBalanceStreamConfigurationPublicationsRoot, seed.Operation.RequestID) {
		return nil, errLoadBalanceStreamInstallationGate
	}
	return stageStreamConfigurationAt(ctx, pub, pubCurrent, original, raw, func(ctx context.Context) error {
		_, err := w.configurationPhase(ctx, "configuration-intent")
		return err
	})
}

func (p *loadBalanceStreamConfigurationPublication) promoteOwned(ctx context.Context, w *loadBalanceStreamControlOwner) (string, error) {
	if p == nil || !p.syntaxIssued || !p.syntaxVerified || p.original == nil || p.original.root == nil || p.publication == nil {
		return "", errLoadBalanceStreamInstallationGate
	}
	raw, err := w.configurationPhase(ctx, "activation-intent")
	if err != nil || p == nil || !bytes.Equal(raw, p.seed) || p.original.root.Name() != loadBalanceStreamConfigurationRoot || p.publication.Name() != filepath.Join(loadBalanceStreamConfigurationPublicationsRoot, p.request) || p.original.gid != w.gate.installed.identity.GID {
		return "", errLoadBalanceStreamInstallationGate
	}
	return p.promoteAt(ctx, func(ctx context.Context) error { _, err := w.configurationPhase(ctx, "activation-intent"); return err })
}
