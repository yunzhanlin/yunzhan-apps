//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// The fixed dependency child has no network RPC. This adapter joins the
// actual original parent, current Core revision, independently signed envelope,
// global leases and durable create-once protocol before invoking shadow-utils.
// A failed/uncertain attempt is retained; neither account nor intent is erased.
func prepareLoadBalanceStreamSystemAccount(ctx context.Context, parent *loadBalanceStreamAccountParent) (loadBalanceStreamIdentity, error) {
	empty := loadBalanceStreamIdentity{}
	if ctx == nil || ctx.Err() != nil || parent == nil ||
		parent.permitRecord == nil || parent.permitRecord.value != parent.permit || !parent.permitRecord.current() ||
		!loadBalanceStreamProgrammeInputsMatch(loadBalanceStreamCompiledProgrammeInputsSHA256, parent.permit.ProgrammeInputsSHA256) ||
		checkLoadBalanceStreamAccountChildKernel(ctx, parent) != nil {
		return empty, errLoadBalanceStreamAccount
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	configuration, err := holdLoadBalanceStreamNSSConfiguration(ctx)
	if err != nil {
		return empty, err
	}
	defer configuration.close()
	source, err := openLoadBalanceStreamCoreAuthority(ctx)
	if err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	defer source.close()
	seedRaw, records, _, err := parent.j.original(ctx)
	if err != nil || len(records) != 2 || !loadbalancestream.AccountChildPermitBindsSeed(parent.permit, seedRaw) {
		return empty, errLoadBalanceStreamAccount
	}
	seed, err := loadbalancestream.DecodeInstallationSeed(seedRaw)
	if err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	grant, err := source.installAuthority(ctx, seed.JobID)
	if err != nil || !loadBalanceStreamInstallationGrantMatches(seedRaw, grant) {
		return empty, errLoadBalanceStreamAccount
	}
	bound, stop := context.WithTimeout(ctx, 3*time.Second)
	lifetime, err := acquireMemcachedUnixRuntime(bound)
	stop()
	if err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	defer lifetime.Close()
	// Use only shared runtime/engine lock ordering. No Docker command, daemon
	// capability or blanket pending-job exemption is inherited from the parent.
	bound, stop = context.WithTimeout(ctx, 3*time.Second)
	engine, err := loadBalanceStreamAccountComposeStore().acquire(bound)
	stop()
	if err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	defer engine.Close()
	var identity loadBalanceStreamIdentity
	err = engine.use(ctx, func(active context.Context) error {
		current := func(check context.Context) error {
			if check == nil || check.Err() != nil || !lifetime.current() || !engine.currentLocked() || !configuration.current() ||
				parent.permitRecord == nil || parent.permitRecord.value != parent.permit || !parent.permitRecord.current() ||
				!loadBalanceStreamProgrammeInputsMatch(loadBalanceStreamCompiledProgrammeInputsSHA256, parent.permit.ProgrammeInputsSHA256) ||
				checkLoadBalanceStreamAccountChildKernel(check, parent) != nil || source.checkInstall(check, grant) != nil {
				return errLoadBalanceStreamAccount
			}
			return nil
		}
		authorize := func(check context.Context) error {
			if current(check) != nil || observeLoadBalanceStreamLegacyQueues(check, current) != nil {
				return errLoadBalanceStreamAccount
			}
			if checkLoadBalanceStreamUpgrade(check, &loadBalanceStreamUpgradeOwner{source: source, original: grant, lifetime: lifetime, child: parent, compose: engine}) != nil {
				return errLoadBalanceStreamAccount
			}
			raw, chain, _, err := parent.j.original(check)
			if err != nil || len(chain) != 2 || core.Hash(string(raw)) != core.Hash(string(seedRaw)) ||
				core.Hash(string(chain[1])) != parent.permit.AccountIntentSHA256 || !loadBalanceStreamInstallationGrantMatches(raw, grant) {
				return errLoadBalanceStreamAccount
			}
			if _, err := parent.j.officialAuthority(check); err != nil {
				return errLoadBalanceStreamAccount
			}
			if !lifetime.current() || !engine.currentLocked() || check.Err() != nil {
				return errLoadBalanceStreamAccount
			}
			return nil
		}
		if authorize(active) != nil {
			return errLoadBalanceStreamAccount
		}
		store, err := openLoadBalanceStreamAccountStoreForCreation()
		if err != nil {
			return err
		}
		defer store.root.Close()
		intent := loadBalanceStreamAccountIntent{1, loadbalancestream.ServiceAccount, seed.Nonce, seed.JobID, seed.ActorID, seed.EmptyConfigurationSHA, seed.ManifestSHA256}
		ops := loadBalanceStreamAccountOps{
			authorize: authorize,
			absent: func(check context.Context) error {
				if authorize(check) != nil {
					return errLoadBalanceStreamAccount
				}
				return loadBalanceStreamAccountAbsent(check)
			},
			create: func(check context.Context) error {
				return createLoadBalanceStreamAccountOS(check, authorize)
			},
			resolve: loadBalanceStreamSystemIdentity,
		}
		identity, err = prepareLoadBalanceStreamAccountAt(active, store, intent, ops)
		return err
	})
	if err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	return identity, nil
}

// The fixed child has a read-only executor namespace. It only locks an
// existing original Compose inode: Linux FLOCK permits an exclusive lock on
// an O_RDONLY descriptor. Never create the lock or grant write access to the
// Docker ledger merely to coordinate the independent account dependency.
func loadBalanceStreamAccountComposeStore() dockerMutationStore {
	store := productionDockerMutationStore()
	store.existingOnly = true
	return store
}

// Only the fixed leaf can be created. Existing modes/contents are never fixed,
// replaced or removed; an incomplete private store remains a visible refusal.
func openLoadBalanceStreamAccountStoreForCreation() (*loadBalanceStreamOSAccountStore, error) {
	parent := filepath.Dir(loadBalanceStreamAccountStorePath)
	if os.Geteuid() != 0 || threatIDSTrustedParents(parent, false) != nil {
		return nil, errLoadBalanceStreamAccount
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, errLoadBalanceStreamAccount
	}
	defer root.Close()
	leaf := filepath.Base(loadBalanceStreamAccountStorePath)
	if _, err := root.Lstat(leaf); errors.Is(err, os.ErrNotExist) {
		if root.Mkdir(leaf, 0700) != nil || ruleFeedStoreSync(root) != nil {
			return nil, errLoadBalanceStreamAccount
		}
	} else if err != nil {
		return nil, errLoadBalanceStreamAccount
	}
	return openLoadBalanceStreamAccountStoreAt(loadBalanceStreamAccountStorePath)
}

type loadBalanceStreamAccountTool struct {
	path   string
	file   *os.File
	before os.FileInfo
}

func (tool *loadBalanceStreamAccountTool) current() bool {
	if tool == nil || tool.file == nil || threatIDSTrustedParents(filepath.Dir(tool.path), false) != nil {
		return false
	}
	held, e1 := tool.file.Stat()
	visible, e2 := os.Lstat(tool.path)
	return e1 == nil && e2 == nil && geoStoreStableInfo(tool.before, held) && geoStoreStableInfo(held, visible)
}

func openLoadBalanceStreamAccountTool(path string) (*loadBalanceStreamAccountTool, error) {
	if path != "/usr/sbin/useradd" && path != "/usr/sbin/nologin" || os.Geteuid() != 0 || threatIDSTrustedParents(filepath.Dir(path), false) != nil {
		return nil, errLoadBalanceStreamAccount
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errLoadBalanceStreamAccount
	}
	fail := func() (*loadBalanceStreamAccountTool, error) { f.Close(); return nil, errLoadBalanceStreamAccount }
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || info.Size() < 4 || info.Size() > 16<<20 {
		return fail()
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != 0 || s.Gid != 0 || s.Nlink != 1 {
		return fail()
	}
	magic := make([]byte, 4)
	if n, err := f.ReadAt(magic, 0); err != nil || n != 4 || string(magic) != "\x7fELF" {
		return fail()
	}
	tool := &loadBalanceStreamAccountTool{path, f, info}
	if !tool.current() {
		return fail()
	}
	return tool, nil
}

// Invoked only once by the durable prepare protocol above. No general runner,
// user-selected argv/path, retry loop, account deletion or secret output exists.
func createLoadBalanceStreamAccountOS(ctx context.Context, authorize func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || authorize == nil || authorize(ctx) != nil || loadBalanceStreamAccountAbsent(ctx) != nil {
		return errLoadBalanceStreamAccount
	}
	configuration, err := holdLoadBalanceStreamNSSConfiguration(ctx)
	if err != nil {
		return err
	}
	defer configuration.close()
	tool, err := openLoadBalanceStreamAccountTool("/usr/sbin/useradd")
	if err != nil {
		return err
	}
	defer tool.file.Close()
	shell, err := openLoadBalanceStreamAccountTool("/usr/sbin/nologin")
	if err != nil {
		return err
	}
	defer shell.file.Close()
	var files []*memcachedUnixNSSFile
	var before, after [][]byte
	defer func() {
		for _, f := range files {
			f.file.Close()
		}
		for _, list := range [][][]byte{before, after} {
			for _, raw := range list {
				clear(raw)
			}
		}
	}()
	read := func() ([][]byte, error) {
		var raw [][]byte
		for _, name := range []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"} {
			f, body, err := openMemcachedUnixNSSFile(name)
			if err != nil {
				for _, body := range raw {
					clear(body)
				}
				return nil, errLoadBalanceStreamAccount
			}
			files, raw = append(files, f), append(raw, body)
		}
		return raw, nil
	}
	before, err = read()
	if err != nil || validateLoadBalanceStreamAccountCreationSources(before) != nil || authorize(ctx) != nil {
		return errLoadBalanceStreamAccount
	}
	for _, f := range files {
		if !f.current() {
			return errLoadBalanceStreamAccount
		}
	}
	if !tool.current() || !shell.current() || !configuration.current() || ctx.Err() != nil {
		return errLoadBalanceStreamAccount
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Intentional procfs descriptor execution of the already-pinned native ELF,
	// never resolution of a changed named program between validation and exec.
	cmd := exec.CommandContext(child, "/proc/self/fd/3", loadBalanceStreamAccountCreationArgs()...)
	cmd.Args[0], cmd.ExtraFiles = "/usr/sbin/useradd", []*os.File{tool.file}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = io.Discard, io.Discard, time.Second
	if cmd.Run() != nil || child.Err() != nil || !tool.current() || !shell.current() || !configuration.current() {
		return errLoadBalanceStreamAccount
	}
	after, err = read()
	if err != nil {
		return errLoadBalanceStreamAccount
	}
	identity, err := validateLoadBalanceStreamAccountCreationDelta(before, after)
	if err != nil {
		return errLoadBalanceStreamAccount
	}
	actual, err := loadBalanceStreamSystemIdentity(ctx)
	if err != nil || actual != identity {
		return errLoadBalanceStreamAccount
	}
	for _, f := range files[4:] {
		if !f.current() {
			return errLoadBalanceStreamAccount
		}
	}
	// The outer prepare protocol persists ownership of an observed successful
	// identity before its final authorization check; do not erase it on revoke.
	return nil
}
