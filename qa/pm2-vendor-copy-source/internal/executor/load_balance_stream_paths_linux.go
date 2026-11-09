//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"local/panel/internal/core"
)

const loadBalanceStreamSubmissionsRoot = "/var/lib/panel-executor/load-balance-stream-install-submissions"
const loadBalanceStreamMutationLockPath = "/var/lib/panel-executor/load-balance-stream.lock"

// A fixed namespace only. Existing nodes are validated, never repaired,
// chowned, emptied or adopted as a new operation. Runtime leases and fresh
// original authority are independent prerequisites of every production caller.
func openLoadBalanceStreamFixedRoot(path string, create bool) (*os.Root, error) {
	if path != loadBalanceStreamInstallationJobsRoot && path != loadBalanceStreamModulePublicationsRoot && path != loadBalanceStreamSubmissionsRoot && path != loadBalanceStreamInstallationsRoot && path != loadBalanceStreamInstallObservationsRoot && path != loadBalanceStreamStateRoot && path != loadBalanceStreamJobsRoot && path != loadBalanceStreamGenerationPublicationsRoot && path != loadBalanceStreamConfigurationPublicationsRoot ||
		os.Geteuid() != 0 || threatIDSTrustedParents(filepath.Dir(path), false) != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	if create {
		parent, err := os.OpenRoot(filepath.Dir(path))
		if err != nil {
			return nil, errLoadBalanceStreamInstallationJournal
		}
		defer parent.Close()
		if _, err := parent.Lstat(filepath.Base(path)); errors.Is(err, os.ErrNotExist) {
			if createStreamRootPrivateDirectory(parent, filepath.Base(path)) != nil {
				return nil, errLoadBalanceStreamInstallationJournal
			}
		} else if err != nil {
			return nil, errLoadBalanceStreamInstallationJournal
		}
	}
	return streamJournalAnchor(path)
}

// Only a freshly exclusive JOB leaf is returned for writing. Directory
// metadata may change as this creator appends files, but its named inode,
// ancestry, Root ownership and private mode must remain the same throughout.
func createLoadBalanceStreamPublicationRoot(ctx context.Context, job string) (*os.Root, func() bool, error) {
	if ctx == nil || ctx.Err() != nil || !core.ValidID(job) {
		return nil, nil, errLoadBalanceStreamModule
	}
	anchor, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamModulePublicationsRoot, true)
	if err != nil {
		return nil, nil, err
	}
	defer anchor.Close()
	dir, err := anchor.Open(".")
	if err != nil {
		return nil, nil, errLoadBalanceStreamModule
	}
	entries, err := dir.ReadDir(129)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) >= 128 {
		return nil, nil, errLoadBalanceStreamModule
	}
	for _, entry := range entries {
		info, err := anchor.Lstat(entry.Name())
		if !core.ValidID(entry.Name()) || err != nil || !memcachedUnixAdminDirectoryInfo(info) {
			return nil, nil, errLoadBalanceStreamModule
		}
	}
	if ctx.Err() != nil || createStreamRootPrivateDirectory(anchor, job) != nil {
		return nil, nil, errLoadBalanceStreamModule
	}
	root, err := anchor.OpenRoot(job)
	if err != nil {
		return nil, nil, errLoadBalanceStreamModule
	}
	before, err := root.Stat(".")
	path := filepath.Join(loadBalanceStreamModulePublicationsRoot, job)
	current := func() bool {
		if threatIDSTrustedParents(filepath.Dir(path), false) != nil {
			return false
		}
		a, e1 := root.Stat(".")
		b, e2 := os.Lstat(path)
		return e1 == nil && e2 == nil && memcachedUnixAdminDirectoryInfo(a) && memcachedUnixAdminDirectoryInfo(b) && os.SameFile(before, a) && os.SameFile(a, b)
	}
	if err != nil || !current() {
		root.Close()
		return nil, nil, errLoadBalanceStreamModule
	}
	return root, current, nil
}

type loadBalanceStreamMutationLease struct {
	file   *os.File
	before os.FileInfo
}

func (l *loadBalanceStreamMutationLease) close() {
	if l != nil && l.file != nil {
		l.file.Close()
		l.file = nil
	}
}
func (l *loadBalanceStreamMutationLease) current() bool {
	if l == nil || l.file == nil || threatIDSTrustedParents(filepath.Dir(loadBalanceStreamMutationLockPath), false) != nil {
		return false
	}
	a, e1 := l.file.Stat()
	b, e2 := os.Lstat(loadBalanceStreamMutationLockPath)
	return e1 == nil && e2 == nil && streamJournalFileInfo(a, 0) && geoStoreStableInfo(l.before, a) && geoStoreStableInfo(a, b)
}

func acquireLoadBalanceStreamMutation(ctx context.Context) (*loadBalanceStreamMutationLease, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || threatIDSTrustedParents(filepath.Dir(loadBalanceStreamMutationLockPath), false) != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	parent, err := os.OpenRoot(filepath.Dir(loadBalanceStreamMutationLockPath))
	if err != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	defer parent.Close()
	f, err := openStreamRootMutationFile(parent, filepath.Base(loadBalanceStreamMutationLockPath))
	if err != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	l := &loadBalanceStreamMutationLease{file: f}
	l.before, err = f.Stat()
	if err != nil || !l.current() {
		l.close()
		return nil, errLoadBalanceStreamInstallationJournal
	}
	for {
		if ctx.Err() != nil || !l.current() {
			l.close()
			return nil, errLoadBalanceStreamInstallationJournal
		}
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return l, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			l.close()
			return nil, errLoadBalanceStreamInstallationJournal
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			l.close()
			return nil, errLoadBalanceStreamInstallationJournal
		case <-timer.C:
		}
	}
}

// Root:panel is the real long-lived RPC process profile. Only a newly
// exclusive inode is chowned through its held descriptor. An old directory
// is NEVER fixed/adopted, even if it has the expected name or private mode.
func createStreamRootPrivateDirectory(parent *os.Root, name string) error {
	if os.Geteuid() != 0 || parent == nil || filepath.Base(name) != name || name == "." || name == ".." || name == "" {
		return errLoadBalanceStreamInstallationJournal
	}
	if err := parent.Mkdir(name, 0700); err != nil {
		return err
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	defer child.Close()
	f, err := child.Open(".")
	if err != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	defer f.Close()
	before, err := f.Stat()
	visible, e1 := parent.Lstat(name)
	if err != nil || e1 != nil || !moduleRecordInfo(before, true, false) || !geoStoreStableInfo(before, visible) {
		return errLoadBalanceStreamInstallationJournal
	}
	if f.Chown(0, 0) != nil || f.Sync() != nil || ruleFeedStoreSync(parent) != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	after, e1 := f.Stat()
	named, e2 := parent.Lstat(name)
	if e1 != nil || e2 != nil || !os.SameFile(before, after) || !memcachedUnixAdminDirectoryInfo(after) || !geoStoreStableInfo(after, named) {
		return errLoadBalanceStreamInstallationJournal
	}
	return nil
}

func openStreamRootMutationFile(parent *os.Root, name string) (*os.File, error) {
	if os.Geteuid() != 0 || parent == nil || name != "load-balance-stream.lock" {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	flags := os.O_RDWR | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	f, err := parent.OpenFile(name, flags|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		// Only THIS new original descriptor is mutable. Existing files are
		// opened without O_CREATE and retain their original ownership/mode.
		if f.Chown(0, 0) != nil || f.Sync() != nil || ruleFeedStoreSync(parent) != nil {
			f.Close()
			return nil, errLoadBalanceStreamInstallationJournal
		}
	} else if errors.Is(err, os.ErrExist) {
		f, err = parent.OpenFile(name, flags, 0)
	}
	if err != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	held, e1 := f.Stat()
	visible, e2 := parent.Lstat(name)
	if e1 != nil || e2 != nil || !streamJournalFileInfo(held, 0) || !geoStoreStableInfo(held, visible) {
		f.Close()
		return nil, errLoadBalanceStreamInstallationJournal
	}
	return f, nil
}
