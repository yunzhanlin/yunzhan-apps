//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"local/panel/internal/core"
)

// This private handoff is immutable metadata, not an effect/recovery permit.
// The fixed original parent independently rechecks Core, signature, programme,
// native leases and its own actual unit before creating a new journal.
type loadBalanceStreamHeldSubmission struct {
	root                     *os.Root
	file                     *os.File
	directory                os.FileInfo
	before                   os.FileInfo
	raw                      []byte
	value                    core.LoadBalanceStreamInstallSubmission
	creator                  bool
	nativeParentUnit         string
	nativeParentExitObserved bool
}

func (r *loadBalanceStreamHeldSubmission) close() {
	if r != nil {
		r.creator = false
		r.nativeParentExitObserved = false
		r.nativeParentUnit = ""
		clear(r.raw)
		clear(r.value.Release.Catalog)
		clear(r.value.Release.Signature)
		clear(r.value.Release.AppManifest)
		if r.file != nil {
			r.file.Close()
			r.file = nil
		}
		if r.root != nil {
			r.root.Close()
			r.root = nil
		}
	}
}

func (r *loadBalanceStreamHeldSubmission) current() bool {
	if r == nil || r.root == nil || r.file == nil || !core.ValidID(r.value.JobID) || threatIDSTrustedParents(loadBalanceStreamSubmissionsRoot, false) != nil {
		return false
	}
	dir, e1 := r.root.Stat(".")
	namedDir, e2 := os.Lstat(loadBalanceStreamSubmissionsRoot)
	held, e3 := r.file.Stat()
	visible, e4 := r.root.Lstat(r.value.JobID + ".json")
	return e1 == nil && e2 == nil && e3 == nil && e4 == nil && memcachedUnixAdminDirectoryInfo(dir) && memcachedUnixAdminDirectoryInfo(namedDir) && os.SameFile(r.directory, dir) && os.SameFile(dir, namedDir) && geoStoreStableInfo(r.before, held) && geoStoreStableInfo(held, visible)
}

func loadBalanceStreamSubmissionInventory(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	defer dir.Close()
	entries, err := dir.ReadDir(129)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 128 {
		return errLoadBalanceStreamInstallationJournal
	}
	for _, entry := range entries {
		name := entry.Name()
		info, err := root.Lstat(name)
		if !strings.HasSuffix(name, ".json") || !core.ValidID(strings.TrimSuffix(name, ".json")) || err != nil || !streamJournalFileInfo(info, core.LoadBalanceStreamInstallSubmissionMaxBytes) {
			return errLoadBalanceStreamInstallationJournal
		}
	}
	return nil
}

func holdLoadBalanceStreamSubmission(job string) (*loadBalanceStreamHeldSubmission, error) {
	if !core.ValidID(job) {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	root, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamSubmissionsRoot, false)
	if err != nil {
		return nil, err
	}
	r := &loadBalanceStreamHeldSubmission{root: root}
	fail := func() (*loadBalanceStreamHeldSubmission, error) {
		r.close()
		return nil, errLoadBalanceStreamInstallationJournal
	}
	r.directory, err = root.Stat(".")
	if err != nil || loadBalanceStreamSubmissionInventory(root) != nil {
		return fail()
	}
	r.file, err = root.OpenFile(job+".json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fail()
	}
	r.before, err = r.file.Stat()
	if err != nil || !streamJournalFileInfo(r.before, core.LoadBalanceStreamInstallSubmissionMaxBytes) {
		return fail()
	}
	r.raw, err = io.ReadAll(io.LimitReader(r.file, core.LoadBalanceStreamInstallSubmissionMaxBytes+1))
	if err != nil || int64(len(r.raw)) != r.before.Size() {
		return fail()
	}
	r.value, err = core.DecodeLoadBalanceStreamInstallSubmission(r.raw)
	if err != nil || r.value.JobID != job || !r.current() {
		return fail()
	}
	return r, nil
}

// The production submitter must hold the original global runtime/L4 leases
// and pass its actual live Core/signature authority recheck. Never use an
// existing handoff as permission to dispatch a fixed unit again.
func writeLoadBalanceStreamSubmission(ctx context.Context, in core.LoadBalanceStreamInstallSubmission, authorize func(context.Context) error) (*loadBalanceStreamHeldSubmission, error) {
	raw, err := core.LoadBalanceStreamInstallSubmissionBytes(in)
	if ctx == nil || ctx.Err() != nil || err != nil || authorize == nil || authorize(ctx) != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	root, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamSubmissionsRoot, true)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if loadBalanceStreamSubmissionInventory(root) != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	entries, readErr := dir.ReadDir(129)
	dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) >= 128 || authorize(ctx) != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	f, err := root.OpenFile(in.JobID+".json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	defer f.Close()
	if f.Chown(0, 0) != nil || f.Chmod(0600) != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) || f.Sync() != nil || ruleFeedStoreSync(root) != nil {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	held, err := holdLoadBalanceStreamSubmission(in.JobID)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(held.raw, raw) || !held.current() || authorize(ctx) != nil {
		held.close()
		return nil, errLoadBalanceStreamInstallationJournal
	}
	held.creator = true
	return held, nil
}
