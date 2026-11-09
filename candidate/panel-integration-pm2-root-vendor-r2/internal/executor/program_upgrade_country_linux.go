//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

// Upgrade admission observes the complete original journal, never constructs a
// Service or task store, starts a unit, repairs a seal or takes a writable lock.
// A missing namespace is the existing no-country-job state. Any prepared,
// interrupted, acknowledgement-unknown or malformed original blocks replacement.
func (r *programQueueReader) wafCountryJobs() error {
	const relative = "var/lib/panel-executor/waf-country-jobs"
	root, err := r.directory(relative)
	if err != nil || root == nil {
		return err
	}
	defer root.Close()
	// The real task store retains this namespace lock after every preparation.
	// Observe the existing inode without creating or repairing it, and retain a
	// shared lease through the complete queue snapshot. A writer, missing lock or
	// unsafe replacement is unfinished/unknown work, not a terminal task.
	lock, err := root.OpenFile("store.lock", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("country original namespace lock cannot be verified; upgrade refused")
	}
	opened, err := lock.Stat()
	if err != nil || !runtimeInstallPrivateFile(opened) || opened.Size() != 0 || syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) != nil {
		lock.Close()
		return errors.New("country original namespace is preparing or its lock is unsafe; upgrade refused")
	}
	named, err := root.Lstat("store.lock")
	if err != nil || !programQueueSame(opened, named) {
		lock.Close()
		return errors.New("country original namespace named lock changed")
	}
	r.readLeases = append(r.readLeases, lock)
	r.snapshots = append(r.snapshots, programQueueSnapshot{filepath.Join(r.root, relative, "store.lock"), named})
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(countryTasksMax + 2)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > countryTasksMax+1 {
		return errors.New("country original job inventory exceeds complete budget")
	}
	for _, entry := range entries {
		id := entry.Name()
		if id == "store.lock" {
			continue // The exact private inode is already validated and leased.
		}
		if !core.ValidID(id) || !entry.IsDir() {
			return errors.New("country original job has unknown or unfinished preparation; upgrade refused")
		}
		rel := relative + "/" + id
		child, err := r.directory(rel)
		if err != nil || child == nil {
			return errors.New("country original job directory cannot be verified")
		}
		err = r.wafCountryJob(rel, id, child)
		child.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *programQueueReader) wafCountryJob(relative, id string, root *os.Root) error {
	if err := countryTaskContents(root, false); err != nil {
		return err
	}
	lock, err := root.OpenFile("task.lock", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("country original task has no verifiable worker lock; upgrade refused")
	}
	defer lock.Close()
	opened, err := lock.Stat()
	if err != nil || !runtimeInstallPrivateFile(opened) || opened.Size() != 0 || syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) != nil {
		return errors.New("country original task is running or its lock is unsafe; upgrade refused")
	}
	named, err := root.Lstat("task.lock")
	if err != nil || !programQueueSame(opened, named) {
		return errors.New("country original task named lock changed")
	}
	r.snapshots = append(r.snapshots, programQueueSnapshot{filepath.Join(r.root, relative, "task.lock"), named})
	raw, err := r.record(root, relative, "request.json", 4096)
	if err != nil {
		return err
	}
	var request countryTaskRequest
	if countryCacheDecode(raw, &request) != nil || !countryTaskRequestValid(request) || request.JobID != id {
		return errors.New("country original task request cannot be fully bound")
	}
	envelope, err := r.record(root, relative, "envelope.json", appcatalog.MaxGeoDataEnvelopeBytes)
	if err != nil || core.Hash(string(envelope)) != request.EnvelopeSHA {
		return errors.New("country original full envelope digest changed")
	}
	decoded, err := appcatalog.DecodeGeoDataEnvelope(envelope)
	canonical, encoded := json.Marshal(decoded)
	if err != nil || encoded != nil || !bytes.Equal(canonical, envelope) {
		return errors.New("country original task envelope is not the complete canonical seal")
	}
	raw, err = r.record(root, relative, "dispatch.json", 4096)
	if err != nil {
		return errors.New("country original task lacks unique dispatch evidence; upgrade refused")
	}
	var dispatch countryTaskDispatch
	digest := countryTaskRequestDigest(request)
	if countryCacheDecode(raw, &dispatch) != nil || dispatch.Format != 1 || dispatch.JobID != id || dispatch.RequestSHA != digest || !countryTaskBootPattern.MatchString(dispatch.BootID) || !hardeningCanonicalTime(dispatch.SubmittedAt) {
		return errors.New("country original dispatch binding differs")
	}
	raw, err = r.record(root, relative, "started.json", 4096)
	if err != nil {
		return errors.New("country original task lacks complete worker-start evidence; upgrade refused")
	}
	var started countryTaskStarted
	if countryCacheDecode(raw, &started) != nil || started.Format != 1 || started.JobID != id || started.RequestSHA != digest || started.BootID != dispatch.BootID || started.PID < 2 || !countryTaskStartTicksValid(started.StartTicks) || !wafLogDigestValid(started.ExecutableSHA) {
		return errors.New("country original worker lifetime and request binding differ")
	}
	raw, err = r.record(root, relative, "result.json", 32<<10)
	if err != nil {
		return errors.New("country original task has no complete terminal; upgrade refused")
	}
	result, err := core.DecodeWAFCountryDataOperation(raw, id, request.ActorID, request.Selection)
	if err != nil || result.RequestSHA != digest || result.State != "succeeded" && result.State != "failed" {
		return errors.New("country original terminal is unknown, partial or needs attention; upgrade refused")
	}
	return nil
}
