//go:build linux

package executor

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

// A request still counts as pending even when no unit/list-jobs row exists.
// Preflight observes immutable receipts only; it never starts/replays a job.
func (r *programQueueReader) statisticsGeoJobs() error {
	if err := r.statisticsGeoJobTree("var/lib/panel-executor/statistics-geodata-jobs", core.StatisticsGeoActiveJobsMax); err != nil {
		return err
	}
	return r.statisticsGeoJobTree("var/lib/panel-executor/statistics-geodata-job-archive", core.StatisticsGeoArchivedJobsMax)
}
func (r *programQueueReader) statisticsGeoJobTree(relative string, max int) error {
	root, err := r.directory(relative)
	if err != nil || root == nil {
		return err
	}
	defer root.Close()
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(max + 1)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > max {
		return errors.New("geographic job complete inventory exceeds budget")
	}
	for _, entry := range entries {
		id := entry.Name()
		if !core.ValidID(id) || !entry.IsDir() {
			return errors.New("geographic request has unknown or unfinished stage; upgrade refused")
		}
		rel := relative + "/" + id
		child, err := r.directory(rel)
		if err != nil || child == nil {
			return errors.New("geographic job directory cannot be verified")
		}
		err = r.statisticsGeoJob(rel, id, child)
		child.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
func (r *programQueueReader) statisticsGeoJob(relative, id string, root *os.Root) error {
	if err := statisticsGeoJobContents(root, true); err != nil {
		return err
	}
	lock, err := root.OpenFile("install.lock", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		defer lock.Close()
		info, err := lock.Stat()
		if err != nil || !runtimeInstallPrivateFile(info) || info.Size() != 0 {
			return errors.New("geographic task lock identity invalid")
		}
		if syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) != nil {
			return errors.New("geographic task still running; upgrade refused")
		}
		visible, err := root.Lstat("install.lock")
		if err != nil || !programQueueSame(info, visible) {
			return errors.New("geographic task lock changed")
		}
		r.snapshots = append(r.snapshots, programQueueSnapshot{filepath.Join(r.root, relative, "install.lock"), visible})
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	requestRaw, err := r.record(root, relative, "request.json", 4096)
	if err != nil {
		return err
	}
	var request statisticsGeoRequest
	if decodeStatisticsGeoPrivate(requestRaw, &request) != nil || request.Format != 1 || request.JobID != id || core.ValidateStatisticsGeoSelection(request.Selection) != nil || !networkIDSRootSHA.MatchString(request.EnvelopeSHA) {
		return errors.New("geographic original request binding invalid")
	}
	envelope, err := r.record(root, relative, "envelope.json", appcatalog.MaxGeoDataEnvelopeBytes)
	if err != nil || core.Hash(string(envelope)) != request.EnvelopeSHA {
		return errors.New("geographic original delivery hash changed")
	}
	started, err := r.record(root, relative, "started.json", 4096)
	if err != nil {
		return errors.New("geographic request lacks verified worker-start receipt")
	}
	var marker statisticsGeoRequest
	if decodeStatisticsGeoPrivate(started, &marker) != nil || marker != request {
		return errors.New("geographic worker-start binding invalid")
	}
	resultRaw, err := r.record(root, relative, "result.json", 32<<10)
	if err != nil {
		return errors.New("geographic original request lacks terminal evidence; upgrade refused")
	}
	var result core.StatisticsGeoOperation
	if decodeStatisticsGeoPrivate(resultRaw, &result) != nil || result.JobID != id || result.Selection != request.Selection || len(result.Steps) > 16 || len(result.Error) > 1024 || result.State != "succeeded" && result.State != "failed" || result.State == "succeeded" && result.Error != "" || result.State == "failed" && result.Error == "" {
		return errors.New("geographic terminal receipt cannot be verified")
	}
	return nil
}
