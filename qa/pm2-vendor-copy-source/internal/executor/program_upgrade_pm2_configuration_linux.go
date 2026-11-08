//go:build linux

package executor

import (
	"errors"
	"io"
	"path/filepath"
)

func (r *programQueueReader) pm2Configurations() error {
	relative := "etc/panel/security-apps/modules/pm2-manager/configuration-transactions"
	root, err := r.directory(relative)
	if err != nil || root == nil {
		return err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(2*pm2ConfigIntentLimit + 1)
	if closeErr := dir.Close(); closeErr != nil {
		return errors.Join(err, closeErr)
	}
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 2*pm2ConfigIntentLimit {
		return errors.New("PM2 configuration complete upgrade inventory exceeds budget")
	}
	files := map[string][]byte{}
	// The new PM2 namespace has its own fixed 64 MiB ceiling. Never spend or
	// enlarge the historical queues' independently pinned 16 MiB budget.
	total := 0
	for _, entry := range entries {
		if err = r.ctx.Err(); err != nil {
			return err
		}
		before, statErr := root.Lstat(entry.Name())
		if statErr != nil || !runtimeInstallPrivateFile(before) {
			return errors.New("PM2 configuration record identity is not private")
		}
		raw, readErr := pm2ConfigReadRoot(root, entry.Name(), func() bool { return r.ctx.Err() == nil })
		if readErr != nil {
			return readErr
		}
		total += len(raw)
		if total > 64<<20 {
			return errors.New("PM2 complete configuration namespace exceeds its independent byte budget")
		}
		after, statErr := root.Lstat(entry.Name())
		if statErr != nil || !programQueueSame(before, after) {
			return errors.New("PM2 configuration changed during upgrade preflight")
		}
		r.snapshots = append(r.snapshots, programQueueSnapshot{filepath.Join(r.root, relative, entry.Name()), after})
		files[entry.Name()] = raw
	}
	if err = pm2ConfigSyncRoot(root, func() bool { return r.ctx.Err() == nil }); err != nil {
		return err
	}
	records, err := decodePM2ConfigurationRecords(files)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Receipt == nil && record.Cancellation == nil {
			return errors.New("PM2 configuration transaction remains unresolved; upgrade refused")
		}
	}
	return nil
}
