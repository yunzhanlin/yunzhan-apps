//go:build linux

package executor

import (
	"errors"
	"io"
	"local/panel/internal/core"
	"path/filepath"
	"strings"
	"syscall"
)

func (r *programQueueReader) platformMaintenanceJobs() error {
	relative := "var/lib/panel-executor/platform-maintenance-jobs"
	root, e := r.directory(relative)
	if e != nil || root == nil {
		return e
	}
	defer root.Close()
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	entries, e := f.ReadDir(3*core.PlatformMaintenanceOperationLimit + 1)
	f.Close()
	if e != nil && !errors.Is(e, io.EOF) || len(entries) > 3*core.PlatformMaintenanceOperationLimit {
		return errors.New("maintenance complete inventory exceeds budget")
	}
	members := map[string]map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		parts := strings.Split(name, ".")
		if len(parts) != 2 && len(parts) != 3 || !core.ValidID(parts[0]) || len(parts) == 2 && parts[1] != "lock" || len(parts) == 3 && (parts[1] != "request" && parts[1] != "result" || parts[2] != "json") {
			return errors.New("unknown or orphan maintenance entry")
		}
		if members[parts[0]] == nil {
			members[parts[0]] = map[string]bool{}
		}
		members[parts[0]][strings.Join(parts[1:], ".")] = true
	}
	if len(members) > core.PlatformMaintenanceOperationLimit {
		return errors.New("maintenance operation count exceeds budget")
	}
	for id, files := range members {
		if len(files) != 3 || !files["lock"] || !files["request.json"] || !files["result.json"] {
			return errors.New("maintenance original request unfinished; upgrade refused")
		}
		lock, e := root.OpenFile(id+".lock", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return e
		}
		info, e := lock.Stat()
		if e != nil || !runtimeInstallPrivateFile(info) || info.Size() != 0 || syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) != nil {
			lock.Close()
			return errors.New("maintenance lock invalid or command active")
		}
		visible, e := root.Lstat(id + ".lock")
		if e != nil || !programQueueSame(info, visible) {
			lock.Close()
			return errors.New("maintenance original lock changed")
		}
		r.snapshots = append(r.snapshots, programQueueSnapshot{filepath.Join(r.root, relative, id+".lock"), visible})
		request, e := r.record(root, relative, id+".request.json", 4096)
		if e != nil {
			lock.Close()
			return e
		}
		var started core.PlatformMaintenanceRecord
		if decodeProgramQueueJSON(request, &started) != nil || core.ValidatePlatformMaintenanceRecord(started) != nil || started.State != "started" || started.Request.Input.RequestID != id {
			lock.Close()
			return errors.New("maintenance original start record invalid")
		}
		if _, e = core.DecodePlatformMaintenanceRecord(request, started.Request); e != nil {
			lock.Close()
			return e
		}
		result, e := r.record(root, relative, id+".result.json", 4096)
		lock.Close()
		if e != nil {
			return e
		}
		out, e := core.DecodePlatformMaintenanceRecord(result, started.Request)
		if e != nil || out.State == "started" {
			return errors.New("maintenance terminal result cannot be verified")
		}
	}
	return nil
}
