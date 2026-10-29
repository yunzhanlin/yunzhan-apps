//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

func countryFailedUnitID(name string) (string, bool) {
	const prefix = "panel-waf-country@"
	id := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".service")
	return id, core.ValidID(id) && name == prefix+id+".service"
}

func countryFailedUnitStopped(raw string) bool {
	wanted := map[string]string{"LoadState": "loaded", "ActiveState": "failed", "SubState": "failed", "MainPID": "0", "ControlPID": "0", "Result": "exit-code", "ExecMainCode": "1", "ExecMainStatus": "1", "Job": "", "KillMode": "control-group", "FragmentPath": "/etc/systemd/system/panel-waf-country@.service", "DropInPaths": "", "NeedDaemonReload": "no", "Transient": "no"}
	if len(raw) < 1 || len(raw) > 4096 || strings.ContainsAny(raw, "\x00\r") {
		return false
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		want, known := wanted[key]
		if !ok || !known || seen[key] || value != want {
			return false
		}
		seen[key] = true
	}
	return len(seen) == len(wanted)
}

func countryFailedUnitSource() (os.FileInfo, error) {
	const path = "/etc/systemd/system/panel-waf-country@.service"
	if err := statisticsGeoParents("/etc/systemd/system"); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Gid != 0 || owner.Nlink != 1 || !info.Mode().IsRegular() || info.Mode() != 0644 {
		return nil, errors.New("country failed unit source is not the original Root file")
	}
	raw, err := apacheWAFReadStableFile(path, 16<<10)
	if err != nil || string(raw) != countryTaskUnitBody && string(raw) != strings.ReplaceAll(countryTaskUnitBody, "/opt/panel/bin/", "/opt/panel/current/bin/") {
		return nil, errors.New("country failed unit differs from fixed signed source")
	}
	return info, nil
}

func verifyCountryFailedEnvelope(request countryTaskRequest, raw []byte) error {
	in, err := appcatalog.DecodeGeoDataEnvelope(raw)
	if err != nil {
		return err
	}
	// Historical validation at the sealed original admission time grants no
	// current download or activation authority and does not refresh old data.
	at, err := time.Parse(time.RFC3339, request.PreparedAt)
	if err != nil {
		return err
	}
	a, err := appcatalog.Default().VerifyCountryDataEnvelope(in, request.Selection.AppVersion, request.Selection.AppManifestSHA, at, nil)
	if err != nil || a.Data().SHA256() != request.Selection.DataManifestSHA || a.Data().Manifest().Release != request.Selection.Release || a.Data().Manifest().Revision != request.Selection.Revision {
		return errors.New("country failed original signed authority differs")
	}
	_, err = a.Data().Select(request.Selection.Countries)
	return err
}

// Only the fixed original worker's normal exit1 is considered, after every
// original Root file, signed envelope and matching full Core failure is checked.
// No reset-failed, kill, start, recovery receipt or selected-ID exemption exists.
func closedCountryFailedTask(ctx context.Context, name string, run Command) bool {
	id, valid := countryFailedUnitID(name)
	if !valid || ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return false
	}
	info, err := countryFailedUnitSource()
	if err != nil {
		return false
	}
	stopped := func() bool {
		raw, err := run(ctx, "/usr/bin/systemctl", "show", name, "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Result,ExecMainCode,ExecMainStatus,Job,KillMode,FragmentPath,DropInPaths,NeedDaemonReload,Transient", "--no-pager")
		return err == nil && countryFailedUnitStopped(raw)
	}
	if !stopped() {
		return false
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return false
	}
	defer reader.db.Close()
	proof := countryFailedUpgradeProof{jobs: productionCountryTaskStore(), verify: verifyCountryFailedEnvelope, validate: func(ctx context.Context, result core.WAFCountryDataOperation) error {
		if !reader.current() {
			return errors.New("country failed original Core identity changed")
		}
		if err := (&core.Store{DB: reader.db}).ValidateWAFCountryFailedNative(ctx, result); err != nil {
			return err
		}
		if !reader.current() {
			return errors.New("country failed Core changed during observation")
		}
		return nil
	}}
	if proof.check(ctx, id) != nil || !stopped() {
		return false
	}
	last, err := countryFailedUnitSource()
	return err == nil && programQueueSame(info, last) && ctx.Err() == nil
}

// Metadata fixture seam only; the public entry above constructs fixed paths,
// the original compiled signature verifier and the read-only Core validator.
type countryFailedUpgradeProof struct {
	jobs     countryTaskStore
	verify   func(countryTaskRequest, []byte) error
	validate func(context.Context, core.WAFCountryDataOperation) error
}

func (p countryFailedUpgradeProof) check(ctx context.Context, id string) error {
	bad := errors.New("country failed original does not have complete matching stopped evidence")
	if ctx == nil || ctx.Err() != nil || !core.ValidID(id) || p.verify == nil || p.validate == nil {
		return bad
	}
	base, err := p.jobs.open(false)
	if err != nil {
		return err
	}
	defer base.Close()
	shared := func(root *os.Root, name string) (*os.File, error) {
		f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		info, err := f.Stat()
		named, ne := root.Lstat(name)
		if err != nil || ne != nil || !moduleRecordInfo(info, false, false) || info.Size() != 0 || !programQueueSame(info, named) || unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
			f.Close()
			return nil, bad
		}
		return f, nil
	}
	global, err := shared(base.Root, "store.lock")
	if err != nil {
		return err
	}
	defer global.Close()
	request, envelope, dir, err := p.jobs.read(base, id)
	if err != nil {
		return err
	}
	defer dir.Close()
	worker, err := shared(dir.Root, "task.lock")
	if err != nil {
		return err
	}
	defer worker.Close()
	r := programQueueReader{ctx: ctx, root: p.jobs.base}
	globalInfo, err := global.Stat()
	if err != nil {
		return err
	}
	r.snapshots = append(r.snapshots, programQueueSnapshot{p.jobs.base + "/store.lock", globalInfo})
	if err := r.wafCountryJob(id, id, dir.Root); err != nil {
		return err
	}
	raw, err := r.record(dir.Root, id, "result.json", 32<<10)
	if err != nil {
		return err
	}
	result, err := core.DecodeWAFCountryDataOperation(raw, id, request.ActorID, request.Selection)
	if err != nil || result.State != "failed" || result.Cache != nil || result.Error == "" || result.RequestSHA != countryTaskRequestDigest(request) {
		return bad
	}
	if err := p.verify(request, envelope); err != nil {
		return err
	}
	if err := p.validate(ctx, result); err != nil {
		return err
	}
	for _, snap := range r.snapshots {
		current, err := os.Lstat(snap.path)
		if err != nil || !programQueueSame(snap.info, current) {
			return bad
		}
	}
	if !base.current() || !dir.current() || ctx.Err() != nil {
		return bad
	}
	return p.validate(ctx, result)
}
