//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

func statisticsGeoFailedUnitID(name string) (string, bool) {
	const prefix = "panel-statistics-geodata@"
	id := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".service")
	return id, core.ValidID(id) && name == prefix+id+".service"
}

// Only this fixed worker's explicit exit-code failure is covered. A timeout,
// signal, active process, control job, foreign kill policy or ambiguous show
// result remains an upgrade blocker. Never reset-failed/stop/restart the unit.
func statisticsGeoFailedUnitStopped(raw string) bool {
	want := map[string]string{"LoadState": "loaded", "ActiveState": "failed", "SubState": "failed", "MainPID": "0", "ControlPID": "0", "Result": "exit-code", "ExecMainCode": "1", "ExecMainStatus": "1", "Job": "", "KillMode": "control-group"}
	if len(raw) > 2048 || strings.ContainsAny(raw, "\x00\r") {
		return false
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		expected, known := want[key]
		if !ok || !known || seen[key] || value != expected {
			return false
		}
		seen[key] = true
	}
	return len(seen) == len(want)
}

func closedStatisticsGeoFailedInstall(ctx context.Context, name string, run Command) bool {
	id, valid := statisticsGeoFailedUnitID(name)
	if !valid || ctx.Err() != nil || os.Geteuid() != 0 {
		return false
	}
	stopped := func() bool {
		raw, err := run(ctx, "/usr/bin/systemctl", "show", name, "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Result,ExecMainCode,ExecMainStatus,Job,KillMode", "--no-pager")
		return err == nil && statisticsGeoFailedUnitStopped(raw)
	}
	if !stopped() {
		return false
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return false
	}
	defer reader.db.Close()
	proof := statisticsGeoFailedUpgradeProof{jobs: productionStatisticsGeoJobArchiveStore(), trust: appcatalog.Default(), now: time.Now, validate: func(ctx context.Context, result core.StatisticsGeoOperation) error {
		if !reader.current() {
			return errors.New("地域终态 Core 数据库身份变化")
		}
		if err := (&core.Store{DB: reader.db}).ValidateStatisticsGeoFailedInstall(ctx, result); err != nil {
			return err
		}
		if !reader.current() {
			return errors.New("地域终态 Core 数据库身份变化")
		}
		return nil
	}}
	return proof.check(ctx, id) == nil && stopped() && ctx.Err() == nil
}

// Unexported fixture seam; the public preflight always uses fixed production
// roots, compiled ORIGINAL application trust and the readonly Core reader.
// There is no marker, allowlist, alternate-root CLI or new closure receipt.
type statisticsGeoFailedUpgradeProof struct {
	jobs     statisticsGeoJobArchiveStore
	trust    *appcatalog.Client
	now      func() time.Time
	validate func(context.Context, core.StatisticsGeoOperation) error
}

func (p statisticsGeoFailedUpgradeProof) check(ctx context.Context, id string) error {
	bad := errors.New("地域失败任务缺少匹配的原始双侧终态；阻止程序升级")
	if ctx.Err() != nil || p.trust == nil || p.now == nil || p.validate == nil || !core.ValidID(id) {
		return bad
	}
	request, envelope, base, root, err := readStatisticsGeoJobAt(p.jobs, id)
	if err != nil {
		return err
	}
	defer base.Close()
	defer root.Close()
	archived := base.path == p.jobs.archive
	lock, err := root.OpenFile("install.lock", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return bad
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
		return bad
	}
	li, err := lock.Stat()
	visible, ve := root.Lstat("install.lock")
	if err != nil || ve != nil || !moduleRecordInfo(li, false, false) || li.Size() != 0 || !geoStoreStableInfo(li, visible) {
		return bad
	}
	files, err := statisticsGeoJobFileIdentities(root)
	if err != nil {
		return err
	}
	row, err := statisticsGeoJobRecord(root, id, archived)
	if err != nil || row.State != "failed" || request.Selection.Action != "install" {
		return bad
	}
	raw, err := geoStoreRead(root, "result.json", 32<<10)
	var result core.StatisticsGeoOperation
	if err != nil || decodeStatisticsGeoPrivate(raw, &result) != nil || result.JobID != id || result.Selection != request.Selection || result.State != "failed" {
		return bad
	}
	in, err := appcatalog.DecodeGeoDataEnvelope(envelope)
	if err != nil {
		return err
	}
	authority, err := p.trust.VerifyGeoDataEnvelope(in, request.Selection.AppVersion, request.Selection.AppManifestSHA, p.now(), nil)
	if err != nil || authority.Data().SHA256() != request.Selection.DataManifestSHA || authority.Data().Manifest().Release != request.Selection.Release {
		return bad
	}
	if err = p.validate(ctx, result); err != nil {
		return err
	}
	if err = p.jobs.checkpoint("before-upgrade-failed-final"); err != nil {
		return err
	}
	final, err := statisticsGeoJobRecord(root, id, archived)
	finalFiles, fe := statisticsGeoJobFileIdentities(root)
	info, e := base.Lstat(id)
	opened, oe := root.Stat(".")
	if err != nil || fe != nil || final != row || !statisticsGeoJobSameFiles(files, finalFiles) || e != nil || oe != nil || !os.SameFile(info, opened) || !base.current() || ctx.Err() != nil {
		return bad
	}
	// Reopening both fixed namespaces detects moved/detached or newly duplicated
	// IDs. A valid archived original is allowed, never a second copy or repair.
	lastBase, lastRoot, lastArchived, err := p.jobs.openJob(id)
	if err != nil {
		return err
	}
	lastInfo, e := lastRoot.Stat(".")
	current := lastBase.current()
	lastRoot.Close()
	lastBase.Close()
	if e != nil || !current || lastArchived != archived || !os.SameFile(opened, lastInfo) {
		return bad
	}
	if err = p.validate(ctx, result); err != nil {
		return err
	}
	return ctx.Err()
}
