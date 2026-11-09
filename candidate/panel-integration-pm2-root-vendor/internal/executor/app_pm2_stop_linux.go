//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// Stopping an already managed service does not need authority from a
// configuration transaction, dependency job or retrospective report. Those
// records are retained verbatim, including malformed and incomplete evidence.
// The live project and its original private namespace must still be known.
type pm2StopLease struct {
	directory *modulePrivateDirectory
	file      *os.File
}

func pm2VerifiedStopResult(id, action string, out any, err error) (map[string]any, bool) {
	result, ok := out.(map[string]any)
	return result, err == nil && ok && id == "pm2-manager" && action == "stop" &&
		result["action"] == "stop" && result["ok"] == true && result["state"] == "inactive" &&
		result["boot_enabled"] == false && result["service_outcome_verified"] == true &&
		result["configuration_preserved"] == true && result["configuration_or_deployment_replayed"] == false
}

func (l *pm2StopLease) Close() {
	_ = l.file.Close()
	_ = l.directory.Close()
}

func (s *Service) pm2StopProjectLease(id string) (_ *pm2StopLease, err error) {
	if !moduleResourceID.MatchString(id) {
		return nil, errors.New("PM2 项目标识无效")
	}
	d, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = d.Close()
		}
	}()
	if err = pm2ConfigChild(d, "locks", true); err != nil {
		return nil, err
	}
	name := id + ".lock"
	info, err := d.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		// First stop of a legacy project may need its ordinary private lock.
		// Existing locks are opened read-only, including a read-only mount.
		var created *os.File
		created, err = d.OpenFile(name, os.O_RDONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
		if err != nil {
			return nil, err
		}
		syncErr := created.Sync()
		closeErr := created.Close()
		if err = errors.Join(syncErr, closeErr); err != nil {
			return nil, err
		}
		if err = pm2ConfigSync(d); err != nil {
			return nil, err
		}
		info, err = d.Lstat(name)
	}
	if err != nil || !moduleRecordInfo(info, false, false) {
		return nil, errors.New("PM2 原项目锁的身份或权限无法核对；未停止服务")
	}
	f, err := d.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	opened, err := f.Stat()
	if err != nil || !programQueueSame(info, opened) || !d.current() {
		return nil, errors.New("PM2 项目锁在打开期间变化；未停止服务")
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.New("PM2 原项目仍在执行配置或部署；未停止或重放操作")
	}
	visible, err := d.Lstat(name)
	if err != nil || !programQueueSame(info, visible) || !d.current() {
		return nil, errors.New("PM2 项目锁的当前身份变化；未停止服务")
	}
	ok, keep = true, true
	return &pm2StopLease{directory: d, file: f}, nil
}

// This read does not fsync a transaction or make any old outcome durable. Its
// only authority is the existing project's fixed service name. Configuration
// and start/recovery operations retain their original durable-read checks.
func (s *Service) pm2StopApp(id string) (_ pm2App, digest string, err error) {
	var app pm2App
	d, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		return app, "", err
	}
	defer func() { err = errors.Join(err, d.Close()) }()
	if err = pm2ConfigChild(d, "apps", false); err != nil {
		return app, "", err
	}
	name := id + ".json"
	info, err := d.Lstat(name)
	if err != nil || !moduleRecordInfo(info, false, false) || info.Size() < 1 || info.Size() > 64<<10 {
		return app, "", errors.New("PM2 原项目清单身份或权限无法核对；未停止服务")
	}
	f, err := d.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return app, "", err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	opened, err := f.Stat()
	if err != nil || !programQueueSame(info, opened) || !d.current() {
		return app, "", errors.New("PM2 原项目清单打开期间变化；未停止服务")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(raw) != int(info.Size()) {
		return app, "", errors.New("PM2 原项目清单读取不完整；未停止服务")
	}
	after, afterErr := f.Stat()
	visible, visibleErr := d.Lstat(name)
	if afterErr != nil || visibleErr != nil || !programQueueSame(info, after) || !programQueueSame(info, visible) || !d.current() {
		return app, "", errors.New("PM2 原项目清单读取期间变化；未停止服务")
	}
	if decodeProgramQueueJSON(raw, &app) != nil || app.ID != id || !core.ValidID(app.SiteID) || app.Revision < 0 {
		return pm2App{}, "", errors.New("PM2 原项目与网站身份无法核对；未停止服务")
	}
	return app, pm2ConfigHash(raw), nil
}

func (s *Service) stopPM2PreservingEvidence(ctx context.Context, in core.AppModuleInput) (any, error) {
	if !moduleResourceID.MatchString(in.ResourceID) || ctx.Err() != nil {
		return nil, errors.New("PM2 停止请求的项目身份或上下文无效")
	}
	lease, err := s.pm2StopProjectLease(in.ResourceID)
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	app, digest, err := s.pm2StopApp(in.ResourceID)
	if err != nil {
		return nil, err
	}
	if in.ExpectedRevision != 0 && in.ExpectedRevision != app.Revision {
		return nil, errors.New("PM2 原项目修订已变化，请刷新当前项目后停止")
	}
	if !lease.directory.current() || !s.moduleInstalled("pm2-manager") {
		return nil, errors.New("PM2 原安装或项目锁身份变化；未停止服务")
	}
	out, err := s.controlPM2(ctx, app, "stop", "panel-pm2@"+app.ID+".service")
	if err != nil {
		return nil, err
	}
	// The current service and boot setting have been independently read back.
	// This is not a configuration commit, recovery, or receipt repair.
	current, currentDigest, readErr := s.pm2StopApp(in.ResourceID)
	if readErr != nil || current.ID != app.ID || currentDigest != digest || !lease.directory.current() {
		return nil, errors.New("PM2 服务停止后原项目身份无法继续核对；请只读检查当前服务，未重试操作")
	}
	result := out.(map[string]any)
	result["service_outcome_verified"] = true
	result["configuration_preserved"] = true
	result["original_project_sha256"] = digest
	result["configuration_or_deployment_replayed"] = false
	return result, nil
}
