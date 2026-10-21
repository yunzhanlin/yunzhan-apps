//go:build linux

package executor

import (
	"context"
	"io"
	"os"

	"local/panel/internal/core"
	"local/panel/internal/diskjob"
	"local/panel/internal/upgradeguard"
)

// Real host capability has no alternate-root/record/lock path. Older isolated
// website-only handlers remain usable without opting into full-host authority.
func (s *Service) diskHostLifecycleBarrier(ctx context.Context) (io.Closer, error) {
	if os.Geteuid() != 0 || s.Config.SystemRoot != "/" || s.Config.SecurityDir != "/etc/panel/security-apps" || upgradeguard.Blocked() {
		return nil, errDiskHostWorker
	}
	lease, err := diskjob.InstanceLease(true)
	if err != nil {
		return nil, err
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		lease.Close()
		return nil, err
	}
	defer reader.db.Close()
	if !reader.current() {
		lease.Close()
		return nil, errDiskHostWorker
	}
	if err := (&core.Store{DB: reader.db}).CheckHostDiskUpgrade(ctx); err != nil {
		lease.Close()
		return nil, err
	}
	if err := diskjob.CheckRootJobs(); err != nil {
		lease.Close()
		return nil, err
	}
	if ctx.Err() != nil || !reader.current() || upgradeguard.Blocked() {
		lease.Close()
		return nil, errDiskHostWorker
	}
	return lease, nil
}

func (s *Service) diskHostLifecycleNeeded(action, selected string) bool {
	if action == "install" && selected == diskjob.HostAppVersion {
		return true
	}
	record, err := s.moduleInstalledRecord("disk-analysis")
	return err == nil && record["version"] == diskjob.HostAppVersion
}
