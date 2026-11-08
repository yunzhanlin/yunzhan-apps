//go:build linux

package executor

import (
	"context"
	"errors"
	"path/filepath"
	"syscall"

	"local/panel/internal/upgradeguard"
)

func (s *Service) wafCountryPublicationLease(expected string) func(context.Context) (func() error, func(), error) {
	return func(ctx context.Context) (func() error, func(), error) {
		if ctx == nil || ctx.Err() != nil {
			return nil, nil, errors.New("国家数据提交上下文无效")
		}
		if err := upgradeguard.CheckStartup(); err != nil {
			return nil, nil, err
		}
		lock, info, err := s.openExistingWAFBackupLock(ctx, syscall.LOCK_SH)
		if err != nil {
			return nil, nil, err
		}
		closed := false
		release := func() {
			if !closed {
				closed = true
				lock.Close()
			}
		}
		check := func() error {
			if closed {
				return errors.New("国家数据原提交租约已释放")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := upgradeguard.CheckStartup(); err != nil {
				return err
			}
			if err := wafBackupLockUnchanged(lock, filepath.Join(s.Config.SecurityDir, "waf-configuration.lock"), info); err != nil {
				return err
			}
			return s.wafCountryInstanceGuard(expected)
		}
		if err := check(); err != nil {
			release()
			return nil, nil, err
		}
		return check, release, nil
	}
}
