//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"log"
	"os"
	"time"
)

func (s *Service) runWAFBodyLogRetentionOnce(ctx context.Context, now time.Time) error {
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	cfg, err := core.DecodeWAFConfig(manifest.Settings)
	if err != nil {
		return err
	}
	if manifest.Version != "2.5.0" || cfg.BodyLogRetention == nil || !cfg.BodyLogRetention.Enabled {
		return nil
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	manifest, err = s.readSoftwareManifest("nginx-waf")
	if err != nil {
		return err
	}
	cfg, err = core.DecodeWAFConfig(manifest.Settings)
	if err != nil {
		return err
	}
	if manifest.Version != "2.5.0" || cfg.BodyLogRetention == nil || !cfg.BodyLogRetention.Enabled {
		return nil
	}
	if err := s.verifyWAFBodyEngine(cfg); err != nil {
		return err
	}
	_, err = s.runWAFBodyRetentionLocked(ctx, now, lock, cfg, nil)
	return err
}

func (s *Service) runWAFBodyLogRetentionWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		cycle, cancel := context.WithTimeout(ctx, 60*time.Second)
		if err := s.runWAFBodyLogRetentionOnce(cycle, time.Now().UTC()); err != nil && ctx.Err() == nil {
			log.Printf("WAF numerical snapshot retention deferred; completion not claimed: %.512s", err.Error())
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
