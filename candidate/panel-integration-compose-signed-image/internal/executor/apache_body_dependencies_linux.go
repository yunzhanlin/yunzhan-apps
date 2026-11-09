//go:build linux

package executor

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"
)

// Dependency preparation must not install Apache, select a system executable,
// upgrade an existing package or write a result for an absent runtime.
func (s *Service) apacheBodyRuntimeReady(ctx context.Context) error {
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
		return errors.New("Apache 请求体构建仅支持真实受管环境")
	}
	r, err := apacheRelease()
	if err != nil || r.Version != "2.4.68" {
		return errors.New("缺少已审核 Apache 2.4.68 选择")
	}
	for _, path := range []string{r.CLI(), filepath.Join(r.Prefix(), "bin/apxs")} {
		if err := apacheBodyOwnedAncestors(filepath.Dir(path)); err != nil {
			return err
		}
		if err := ownedRuntimePath(path, false); err != nil {
			return err
		}
	}
	version, err := s.moduleCommand(ctx, 10*time.Second, r.CLI(), "-v")
	if err != nil || (!strings.HasPrefix(version, "Server version: Apache/"+r.Version+" ") && !strings.HasPrefix(version, "Server version: Apache/"+r.Version+"\n")) {
		return errors.New("Apache 实际程序版本不匹配；未准备依赖")
	}
	return nil
}

func (s *Service) apacheBodyBuildReady(ctx context.Context) error {
	if err := s.apacheBodyRuntimeReady(ctx); err != nil {
		return err
	}
	if !s.wafBuildPackagesReady(apacheBodyBuildDependencies()) {
		return errors.New("Apache 固定构建依赖未通过实际包状态核对")
	}
	return nil
}
