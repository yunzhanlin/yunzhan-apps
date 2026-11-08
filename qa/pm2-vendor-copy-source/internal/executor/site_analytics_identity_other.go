//go:build !linux

package executor

import (
	"errors"
	"local/panel/internal/core"
)

func (s *Service) prepareSiteAnalyticsIdentity(site core.Site) error {
	return errors.New("采集代理身份文件仅支持 Linux，未应用网站配置")
}
