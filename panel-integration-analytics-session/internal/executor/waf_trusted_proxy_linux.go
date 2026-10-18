//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"strings"
	"time"
)

func (s *Service) verifyWAFTrustedProxy(ctx context.Context, cfg core.WAFConfig, nginx string) error {
	if cfg.TrustedProxy == nil || !cfg.TrustedProxy.Enabled {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := s.Config.Run(bounded, nginx, "-V")
	if err != nil || len(output) > 64<<10 {
		return errors.New("无法核实当前 Nginx 的 real_ip 模块，未启用代理信任")
	}
	for _, field := range strings.Fields(output) {
		if strings.Trim(field, "'\"") == "--with-http_realip_module" {
			return nil
		}
	}
	return errors.New("当前 Nginx 未明确构建 http_realip_module；先选择受管兼容程序，不自动重编译或信任请求头")
}
