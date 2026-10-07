//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Configuration syntax alone is not proof that the selected Nginx is running.
func (s *Service) wafNginxRunning(ctx context.Context, binary string) error {
	out, e := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "nginx", "--property=ActiveState,MainPID")
	if e != nil {
		return e
	}
	state, pid := "", ""
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && k == "ActiveState" {
			state = v
		}
		if ok && k == "MainPID" {
			pid = v
		}
	}
	n, e := strconv.Atoi(pid)
	if e != nil || n < 2 || state != "active" {
		return errors.New("Nginx 服务未运行或状态无法核实")
	}
	running, e := os.Readlink(s.systemPath(fmt.Sprintf("/proc/%d/exe", n)))
	if e != nil || running != binary {
		return errors.New("Nginx 主进程与选择的版本不一致，请核对")
	}
	return ctx.Err()
}

func (s *Service) verifyWAFReload(ctx context.Context, cfg core.WAFConfig, nginx string) error {
	return s.verifyWAFReloadVersion(ctx, cfg, nginx, core.WAFVersion)
}

func (s *Service) verifyWAFReloadVersion(ctx context.Context, cfg core.WAFConfig, nginx, version string) error {
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
		return nil
	}
	if e := s.wafNginxRunning(ctx, nginx); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for attempt := 0; attempt < 20; attempt++ {
		r, e := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:19101/__panel_waf_check", nil)
		if e != nil {
			return e
		}
		r.Host = "panel-waf-check.invalid"
		res, e := client.Do(r)
		if e == nil {
			body, readErr := io.ReadAll(io.LimitReader(res.Body, 1024))
			res.Body.Close()
			if readErr == nil && res.StatusCode == 200 && string(body) == wafProbeValueVersion(cfg, version) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("Nginx 重载后实际配置指纹探针不匹配，未确认新版规则已加载")
}
