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
	_, err := s.wafNginxPID(ctx, binary)
	return err
}

func (s *Service) wafNginxPID(ctx context.Context, binary string) (int, error) {
	out, e := s.Config.Run(ctx, "/usr/bin/systemctl", "show", "nginx", "--property=ActiveState,MainPID")
	if e != nil {
		return 0, e
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
		return 0, errors.New("Nginx 服务未运行或状态无法核实")
	}
	running, e := os.Readlink(s.systemPath(fmt.Sprintf("/proc/%d/exe", n)))
	if e != nil || running != binary {
		return 0, errors.New("Nginx 主进程与选择的版本不一致，请核对")
	}
	return n, ctx.Err()
}

func (s *Service) verifyWAFReload(ctx context.Context, cfg core.WAFConfig, nginx string) error {
	return s.verifyWAFReloadVersion(ctx, cfg, nginx, core.WAFVersion)
}

func (s *Service) verifyWAFReloadVersion(ctx context.Context, cfg core.WAFConfig, nginx, version string) error {
	return s.verifyWAFReloadGeneration(ctx, cfg, nginx, version, nil)
}

func verifyWAFReloadGenerationDrained(ctx context.Context, generation *wafReloadGeneration) error {
	if generation != nil {
		drained, err := generation.drained(ctx)
		if err != nil {
			return err
		}
		if !drained {
			// A worker can enter its verified exit transition while the probe
			// is in flight. Remain unconfirmed and wait within THIS probe
			// context, never start a new budget or accept an unknown title.
			if err := waitWAFReloadGeneration(ctx, generation); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

// A fast fingerprint from one new worker cannot acknowledge the old worker
// generation. Complete the exact original-listener barrier first, then give
// the fixed fingerprint probe its own five-second budget. Neither phase can
// extend an earlier caller deadline, and a failed barrier never probes.
func verifyWAFReloadAfterHandoff(ctx context.Context, generation *wafReloadGeneration, probe func(context.Context) error) error {
	if err := waitWAFReloadGeneration(ctx, generation); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := probe(ctx); err != nil {
		return err
	}
	// A probe reply is not permission to commit if the original master or
	// listener evidence changed while the request was in flight.
	return verifyWAFReloadGenerationDrained(ctx, generation)
}

func (s *Service) verifyWAFReloadGeneration(ctx context.Context, cfg core.WAFConfig, nginx, version string, generation *wafReloadGeneration) error {
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
		return nil
	}
	if e := s.wafNginxRunning(ctx, nginx); e != nil {
		return e
	}
	return verifyWAFReloadAfterHandoff(ctx, generation, func(ctx context.Context) error {
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		defer client.CloseIdleConnections()
		for attempt := 0; attempt < 50; attempt++ {
			if err := verifyWAFReloadGenerationDrained(ctx, generation); err != nil {
				return err
			}
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
	})
}
