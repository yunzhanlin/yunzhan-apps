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
	"path/filepath"
	"regexp"
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
	// The production service is fixed to this listener. Unit fixtures never
	// make requests to real websites or require system services.
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" {
		return nil
	}
	if e := s.wafNginxRunning(ctx, nginx); e != nil {
		return e
	}
	entries, e := os.ReadDir(s.Config.ConfDir)
	if e != nil {
		return e
	}
	hostPattern := regexp.MustCompile(`(?m)^\s*server_name\s+([a-zA-Z0-9.-]+)`)
	for _, x := range entries {
		id := strings.TrimSuffix(x.Name(), ".conf")
		if !core.ValidID(id) {
			continue
		}
		b, e := os.ReadFile(filepath.Join(s.Config.ConfDir, x.Name()))
		if e != nil {
			return e
		}
		content := string(b)
		if !strings.HasPrefix(content, "# managed by panel; site="+id) || strings.Contains(strings.SplitN(content, "\n", 2)[0], "panel-waf-disabled") {
			continue
		}
		host := hostPattern.FindStringSubmatch(content)
		if len(host) != 2 || !core.ValidDomain(host[1]) {
			return errors.New("无法确定 WAF 重载核验站点")
		}
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		defer client.CloseIdleConnections()
		for attempt := 0; attempt < 20; attempt++ {
			r, e := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:19101/__panel_health_"+id, nil)
			if e != nil {
				return e
			}
			r.Host = host[1]
			res, e := client.Do(r)
			if e == nil {
				revision := res.Header.Get("X-Panel-WAF-Revision")
				status := res.StatusCode
				io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
				res.Body.Close()
				if status == 200 && revision == strconv.FormatInt(cfg.Policy.Revision, 10) {
					return nil
				}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		return errors.New("Nginx 重载后实际防护修订探针不匹配，未确认新版规则已加载")
	}
	return nil // No protected managed site exists on this host.
}
