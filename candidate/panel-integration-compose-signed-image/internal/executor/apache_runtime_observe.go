package executor

import (
	"context"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"maps"
	"time"

	"local/panel/internal/runtimecatalog"
)

// A successful systemctl restart of a Type=simple unit means that the fixed
// launcher has started, not that its final httpd execve is complete. This is an
// observation-only deadline: it cannot replay a native service operation.
func waitApacheRuntimeExecutable(ctx context.Context, expected string, observe func(context.Context) (string, string, error)) (string, string, error) {
	if expected != runtimecatalog.ApacheLegacyID && expected != runtimecatalog.ApacheCurrentID || observe == nil {
		return "", "", errors.New("Apache 目标运行身份不在审核范围")
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var lastErr error
	for {
		if err := bounded.Err(); err != nil {
			return "", "", errors.Join(errors.New("Apache 实际可执行程序未在有界启动窗口内确认"), err, lastErr)
		}
		state, actual, err := observe(bounded)
		if bounded.Err() != nil {
			return "", "", errors.Join(errors.New("Apache 原任务启动观察窗口已结束"), bounded.Err(), err)
		}
		if err == nil && state == "active" && actual == expected {
			return state, actual, nil
		}
		lastErr = err
		if lastErr == nil {
			lastErr = fmt.Errorf("Apache 原生状态 %q 与实际运行身份 %q 尚未匹配 %q", state, actual, expected)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-bounded.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

// Final execve and HTTP readiness are separate events. Keep every original
// domain and response status in one bounded observation; neither a listener
// label nor a partial successful website set authorizes committing the switch.
func waitApacheRuntimeResponses(ctx context.Context, expected map[string]int, observe func(context.Context) (map[string]int, error)) (map[string]int, error) {
	if len(expected) == 0 || len(expected) > 128 || observe == nil {
		return nil, errors.New("Apache 原入口清单不可核实")
	}
	original := maps.Clone(expected)
	for domain, status := range original {
		if !core.ValidDomain(domain) || status < 200 || status >= 500 {
			return nil, errors.New("Apache 原入口身份或状态不可核实")
		}
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var lastErr error
	for {
		if bounded.Err() != nil {
			return nil, errors.Join(errors.New("Apache 原入口未在有界启动窗口内全部就绪"), bounded.Err(), lastErr)
		}
		actual, err := observe(bounded)
		if bounded.Err() != nil {
			return nil, errors.Join(errors.New("Apache 原入口观察窗口已结束"), bounded.Err(), err)
		}
		if err == nil && maps.Equal(original, actual) {
			return maps.Clone(actual), nil
		}
		lastErr = err
		if lastErr == nil {
			lastErr = errors.New("Apache 原完整域名清单或响应状态尚未全部匹配")
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-bounded.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}
