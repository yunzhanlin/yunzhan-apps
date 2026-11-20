package executor

import (
	"context"
	"errors"
	"fmt"
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
