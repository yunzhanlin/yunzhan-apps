//go:build linux

package executor

import (
	"fmt"

	"local/panel/internal/core"
)

// Describe the registered policy and current exclusions, not a promise that
// every backend is healthy or the worker is making progress. Old/stale checks
// and worker errors never contribute to the healthy count.
func loadBalanceStatusDetail(entries []loadBalanceEntry, health []map[string]any, validatedVersion string) string {
	normal, failed, unknown := 0, 0, 0
	for _, row := range health {
		stale, _ := row["stale"].(bool)
		workerError, _ := row["worker_error"].(string)
		if stale || workerError != "" {
			unknown++
			continue
		}
		switch row["state"] {
		case "healthy":
			normal++
		case "unhealthy":
			failed++
		default:
			unknown++
		}
	}
	active, automatic, excluded := 0, 0, 0
	for _, entry := range entries {
		if entry.Removed {
			continue
		}
		active++
		if core.LoadBalanceAutomaticTraffic(entry.HealthCheck) {
			automatic++
			if entry.Routing != nil {
				excluded += len(entry.Routing.Down)
			}
		}
	}
	mode := "只观测，不自动修改流量"
	if automatic > 0 {
		mode = fmt.Sprintf("自动流量已明确启用 %d 个入口；当前摘除 %d 个节点；其余入口只观测", automatic, excluded)
		if !core.LoadBalanceHealthRoutingVersion(validatedVersion) {
			mode = fmt.Sprintf("%d 个入口已配置自动流量，但安装身份未通过支持版本校验；检查与新的流量调整暂停，当前 %d 个摘除节点保持不变", automatic, excluded)
		}
	}
	return fmt.Sprintf("%d 个回环 HTTP 入口；持续 HTTP 节点检查：%d 正常 / %d 失败 / %d 未判定、过期或后台异常；%s", active, normal, failed, unknown, mode)
}
