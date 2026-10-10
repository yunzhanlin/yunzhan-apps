//go:build linux

package executor

import (
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestLoadBalanceStatusShowsActualAuthorityAndUnknownResults(t *testing.T) {
	on, off := true, false
	auto := loadBalanceEntry{HealthCheck: &core.LoadBalanceHTTPHealth{AutoTraffic: &on}, Routing: &loadBalanceRouting{Down: []string{"127.0.0.1:45021"}}}
	observe := loadBalanceEntry{HealthCheck: &core.LoadBalanceHTTPHealth{AutoTraffic: &off}}
	for _, version := range []string{"1.7.0", "1.7.1", "1.8.0", "1.8.1", "1.8.2"} {
		got := loadBalanceStatusDetail([]loadBalanceEntry{auto, observe}, []map[string]any{{"state": "healthy"}, {"state": "unhealthy"}}, version)
		for _, part := range []string{"2 个回环 HTTP 入口", "1 正常 / 1 失败 / 0", "自动流量已明确启用 1 个入口", "当前摘除 1 个节点"} {
			if !strings.Contains(got, part) {
				t.Fatal(version, got, part)
			}
		}
		if strings.Contains(got, "只观测，不自动修改流量") {
			t.Fatal("automatic policy incorrectly described as observation only", got)
		}
	}
	rows := []map[string]any{{"state": "healthy", "stale": true}, {"state": "unhealthy", "stale": true}, {"state": "healthy", "worker_error": "actual failure"}, {"state": "unknown", "last_success": true}}
	if got := loadBalanceStatusDetail([]loadBalanceEntry{observe}, rows, "1.7.1"); !strings.Contains(got, "0 正常 / 0 失败 / 4") || !strings.Contains(got, "只观测，不自动修改流量") {
		t.Fatal("stale/failed worker/unknown result counted as healthy", got)
	}
	for _, version := range []string{"", "1.6.0", "1.7.2", "1.8.3", "1.9.0"} {
		got := loadBalanceStatusDetail([]loadBalanceEntry{auto}, nil, version)
		if !strings.Contains(got, "安装身份未通过支持版本校验") || !strings.Contains(got, "摘除节点保持不变") || strings.Contains(got, "已明确启用") {
			t.Fatal("unrecognized installation overclaims active worker", version, got)
		}
	}
	removed := auto
	removed.Removed = true
	if got := loadBalanceStatusDetail([]loadBalanceEntry{removed}, nil, "1.7.1"); !strings.Contains(got, "0 个回环 HTTP 入口") || strings.Contains(got, "已明确启用") {
		t.Fatal("removed entry expanded current authority", got)
	}
}
