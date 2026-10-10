package core

import (
	"strings"
	"testing"
)

func TestStatisticsLatencyCapabilityVersionAndTruthfulGuidance(t *testing.T) {
	found := false
	for _, app := range SoftwareAppCatalog() {
		if app.ID == "website-statistics-v2" {
			found = true
			if app.Version != "2.4.0" {
				t.Fatal("statistical capability version was not advanced", app.Version)
			}
		}
	}
	if !found {
		t.Fatal("statistics module missing")
	}
	guide := ModuleGuidance("website-statistics-v2")
	text := guide.Description + strings.Join(guide.Workflow, " ") + strings.Join(guide.Limitations, " ")
	for _, evidence := range []string{"P50/P90/P95/P99", "慢请求阈值只改变", "不改变总请求数", "request_time", "不是后端执行耗时", "无有效请求时不可用", "250000", "有偏分位数", "部分历史"} {
		if !strings.Contains(text, evidence) {
			t.Fatal("latency behavior or important boundary missing", evidence)
		}
	}
}
