package core

import (
	"context"
	"fmt"
	"time"
)

func runAnalyticsHTMLJob(parent context.Context, s *Store, e *ExecutorClient, j Job) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Hour)
	defer cancel()
	dependencyCtx, dependencyCancel := context.WithTimeout(ctx, 10*time.Minute)
	err := waitAppDependencies(dependencyCtx, e, "website-analytics")
	dependencyCancel()
	if err != nil {
		if parent.Err() == nil {
			_ = s.FinishRuntime(j, err.Error(), nil)
		}
		return
	}
	var result WAFEngineStatus
	if err = e.Call(ctx, "POST", "/v1/software/website-analytics/html-engine/build", map[string]string{"job_id": j.ID}, &result); err != nil {
		if parent.Err() == nil {
			_ = s.finishRuntime(j, err.Error(), nil, true)
		}
		return
	}
	for {
		if result.JobID != j.ID || !result.BuildOnly {
			_ = s.finishRuntime(j, "引擎任务响应身份或独立构建契约不匹配", result.Steps, true)
			return
		}
		_ = s.updateAnalyticsHTMLSteps(j.ID, result.Steps)
		switch result.State {
		case "ready":
			if !result.IntegrityVerified || !result.ABIValidated || result.Error != "" {
				_ = s.finishRuntime(j, "引擎缺少实际完整性、ABI 核对或带有未解决错误", result.Steps, true)
			} else {
				_ = s.FinishRuntime(j, "", result.Steps)
			}
			return
		case "failed":
			detail := result.Error
			if detail == "" {
				detail = "原生引擎构建失败；证据保留"
			}
			_ = s.FinishRuntime(j, detail, result.Steps)
			return
		case "needs_attention":
			_ = s.finishRuntime(j, result.Error, result.Steps, true)
			return
		case "queued", "running":
		default:
			_ = s.finishRuntime(j, "无法核实原生引擎构建状态", result.Steps, true)
			return
		}
		select {
		case <-ctx.Done():
			if parent.Err() == nil {
				_ = s.finishRuntime(j, "构建观察达到 5 小时上限；未宣称成功，原服务及证据保留", result.Steps, true)
			}
			return
		case <-time.After(3 * time.Second):
		}
		var next WAFEngineStatus
		for attempt := 0; attempt < 3; attempt++ {
			err = e.Call(ctx, "GET", "/v1/software/website-analytics/html-engine/jobs/"+j.ID, nil, &next)
			if err == nil {
				break
			}
			select {
			case <-ctx.Done():
				if parent.Err() == nil {
					_ = s.finishRuntime(j, "构建状态观察超时；未宣称成功", result.Steps, true)
				}
				return
			case <-time.After(time.Duration(attempt+1) * time.Second):
			}
		}
		if err != nil {
			if parent.Err() == nil {
				_ = s.finishRuntime(j, fmt.Sprintf("不能核实构建服务；不覆盖原记录，请检查：%v", err), result.Steps, true)
			}
			return
		}
		result = next
	}
}
