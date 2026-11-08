package core

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
)

// Include the durable queue before its dependency/build worker has dispatched.
// A lost creation reply must not make a pending job invisible or uncancellable.
// The core job remains authoritative for its immutable terminal failure, while
// a succeeded job still needs the executor's current real integrity/ABI proof.
func (s *Store) mergeAnalyticsHTMLInventory(ctx context.Context, native []WAFEngineStatus) ([]WAFEngineStatus, error) {
	entries := map[string]WAFEngineStatus{}
	for _, entry := range native {
		if !ValidID(entry.JobID) || !entry.BuildOnly || len(entry.Steps) > 32 {
			return nil, errors.New("HTML 原生构建库存身份或步骤异常")
		}
		if _, duplicate := entries[entry.JobID]; duplicate {
			return nil, errors.New("HTML 原生构建库存有重复身份")
		}
		entries[entry.JobID] = entry
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,state,error,steps FROM runtime_jobs WHERE target_id='website-analytics' AND kind='analytics_html_build' ORDER BY id LIMIT 65`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	owned := map[string]bool{}
	for rows.Next() {
		var id, state, detail, text string
		if err := rows.Scan(&id, &state, &detail, &text); err != nil {
			return nil, err
		}
		if !ValidID(id) || len(owned) >= 64 || len(text) > 64<<10 {
			return nil, errors.New("HTML 持久构建库存标识、大小或 64 份保留预算异常")
		}
		owned[id] = true
		var steps []Step
		if json.Unmarshal([]byte(text), &steps) != nil || len(steps) > 32 {
			return nil, errors.New("HTML 持久构建步骤损坏")
		}
		if steps == nil {
			steps = []Step{}
		}
		if state != "succeeded" {
			if state != "queued" && state != "running" && state != "failed" && state != "needs_attention" {
				return nil, errors.New("HTML 持久构建状态异常")
			}
			entries[id] = WAFEngineStatus{JobID: id, State: state, Error: detail, Steps: steps, BuildOnly: true}
		} else if entry, exists := entries[id]; !exists {
			entries[id] = WAFEngineStatus{JobID: id, State: "needs_attention", Error: "完成任务缺少当前可核验的原生构建记录", Steps: steps, BuildOnly: true}
		} else if entry.State == "ready" && (!entry.IntegrityVerified || !entry.ABIValidated || entry.Error != "") {
			entry.State, entry.IntegrityVerified, entry.ABIValidated = "needs_attention", false, false
			if entry.Error == "" {
				entry.Error = "完成任务缺少当前完整性或 ABI 核验"
			}
			entries[id] = entry
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	for id, entry := range entries {
		if !owned[id] {
			entry.State, entry.IntegrityVerified, entry.ABIValidated = "needs_attention", false, false
			entry.Error = "原生记录没有本面板所属构建任务，不允许加载或接管"
			entries[id] = entry
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]WAFEngineStatus, 0, len(ids))
	for _, id := range ids {
		out = append(out, entries[id])
	}
	return out, nil
}
